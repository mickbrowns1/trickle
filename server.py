#!/usr/bin/env python3
"""Trickle: a local web UI that builds and runs real Vector pipelines and
tests DPM-style Lua serializers.

Standard library only (no pip install). Listens on 127.0.0.1 only.

    python3 server.py            # then open http://127.0.0.1:8790
    PORT=9000 python3 server.py  # different port

How a run works
---------------
1. The UI sends a linear pipeline: source -> steps -> destination.
2. Sources and Vector steps (filter, remap, sample, dedupe) run in the real
   `vector` binary. Every stage gets a hidden "tap" file sink so we can count
   events and bytes after each stage.
3. An optional final "Lua serializer" step runs your processEvent(record)
   function in a local Lua (LuaJIT) through lua_runner.lua, one record at a
   time. We then diff each input record against its output so you can see
   exactly what the serializer changed, and run OCSF sanity checks.
4. A "raw record" source with no Vector steps skips Vector entirely: the
   record goes straight to the serializer, like a DPM collector would hand it.
"""
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import zipfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

import formats as fm
import mockapi

HERE = Path(__file__).resolve().parent
PIPE_DIR = HERE / "pipelines"
OUT_DIR = HERE / "output"
LOCAL = "127.0.0.1"                       # used for Vector's own temporary HTTP listener
HOST = os.environ.get("HOST", LOCAL)      # 0.0.0.0 inside Docker; the compose file only publishes it on 127.0.0.1
PORT = int(os.environ.get("PORT", "8790"))
IN_DOCKER = os.environ.get("IN_DOCKER") == "1"
EXTRA_HOSTS = [h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()]

MAX_INPUT_BYTES = 20 * 1024 * 1024
MAX_CODE_BYTES = 1024 * 1024
MAX_RUN_SECONDS = 120
SAMPLE_LIMIT = 8
PRINT_LIMIT = 200
SER_EVENT_LIMIT = 2000      # most events sent through the serializer per run
SER_DIFF_RECORDS = 200      # records that get a full before/after diff
MAX_RECORDS = 5000
GEN_FORMATS = ["syslog", "json", "apache_common", "apache_error", "bsd_syslog", "shuffle"]
HTTP_FORMATS = ["text", "ndjson", "json"]

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RUN_LOCK = threading.Lock()


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def _first_executable(candidates):
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def find_vector():
    return _first_executable([os.environ.get("VECTOR_BIN"), shutil.which("vector"),
                              "/opt/homebrew/bin/vector", "/usr/local/bin/vector",
                              str(Path.home() / ".vector" / "bin" / "vector")])


def find_lua():
    return _first_executable([os.environ.get("LUA_BIN"), shutil.which("luajit"),
                              "/opt/homebrew/bin/luajit", "/usr/local/bin/luajit",
                              shutil.which("lua"), "/opt/homebrew/bin/lua", "/usr/local/bin/lua"])


def vector_version(vec):
    try:
        r = subprocess.run([vec, "--version"], capture_output=True, text=True, timeout=15)
        return ANSI.sub("", (r.stdout or r.stderr).strip())
    except Exception as exc:  # noqa: BLE001
        return "unknown (%s)" % exc


def clean_env():
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    return env


# ---------------------------------------------------------------------------
# Pipeline -> Vector config
# ---------------------------------------------------------------------------

def escape_dollars(obj):
    """Vector substitutes $VAR / ${VAR} in config text; $$ is a literal dollar."""
    if isinstance(obj, str):
        return obj.replace("$", "$$")
    if isinstance(obj, list):
        return [escape_dollars(x) for x in obj]
    if isinstance(obj, dict):
        return {k: escape_dollars(v) for k, v in obj.items()}
    return obj


def to_int(value, name, lo, hi, default):
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    if n < lo or n > hi:
        raise ApiError("%s must be between %d and %d." % (name, lo, hi))
    return n


def safe_filename(name, default="pipeline-output.ndjson"):
    name = re.sub(r"[^A-Za-z0-9._-]", "_", str(name or "").strip())
    name = name.lstrip(".")
    return name[:80] or default


def file_json_records(src):
    """If a file source holds ONE pretty-printed JSON document (object or array of objects), return its
    records. Plain log lines and one-event-per-line files return None and keep line-by-line behaviour."""
    try:
        if str(src.get("path", "")).strip():
            fp = Path(str(src["path"]).strip()).expanduser()
            if not fp.is_file() or fp.stat().st_size > MAX_INPUT_BYTES:
                return None
            text = fp.read_text(encoding="utf-8", errors="replace")
        else:
            text = str(src.get("text", ""))
        text = text.strip()
        if "\n" not in text or text[:1] not in "{[":
            return None
        data = json.loads(text)
    except (ValueError, OSError):
        return None
    recs = data if isinstance(data, list) else [data]
    if recs and all(isinstance(r, dict) for r in recs) and len(recs) <= MAX_RECORDS:
        return recs
    return None


def make_transforms(tlist, prev, prefix, offset):
    """Build Vector transform nodes for a list of steps. Returns (transforms, stages, last_id)."""
    transforms, stages = {}, []
    for n, t in enumerate(tlist, 1):
        i = n + offset
        tid = "%s%d" % (prefix, n)
        ty = t.get("type")
        if ty == "filter":
            cond = str(t.get("condition", "")).strip()
            if not cond:
                raise ApiError("Step %d (filter): the condition is empty." % i)
            transforms[tid] = {"type": "filter", "inputs": [prev], "condition": cond}
        elif ty == "remap":
            code = str(t.get("source", "")).strip()
            if not code:
                raise ApiError("Step %d (remap): the VRL is empty." % i)
            transforms[tid] = {"type": "remap", "inputs": [prev], "source": code}
        elif ty == "sample":
            k = to_int(t.get("n"), "Step %d sample N" % i, 1, 1_000_000, 10)
            transforms[tid] = {"type": "sample", "inputs": [prev], "ratio": 1.0 / k}
        elif ty == "dedupe":
            fields = [f.strip() for f in str(t.get("fields", "")).split(",") if f.strip()]
            node = {"type": "dedupe", "inputs": [prev]}
            if fields:
                node["fields"] = {"match": fields}
            transforms[tid] = node
        else:
            raise ApiError("Step %d: unknown transform type %r." % (i, ty))
        stages.append({"id": tid, "label": "%s" % ty, "kind": "transform"})
        prev = tid
    return transforms, stages, prev


def build_post_config(post, run_dir, offset):
    """Vector config for the steps AFTER the serializer: OCSF records in on stdin, taps out."""
    transforms, stages, prev = make_transforms(post, "source", "p", offset)
    sinks = {"destination": {"type": "blackhole", "inputs": [prev]}}
    for st in stages:
        sinks["tap_" + st["id"]] = {"type": "file", "inputs": [st["id"]],
                                    "path": str(Path(run_dir) / ("tap_%s.ndjson" % st["id"])),
                                    "encoding": {"codec": "json"}}
    cfg = {"data_dir": str(Path(run_dir) / "data_post"),
           "sources": {"source": {"type": "stdin", "decoding": {"codec": "json"},
                                  "framing": {"method": "newline_delimited"}}},
           "transforms": transforms, "sinks": sinks}
    return escape_dollars(cfg), stages


def run_post(vec, post, events, run_dir, offset):
    """Run the post-serializer steps in a second Vector pass over the OCSF records."""
    cfg, stages = build_post_config(post, run_dir, offset)
    (run_dir / "data_post").mkdir(exist_ok=True)
    cfg_path = run_dir / "vector_post.json"
    cfg_path.write_text(json.dumps(cfg, indent=2))
    v = subprocess.run([vec, "validate", str(cfg_path)], capture_output=True, text=True, timeout=60, env=clean_env())
    if v.returncode != 0:
        return {"ok": False, "error": ANSI.sub("", (v.stdout or "") + (v.stderr or "")).strip() or "Vector rejected the post-serializer steps."}
    data = ("\n".join(json.dumps(e) for e in events) + "\n").encode("utf-8") if events else b""
    try:
        r = subprocess.run([vec, "--config", str(cfg_path)], input=data, capture_output=True,
                           timeout=MAX_RUN_SECONDS, env=clean_env())
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "The steps after the serializer hit the time limit."}
    results, outputs = [], []
    for idx, st in enumerate(stages):
        last = idx == len(stages) - 1
        ev, nb, samples, kept = read_tap(run_dir / ("tap_%s.ndjson" % st["id"]), SER_EVENT_LIMIT if last else 0)
        if last:
            outputs = kept
        results.append(dict(st, events=ev, bytes=nb, samples=samples))
    log = [l for l in ANSI.sub("", (r.stderr or b"").decode("utf-8", "replace")).splitlines() if l.strip()][-40:]
    return {"ok": True, "stages": results, "outputs": outputs, "log": log}


def build_config(p, run_dir, http_port=8686):
    """Return (config dict or None, stages, meta). Does not read input files.

    config is None when the pipeline needs no Vector (raw records straight into
    a Lua serializer).
    """
    if not isinstance(p, dict):
        raise ApiError("Pipeline must be a JSON object.")
    src = p.get("source") or {}
    stype = src.get("type")
    meta = {"mode": None, "http_format": None, "saved_path": None, "sink": None, "lua": None, "post": []}

    tlist = list(p.get("transforms") or [])
    lua_steps = [i for i, t in enumerate(tlist) if t.get("type") == "lua"]
    if lua_steps:
        if len(lua_steps) > 1:
            raise ApiError("There can be only one Lua serializer.")
        li = lua_steps[0]
        meta["lua"] = tlist[li]
        meta["post"] = tlist[li + 1:]   # steps after the serializer run in a second Vector pass
        tlist = tlist[:li]

    s = None
    if stype == "generator":
        fmt = src.get("format", "syslog")
        if fmt not in GEN_FORMATS:
            raise ApiError("Unknown generator format: %s" % fmt)
        count = to_int(src.get("count"), "Event count", 1, 5_000_000, 1000)
        s = {"type": "demo_logs", "format": fmt, "count": count, "interval": 0.0}
        if fmt == "shuffle":
            lines = [l for l in str(src.get("lines", "")).splitlines() if l.strip()]
            if not lines:
                raise ApiError("The shuffle format needs at least one line of sample text.")
            s["lines"] = lines
        label = "Generator (%s)" % fmt
        meta["mode"] = "generator"
        meta["count"] = count
    elif stype == "file":
        jr = file_json_records(src)
        if jr is not None:    # a pretty-printed JSON document: its events, not one event per line
            s = {"type": "stdin", "decoding": {"codec": "json"}, "framing": {"method": "newline_delimited"}}
            label = "File (JSON)"
            meta["mode"] = "stdin_json"
            meta["json_records"] = jr
        else:
            s = {"type": "stdin"}
            label = "File"
            meta["mode"] = "stdin"
    elif stype == "record":
        label = "Raw records"
        if tlist:
            s = {"type": "stdin", "decoding": {"codec": "json"},
                 "framing": {"method": "newline_delimited"}}
            meta["mode"] = "stdin_json"
        else:
            meta["mode"] = "record"
    elif stype == "http":
        fmt = src.get("format", "ndjson")
        if fmt not in HTTP_FORMATS:
            raise ApiError("Unknown HTTP body format: %s" % fmt)
        if fmt == "text":
            decoding, framing = {"codec": "bytes"}, {"method": "newline_delimited"}
        elif fmt == "ndjson":
            decoding, framing = {"codec": "json"}, {"method": "newline_delimited"}
        else:
            decoding, framing = {"codec": "json"}, {"method": "bytes"}
        s = {"type": "http_server", "address": "127.0.0.1:%d" % http_port,
             "decoding": decoding, "framing": framing}
        label = "HTTP (%s)" % fmt
        meta["mode"] = "http"
        meta["http_format"] = fmt
    else:
        raise ApiError("Choose a source type (generator, file, raw record or http).")

    stages = [{"id": "source", "label": label, "kind": "source"}]
    transforms, tstages, prev = make_transforms(tlist, "source", "t", 0)
    stages += tstages

    sink = p.get("sink") or {}
    sink_type = sink.get("type", "devnull")
    if sink_type not in ("devnull", "console", "file"):
        raise ApiError("Unknown destination type: %s" % sink_type)
    meta["sink"] = sink_type
    if sink_type == "file":
        meta["saved_path"] = str(OUT_DIR / safe_filename(sink.get("filename")))

    if s is None:  # raw records straight into the serializer
        return None, stages, meta

    sinks = {}
    # With a serializer, the real destination happens after it, in this server.
    if sink_type == "devnull" or meta["lua"]:
        sinks["destination"] = {"type": "blackhole", "inputs": [prev]}
    elif sink_type == "console":
        sinks["destination"] = {"type": "console", "inputs": [prev],
                                "encoding": {"codec": "json"}, "target": "stdout"}
    else:
        sinks["destination"] = {"type": "file", "inputs": [prev], "path": meta["saved_path"],
                                "encoding": {"codec": "json"}}

    for st in stages:
        sinks["tap_" + st["id"]] = {
            "type": "file", "inputs": [st["id"]],
            "path": str(Path(run_dir) / ("tap_%s.ndjson" % st["id"])),
            "encoding": {"codec": "json"},
        }

    cfg = {"data_dir": str(Path(run_dir) / "data"),
           "sources": {"source": s}, "transforms": transforms, "sinks": sinks}
    return escape_dollars(cfg), stages, meta


# ---------------------------------------------------------------------------
# Raw records and Lua helpers
# ---------------------------------------------------------------------------

def parse_records(text, keep_header=False):
    text = (text or "").strip()
    if not text:
        raise ApiError("The raw record source is empty. Paste one JSON event, a JSON array, or one JSON object per line.")
    try:
        data = json.loads(text)
        recs = data if isinstance(data, list) else [data]
    except ValueError:
        recs = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                recs.append(json.loads(line))
            except ValueError:
                if line.lstrip().startswith(("{", "[")):
                    raise ApiError("Line %d looks like JSON but is not valid JSON (check commas and quotes)." % n)
                recs.append({"message": line.strip()})   # a text log line (CEF, LEEF, key=value, syslog) arrives as a message

    if not keep_header and recs and all(set(r) == {"message"} and isinstance(r["message"], str) for r in recs):
        found = sniff([r["message"] for r in recs])
        if found and found["skip"]:
            recs = [r for i, r in enumerate(recs) if i not in found["skip"]]   # header rows are not events
    if not recs:
        raise ApiError("No records found in the raw record source.")
    if len(recs) > MAX_RECORDS:
        raise ApiError("Too many records (max %d)." % MAX_RECORDS)
    for r in recs:
        if not isinstance(r, dict):
            raise ApiError("Each raw record must be a JSON object.")
    return recs


def lua_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 32 or o == 127:
            out.append("\\%03d" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)



# ---------------------------------------------------------------------------
# Serializer generator: build an OCSF processEvent from a sample record
# ---------------------------------------------------------------------------

def _norm(k):
    return re.sub(r"[^a-z0-9]", "", str(k).lower())

# normalised vendor field name -> (OCSF path, kind). kind: s string, n number
GEN_ALIASES = {}
def _alias(names, target, kind="s"):
    for n in names.split():
        GEN_ALIASES.setdefault(n, (target, kind))

_alias("srcip sourceip srcaddr sourceaddress clientip srchost sourceipaddress", "src_endpoint.ip")
_alias("srcport sourceport clientport", "src_endpoint.port", "n")
_alias("srccountry sourcecountry", "src_endpoint.location.country")
_alias("srcsite srchostname sourcehostname sitename", "src_endpoint.hostname")
_alias("srcmac sourcemac", "src_endpoint.mac")
_alias("dstip destip destinationip dstaddr destaddr destinationaddress serverip destinationipaddress", "dst_endpoint.ip")
_alias("dstport destport destinationport serverport", "dst_endpoint.port", "n")
_alias("dstcountry destcountry destinationcountry", "dst_endpoint.location.country")
_alias("dsthostname desthostname destinationhostname", "dst_endpoint.hostname")
_alias("protocol ipprotocol proto transport", "connection_info.protocol_name")
_alias("trafficdirection direction", "connection_info.direction")
_alias("username user usr accountname actor initiatedby", "actor.user.name")
_alias("useremail email", "actor.user.email_addr")
_alias("hostname host devicename computername", "device.hostname")
_alias("ostype os osname", "device.os.name")
_alias("rule rulename policy policyname", "firewall_rule.name")
_alias("ruleid policyid", "firewall_rule.uid")
_alias("threatname signaturename malwarename alertname detectionname", "finding_info.title")
_alias("threattype category", "finding_info.types[0]")
_alias("signatureid signature threatid sid detectionid", "finding_info.uid")
_alias("threatreference reference refurl", "finding_info.src_url")
_alias("url uri requesturl", "http_request.url.url_string")
_alias("domain fqdn", "http_request.url.hostname")
_alias("useragent", "http_request.user_agent")
_alias("method httpmethod", "http_request.http_method")
_alias("statuscode httpstatus responsecode", "http_response.code", "n")
_alias("bytesin bytesdownloaded rxbytes bytesreceived", "traffic.bytes_in", "n")
_alias("bytesout bytesuploaded txbytes bytessent", "traffic.bytes_out", "n")
_alias("filename", "file.name")
_alias("filehash sha256 hash md5", "file.hashes[0].value")
_alias("filepath", "file.path")
_alias("processname process", "process.name")
_alias("commandline cmdline", "process.cmd_line")
_alias("accountid tenantid customerid", "cloud.account.uid")
_alias("popname region", "cloud.region")
_alias("internalid eventid id uid guid", "metadata.uid")
_alias("eventcount count", "count", "n")
_alias("message msg description", "message")
_alias("sysloghost", "device.hostname")
_alias("alertid", "finding_info.uid")
_alias("alertname", "finding_info.title")
_alias("alerttype", "finding_info.types[0]")
_alias("alertinfosubject", "message")
_alias("alertinfodescription", "finding_info.desc")
_alias("referer referrer", "http_request.referrer")
_alias("status", "http_response.code", "n")
_alias("protocol", "http_request.version")
_alias("clientrequestmethod", "http_request.http_method")
_alias("clientrequesturi clientrequestpath", "http_request.url.path")
_alias("clientrequesthost", "http_request.url.hostname")
_alias("clientrequestuseragent", "http_request.user_agent")
_alias("edgeresponsestatus originresponsestatus", "http_response.code", "n")
_alias("qname queryname dnsquery question", "query.hostname")
_alias("qtype querytype", "query.type")
_alias("rcode", "rcode")
_alias("starttime", "start_time", "t")
_alias("endtime", "end_time", "t")

GEN_TIME_KEYS = ["time", "timegenerated", "receivetime", "timestamp", "eventtimestamp", "eventtime", "ts", "datetime", "createdat", "date", "rt", "end", "start", "devtime", "syslogtime"]
GEN_SEV_KEYS = ["risklevel", "severity", "sev", "risk", "level", "priority"]
GEN_ACTION_KEYS = ["action", "act", "disposition", "verdict", "outcome"]


# ---- Log format support: CEF, LEEF, key=value, JSON-in-message, syslog wrappers ------
CEF_HEADER = ["cef_version", "device_vendor", "device_product", "device_version", "signature_id", "name", "severity"]
LEEF_HEADER = ["leef_version", "device_vendor", "device_product", "device_version", "signature_id"]
# normalised key -> (OCSF path, kind). Applied to non-JSON formats (CEF, LEEF, key=value).
LOG_ALIASES = {
    "name": ("finding_info.title", "s"), "deviceversion": ("metadata.product.version", "s"),
    "src": ("src_endpoint.ip", "s"), "spt": ("src_endpoint.port", "n"), "shost": ("src_endpoint.hostname", "s"),
    "smac": ("src_endpoint.mac", "s"), "dst": ("dst_endpoint.ip", "s"), "dpt": ("dst_endpoint.port", "n"),
    "dhost": ("dst_endpoint.hostname", "s"), "dmac": ("dst_endpoint.mac", "s"),
    "proto": ("connection_info.protocol_name", "s"), "suser": ("actor.user.name", "s"), "duser": ("actor.user.name", "s"),
    "usrname": ("actor.user.name", "s"), "fname": ("file.name", "s"), "filepath": ("file.path", "s"),
    "filehash": ("file.hashes[0].value", "s"), "request": ("http_request.url.url_string", "s"),
    "requestmethod": ("http_request.http_method", "s"), "requestclientapplication": ("http_request.user_agent", "s"),
    "app": ("app_name", "s"), "msg": ("message", "s"), "cat": ("finding_info.types[0]", "s"),
    "externalid": ("metadata.uid", "s"), "dvchost": ("device.hostname", "s"), "devicehostname": ("device.hostname", "s"),
    "dvc": ("device.ip", "s"), "cnt": ("count", "n"), "in": ("traffic.bytes_in", "n"), "out": ("traffic.bytes_out", "n"),
    "sysloghost": ("device.hostname", "s"),
    "sport": ("src_endpoint.port", "n"), "dport": ("dst_endpoint.port", "n"), "srcuser": ("actor.user.name", "s"),
    "remoteuser": ("actor.user.name", "s"), "clientip": ("src_endpoint.ip", "s"),
    "bytes": ("traffic.bytes", "n"), "packets": ("traffic.packets", "n"), "pktssent": ("traffic.packets_out", "n"),
    "pktsreceived": ("traffic.packets_in", "n"), "rule": ("firewall_rule.name", "s"), "sessionid": ("connection_info.uid", "s"),
    "srcloc": ("src_endpoint.location.country", "s"), "dstloc": ("dst_endpoint.location.country", "s"),
    "threatid": ("finding_info.title", "s"), "misc": ("http_request.url.url_string", "s"),
    "devicename": ("device.hostname", "s"), "serial": ("device.uid", "s"),
    "systemcomputer": ("device.hostname", "s"), "eventdataipaddress": ("src_endpoint.ip", "s"),
    "eventdatatargetusername": ("actor.user.name", "s"), "eventdatasubjectusername": ("actor.user.name", "s"),
    "cip": ("src_endpoint.ip", "s"), "sip": ("dst_endpoint.ip", "s"), "csmethod": ("http_request.http_method", "s"),
    "csuristem": ("http_request.url.path", "s"), "scstatus": ("http_response.code", "n"),
    "csuseragent": ("http_request.user_agent", "s"), "csusername": ("actor.user.name", "s"),
    "start": ("start_time", "t"), "end": ("end_time", "t"),
}
LOG_CONSUMED = {"cef_version", "leef_version", "device_vendor", "device_product", "syslog_app"}
FORMAT_NAMES = {"cef": "CEF", "leef": "LEEF", "kv": "key=value", "json": "JSON in a message",
                "panos": "Palo Alto PAN-OS (CSV)", "xml": "XML events", "apache": "Apache / Nginx access log",
                "table": "CSV / TSV with a header row", "w3c": "W3C / Zeek header log", "grok": "Custom grok pattern"}
FORMAT_ORDER = ["cef", "leef", "panos", "xml", "apache", "w3c", "table", "kv", "json"]


def strip_syslog(line):
    """Return (payload, syslog_fields). Understands RFC 5424 and RFC 3164 wrappers."""
    m = re.match(r"^<\d+>1\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(.*)$", line)
    if m:
        tail = m.group(4)
        if tail.startswith("-"):
            tail = tail[1:].lstrip()
        else:
            while tail.startswith("["):
                close = tail.find("]")
                if close < 0:
                    break
                tail = tail[close + 1:]
            tail = tail.lstrip()
        return tail, {"syslog_time": m.group(1), "syslog_host": m.group(2), "syslog_app": m.group(3)}
    m = re.match(r"^(?:<\d+>)?([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)$", line)
    if m:
        payload = re.sub(r"^[\w\-./]+(\[\d+\])?:\s+", "", m.group(3))
        return payload, {"syslog_host": m.group(2)}
    return line, {}


def parse_leef_py(payload):
    i = payload.find("LEEF:")
    if i < 0:
        return None
    parts = payload[i + 5:].split("|", 5)
    if len(parts) < 6:
        return None
    rec = dict(zip(LEEF_HEADER, parts[:5]))
    rest = parts[5]
    delim = "\t"
    if rec["leef_version"].startswith("2"):
        head, _, rest = rest.partition("|")
        if head:
            delim = chr(int(head[1:], 16)) if head.lower().startswith("x") and len(head) > 1 else head[0]
    for pair in rest.split(delim):
        k, eq, v = pair.partition("=")
        if eq and k.strip():
            rec[k.strip()] = v
    return rec


CEF_BARE = re.compile(r"^\s*\d\|(?:[^|]*\|){5}")   # CEF header without the CEF: prefix, e.g. 0|Vendor|Product|1.0|id|name|3|...


def looks_like_cef(payload):
    return "CEF:" in payload or bool(CEF_BARE.match(payload))


def parse_cef_py(payload):
    i = payload.find("CEF:")
    if i >= 0:
        rest = payload[i + 4:]
    elif CEF_BARE.match(payload):
        rest = payload.lstrip()
    else:
        return None
    rec, pos = {}, 0
    for name in CEF_HEADER:
        j = pos
        while True:
            p = rest.find("|", j)
            if p < 0:
                return None
            b, k = 0, p - 1
            while k >= pos and rest[k] == "\\":
                b += 1
                k -= 1
            if b % 2 == 0:
                rec[name] = rest[pos:p].replace("\\|", "|").replace("\\\\", "\\")
                pos = p + 1
                break
            j = p + 1
    ext = rest[pos:]
    keys = [m for m in re.finditer(r"([\w.\-]+)=", ext) if m.start() == 0 or ext[m.start() - 1] == " "]
    for n, m in enumerate(keys):
        end = keys[n + 1].start() - 1 if n + 1 < len(keys) else len(ext)
        rec[m.group(1)] = ext[m.end():end].strip().replace("\\=", "=").replace("\\n", "\n").replace("\\\\", "\\")
    for key in [k for k in rec if k.endswith("Label") and len(k) > 5]:   # csN, cnN, cfpN ... plus their Label
        base = key[:-5]
        if base in rec:
            lab, val = rec.pop(key), rec.pop(base)
            if lab:
                rec[lab] = val
    return rec


def parse_kv_py(payload):
    rec = {}
    for m in re.finditer(r'([\w.\-]+)="([^"]*)"', payload):
        rec[m.group(1)] = m.group(2)
    stripped = re.sub(r'[\w.\-]+="[^"]*"', " ", payload)
    for m in re.finditer(r"([\w.\-]+)=(\S+)", stripped):
        rec[m.group(1)] = m.group(2)
    return rec if len(rec) >= 2 else None


def detect_log(line):
    """Return (format, fields) for a text log line, or (None, None)."""
    payload, sys_fields = strip_syslog(line.strip())
    rec, fmt = None, None
    if looks_like_cef(payload):
        rec, fmt = parse_cef_py(payload), "cef"
    elif "LEEF:" in payload:
        rec, fmt = parse_leef_py(payload), "leef"
    elif payload.lstrip().startswith("{"):
        try:
            d = json.loads(payload)
            if isinstance(d, dict):
                rec, fmt = d, "json"
        except ValueError:
            pass
    if rec is None:
        rec, fmt = parse_kv_py(payload), "kv"
    if rec is None:
        return None, None
    rec.update(sys_fields)
    return fmt, rec


def _per_line(lines, fn):
    out = []
    for line in lines:
        payload, sysf = strip_syslog(line.strip())
        rec = fn(payload)
        if rec is None:
            return None
        rec = dict(rec)
        rec.update(sysf)
        out.append(rec)
    return out


def _json_payload(payload):
    if not payload.lstrip().startswith("{"):
        return None
    try:
        d = json.loads(payload)
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def try_format(f, lines, pattern=""):
    """Try one format on every line. Returns {fmt, recs, spec, conf, skip} or None."""
    spec, skip, conf = {}, set(), "high"
    if f == "cef":
        recs = _per_line(lines, lambda p: parse_cef_py(p) if looks_like_cef(p) else None)
    elif f == "leef":
        recs = _per_line(lines, lambda p: parse_leef_py(p) if "LEEF:" in p else None)
    elif f == "panos":
        recs = _per_line(lines, fm.parse_panos)
        if recs:
            spec = {"ptype": recs[0].get("type", ""), "psub": recs[0].get("subtype", "")}
    elif f == "xml":
        recs = _per_line(lines, fm.parse_xml)
    elif f == "apache":
        recs = _per_line(lines, fm.parse_apache)
    elif f == "grok":
        try:
            rx, lua_pat, names = fm.compile_grok(pattern)
        except ValueError as e:
            raise ApiError(str(e))
        recs = _per_line(lines, lambda p: fm.parse_grok(p, rx, names))
        spec = {"lua_pattern": lua_pat, "names": names}
    elif f in ("table", "w3c"):
        h = fm.table_header(lines)
        if not h or (f == "w3c" and h["kind"] != "w3c"):
            return None
        data = [l for i, l in enumerate(lines) if i not in h["skip"]]
        if not data:
            return None
        recs = []
        for l in data:
            r = fm.parse_table(l, h["cols"], h["delim"])
            if r is None:
                return None
            recs.append(r)
        spec = {"cols": h["cols"], "delim": h["delim"]}
        skip = h["skip"]
        conf = "high" if h["kind"] == "w3c" else "low"
    elif f == "kv":
        recs = _per_line(lines, parse_kv_py)
        conf = "low"
    elif f == "json":
        recs = _per_line(lines, _json_payload)
    else:
        return None
    if not recs:
        return None
    return {"fmt": f, "recs": recs, "spec": spec, "conf": conf, "skip": skip}


def sniff(lines, forced="auto", pattern=""):
    """Work out which text format the lines are in. Header rows are reported in skip (indexes into lines)."""
    lines = [l for l in lines if l.strip()]
    if not lines:
        return None
    forced = (forced or "auto").lower()
    if forced != "auto":
        cands = [forced]
    else:
        cands = (["grok"] if (pattern or "").strip() else []) + FORMAT_ORDER
    for f in cands:
        try:
            res = try_format(f, lines, pattern)
        except ApiError:
            if forced != "auto":
                raise
            continue
        if res:
            return res
    return None


def detect_info(text, forced="auto", pattern=""):
    """What the UI badge shows: the format guess for pasted text, without generating anything."""
    text = (text or "").strip()
    if not text:
        return {"format": None, "label": "", "message": "Paste in a record to test if Trickle can Auto Detect the format."}
    try:
        recs = parse_records(text, keep_header=True)
    except ApiError as e:
        return {"format": None, "label": "", "message": str(e)}
    if not all(set(r) == {"message"} and isinstance(r["message"], str) for r in recs):
        return {"format": "json", "label": "JSON", "conf": "high", "fields": len({k for r in recs for k in r}), "records": len(recs)}
    lines = [r["message"] for r in recs]
    try:
        res = sniff(lines, forced, pattern)
    except ApiError as e:
        return {"format": None, "label": "", "forced": forced, "message": str(e)}
    if not res:
        why = "Could not read these lines as %s." % FORMAT_NAMES.get(forced, forced) if forced != "auto" else \
            "Not recognised. For CSV or tab separated logs paste the header row first, or pick a format or a custom pattern."
        return {"format": None, "label": "", "forced": forced, "message": why}
    fields = sorted({k for r in res["recs"] for k in r})
    tip = ""
    if res["fmt"] == "table" and len(lines) < 2:
        tip = "Header rows need at least one data row below them."
    info = {"format": res["fmt"], "label": FORMAT_NAMES.get(res["fmt"], res["fmt"]), "conf": res["conf"],
            "fields": len(fields), "records": len(res["recs"]), "sample": fields[:8], "tip": tip}
    if res["fmt"] == "panos":
        info["label"] += " " + (res["spec"].get("ptype") or "").title()
    return info


GEN_CEF_FUNCS = r"""
-- CEF parser: header is CEF:ver|vendor|product|version|signature|name|severity|extension.
local function cefUnescape(v)
    v = string.gsub(v, "\\=", "=")
    v = string.gsub(v, "\\n", "\n")
    v = string.gsub(v, "\\\\", "\\")
    return v
end

local function parseCef(payload)
    local at = string.find(payload, "CEF:", 1, true)
    local rest
    if at then
        rest = string.sub(payload, at + 4)
    elseif string.match(payload, "^%s*%d|") then
        rest = string.gsub(payload, "^%s+", "")
    else
        return nil
    end
    local names = { "cef_version", "device_vendor", "device_product", "device_version", "signature_id", "name", "severity" }
    local rec = {}
    local pos = 1
    for i = 1, 7 do
        local j = pos
        while true do
            local p = string.find(rest, "|", j, true)
            if not p then return nil end
            local b = 0
            local k = p - 1
            while k >= pos and string.sub(rest, k, k) == "\\" do b = b + 1; k = k - 1 end
            if b % 2 == 0 then
                local h = string.sub(rest, pos, p - 1)
                h = string.gsub(h, "\\|", "|")
                h = string.gsub(h, "\\\\", "\\")
                rec[names[i]] = h
                pos = p + 1
                break
            end
            j = p + 1
        end
    end
    local ext = string.sub(rest, pos)
    local keys = {}
    local idx = 1
    while true do
        local s1, e1, key = string.find(ext, "([%w_%.%-]+)=", idx)
        if not s1 then break end
        local prev = " "
        if s1 > 1 then prev = string.sub(ext, s1 - 1, s1 - 1) end
        if prev == " " then table.insert(keys, { key = key, s = s1, e = e1 }) end
        idx = e1 + 1
    end
    for n = 1, #keys do
        local stop = string.len(ext)
        if keys[n + 1] then stop = keys[n + 1].s - 2 end
        local val = string.sub(ext, keys[n].e + 1, stop)
        val = string.gsub(val, "^%s+", "")
        val = string.gsub(val, "%s+$", "")
        rec[keys[n].key] = cefUnescape(val)
    end
    local renames = {}
    for key, lab in pairs(rec) do
        if string.len(key) > 5 and string.sub(key, -5) == "Label" then
            local base = string.sub(key, 1, -6)
            if rec[base] ~= nil then table.insert(renames, { key = key, base = base, lab = lab }) end
        end
    end
    for _, rn in ipairs(renames) do
        local val = rec[rn.base]
        rec[rn.key] = nil
        rec[rn.base] = nil
        if rn.lab ~= "" then rec[rn.lab] = val end
    end
    return rec
end
"""


LUA_PARSE = {
"json": r"""local json = require('json')
""",
"syslog": r"""
-- Strip an RFC 5424 or RFC 3164 syslog wrapper. Returns the payload and the syslog fields.
local function stripSyslog(line)
    local fields = {}
    local ts, host, app, tail = string.match(line, "^<%d+>1%s+(%S+)%s+(%S+)%s+(%S+)%s+%S+%s+%S+%s+(.*)$")
    if ts then
        fields.syslog_time = ts
        fields.syslog_host = host
        fields.syslog_app = app
        if string.sub(tail, 1, 1) == "-" then
            tail = string.gsub(tail, "^%-%s*", "")
        else
            while string.sub(tail, 1, 1) == "[" do
                local close = string.find(tail, "]", 1, true)
                if not close then break end
                tail = string.sub(tail, close + 1)
            end
            tail = string.gsub(tail, "^%s+", "")
        end
        return tail, fields
    end
    local h3, rest = string.match(line, "^<?%d*>?%a%a%a%s+%d+%s+%d+:%d+:%d+%s+(%S+)%s+(.*)$")
    if h3 then
        fields.syslog_host = h3
        rest = string.gsub(rest, "^[%w_%-%./]+%[?%d*%]?:%s+", "")
        return rest, fields
    end
    return line, fields
end
""",
"cef": GEN_CEF_FUNCS,
"leef": r"""
-- LEEF parser: LEEF:1.0|vendor|product|version|eventid|key=value<tab>key=value
local function parseLeef(payload)
    local at = string.find(payload, "LEEF:", 1, true)
    if not at then return nil end
    local rest = string.sub(payload, at + 5)
    local names = { "leef_version", "device_vendor", "device_product", "device_version", "signature_id" }
    local rec = {}
    for i = 1, 5 do
        local p = string.find(rest, "|", 1, true)
        if not p then return nil end
        rec[names[i]] = string.sub(rest, 1, p - 1)
        rest = string.sub(rest, p + 1)
    end
    local delim = "\t"
    if string.sub(rec.leef_version, 1, 1) == "2" then
        local p = string.find(rest, "|", 1, true)
        if p then
            local head = string.sub(rest, 1, p - 1)
            rest = string.sub(rest, p + 1)
            if head ~= "" then delim = string.sub(head, 1, 1) end
        end
    end
    local pos = 1
    while pos <= string.len(rest) do
        local nxt = string.find(rest, delim, pos, true)
        local pair
        if nxt then pair = string.sub(rest, pos, nxt - 1); pos = nxt + 1 else pair = string.sub(rest, pos); pos = string.len(rest) + 1 end
        local k, v = string.match(pair, "^([^=]+)=(.*)$")
        if k then rec[k] = v end
    end
    return rec
end
""",
"kv": r"""
-- key=value parser (logfmt style). Quoted values may contain spaces.
local function parseKv(payload)
    local rec = {}
    local count = 0
    for key, val in string.gmatch(payload, "([%w_%.%-]+)=\"([^\"]*)\"") do rec[key] = val; count = count + 1 end
    local stripped = string.gsub(payload, "[%w_%.%-]+=\"[^\"]*\"", " ")
    for key, val in string.gmatch(stripped, "([%w_%.%-]+)=(%S+)") do rec[key] = val; count = count + 1 end
    if count < 2 then return nil end
    return rec
end
""",
}


def build_parse_funcs(fmt, spec=None):
    spec = spec or {}
    parts = [LUA_PARSE["syslog"]]
    if fmt == "json":
        parts.insert(0, LUA_PARSE["json"])
    elif fmt == "panos":
        parts.append(fm.lua_panos(spec.get("ptype", ""), lua_str))
    elif fmt == "xml":
        parts.append(fm.LUA_XML)
    elif fmt == "apache":
        parts.append(fm.lua_apache(lua_str))
    elif fmt in ("table", "w3c"):
        parts.append(fm.lua_table(spec["cols"], spec["delim"], lua_str))
    elif fmt == "grok":
        parts.append(fm.lua_grok(spec["lua_pattern"], spec["names"], lua_str))
    else:
        parts.append(LUA_PARSE[fmt])
    call = {"cef": "parseCef(payload)", "kv": "parseKv(payload)", "panos": "parsePanos(payload)", "xml": "parseXml(payload)",
            "apache": "parseApache(payload)", "table": "parseTable(payload)", "w3c": "parseTable(payload)", "grok": "parseGrok(payload)"}
    disp = ["", "-- Detect the payload format and return a flat table of fields (or nil).", "local function parseLine(line)",
            "    local payload, rec = stripSyslog(line)"]
    if fmt == "leef":
        disp += ['    local parsed = nil', '    if string.find(payload, "LEEF:", 1, true) then parsed = parseLeef(payload) end']
    elif fmt in call:
        disp += ['    local parsed = ' + call[fmt]]
    else:
        disp += ['    local parsed = nil', '    if string.sub(string.gsub(payload, "^%s+", ""), 1, 1) == "{" then',
                 '        local ok, d = pcall(json.decode, payload)', '        if ok and type(d) == "table" then parsed = d end', '    end']
    disp += ["    if not parsed then return nil end",
             "    for k, v in pairs(rec) do parsed[k] = v end",
             "    return parsed", "end", ""]
    return "".join(parts) + "\n".join(disp)


GEN_TEMPLATE = r"""-- OCSF serializer GENERATED by Trickle from a sample record.
-- Vendor: __VENDOR__   Class: __CLASS_NAME__ (__CLASS_UID__)
-- Review it: the field map below is a best guess from field names.
-- Edit MAP, CLASS settings and the enums, then press Run to see before and after.
-- Rules honored: no dollar-sigil tokens, single-line strings, ASCII comments.

local OCSF_VERSION = "__VERSION__"
local VENDOR_NAME  = __VENDOR_Q__
local PRODUCT_NAME = __PRODUCT_Q__
local PRODUCT_UID   = __PRODUCT_UID__
local CLASS_UID    = __CLASS_UID__
local CLASS_NAME   = "__CLASS_NAME__"
local CATEGORY_UID = __CAT_UID__
local CATEGORY_NAME = "__CAT_NAME__"
local FIXED_ACTIVITY_ID = __ACTIVITY__

-- vendor field -> OCSF dotted path. number = true converts to a number.
local MAP = {
__MAP__
}

-- Fields handled below, so they are not copied into unmapped.
local CONSUMED = {
__CONSUMED__
}

local TIME_FIELDS   = { __TIME_FIELDS__ }
local SEVERITY_FIELD = __SEV_FIELD__
local ACTION_FIELD   = __ACTION_FIELD__

local SEVERITY = { info = 1, informational = 1, low = 2, medium = 3, high = 4, critical = 5, fatal = 6, ["very-high"] = 5, unknown = 0 }

-- Numeric severities (CEF uses 0 to 10): 0 info, 1-3 low, 4-6 medium, 7-8 high, 9-10 critical.
local function severityId(sev)
    local n = tonumber(sev)
    if n then
        if n <= 0 then return 1 elseif n <= 3 then return 2 elseif n <= 6 then return 3 elseif n <= 8 then return 4 end
        return 5
    end
    return SEVERITY[string.lower(tostring(sev or ""))] or 0
end

-- Read a value by plain key or by dotted path such as alertInfo.subject.
local function getPath(obj, path)
    local direct = obj[path]
    if direct ~= nil then return direct end
    local cur = obj
    for part in string.gmatch(path, "[^.]+") do
        if type(cur) ~= "table" then return nil end
        cur = cur[part]
    end
    return cur
end

local function isEmpty(v)
    if v == nil or v == "" then return true end
    if type(v) == "table" and next(v) == nil then return true end
    return false
end

local function setNestedField(obj, path, value)
    if value == nil or path == nil or path == "" then return end
    local keys = {}
    for key in string.gmatch(path, "[^.]+") do
        if key and key ~= "" then table.insert(keys, key) end
    end
    if #keys == 0 then return end
    local current = obj
    for i = 1, #keys - 1 do
        local key = keys[i]
        local base = string.match(key, "(.-)%[(%d+)%]")
        if base then
            local index = tonumber(string.match(key, "%[(%d+)%]")) + 1
            if current[base] == nil then current[base] = {} end
            if current[base][index] == nil then current[base][index] = {} end
            current = current[base][index]
        else
            if current[key] == nil then current[key] = {} end
            current = current[key]
        end
    end
    local finalKey = keys[#keys]
    local base = string.match(finalKey, "(.-)%[(%d+)%]")
    if base then
        local index = tonumber(string.match(finalKey, "%[(%d+)%]")) + 1
        if current[base] == nil then current[base] = {} end
        current[base][index] = value
    else
        current[finalKey] = value
    end
end

-- Civil date and time (UTC) to epoch milliseconds, no os.time so no timezone surprises.
local function civilMs(yy, mm, dd, h, mi, s)
    if mm <= 2 then yy = yy - 1 end
    local era = math.floor(yy / 400)
    local yoe = yy - era * 400
    local mp = (mm + 9) % 12
    local doy = math.floor((153 * mp + 2) / 5) + dd - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    local days = era * 146097 + doe - 719468
    return (days * 86400 + h * 3600 + mi * 60 + s) * 1000
end

local function isoToMs(ts)
    local y, mo, d, h, mi, s = string.match(ts, "^(%d%d%d%d)[-/](%d%d)[-/](%d%d)[T ](%d%d):(%d%d):(%d%d)")
    if not y then return nil end
    local ms = civilMs(tonumber(y), tonumber(mo), tonumber(d), tonumber(h), tonumber(mi), tonumber(s))
    local frac = string.match(ts, "^%d%d%d%d[-/]%d%d[-/]%d%d[T ]%d%d:%d%d:%d%d%.(%d+)")
    if frac then ms = ms + tonumber(string.sub(frac .. "000", 1, 3)) end
    return ms
end

local MONTHS = { jan = 1, feb = 2, mar = 3, apr = 4, may = 5, jun = 6, jul = 7, aug = 8, sep = 9, oct = 10, nov = 11, dec = 12 }

-- Text dates such as Nov 04 2026 12:30:00 (common in CEF rt fields).
local function textToMs(ts)
    local mon, d, y, h, mi, s = string.match(ts, "^(%a%a%a)%a*%s+(%d+),?%s+(%d%d%d%d)%s+(%d+):(%d+):(%d+)")
    if not mon or not MONTHS[string.lower(mon)] then return nil end
    return civilMs(tonumber(y), MONTHS[string.lower(mon)], tonumber(d), tonumber(h), tonumber(mi), tonumber(s))
end

local function toEpochMs(v)
    if v == nil or v == "" then return nil end
    local n = tonumber(v)
    if n then
        if n < 100000000000 then n = n * 1000 end
        return n
    end
    if type(v) == "string" then return isoToMs(v) or textToMs(v) end
    return nil
end

__CEF_FUNCS__
local function dispositionId(action)
    local a = string.lower(tostring(action or ""))
    if a == "allow" or a == "allowed" or a == "permit" then return 1
    elseif a == "block" or a == "blocked" or a == "deny" or a == "denied" then return 2
    elseif a == "drop" or a == "dropped" then return 6
    elseif a == "monitor" or a == "alert" or a == "detect" then return 15 end
    return 99
end

local function activityId(action)
    if FIXED_ACTIVITY_ID >= 0 then return FIXED_ACTIVITY_ID end
    local a = string.lower(tostring(action or ""))
    if a == "allow" or a == "allowed" or a == "permit" then return 1 end
    if a == "block" or a == "blocked" or a == "deny" or a == "denied" or a == "drop" then return 5 end
    return 6
end

function processEvent(event)
    if event == nil then return {} end
    local e = event
    if type(event.message) == "table" then e = event.message end
    local r = {}
__CEF_USE__
    local action = nil
    if ACTION_FIELD then action = getPath(e, ACTION_FIELD) end
    local act = activityId(action)

    r.class_uid = CLASS_UID
    r.class_name = CLASS_NAME
    r.category_uid = CATEGORY_UID
    r.category_name = CATEGORY_NAME
    r.activity_id = act
    r.type_uid = CLASS_UID * 100 + act
    r.status_id = 1

    local sev = nil
    if SEVERITY_FIELD then sev = getPath(e, SEVERITY_FIELD) end
    r.severity_id = severityId(sev)
    if not isEmpty(sev) then r.severity = tostring(sev) end

    if not isEmpty(action) then
        r.action = tostring(action)
        r.disposition_id = dispositionId(action)
    end

    for _, f in ipairs(TIME_FIELDS) do
        local ms = toEpochMs(getPath(e, f))
        if ms then r.time = ms; break end
    end

__CEF_TIME__
    setNestedField(r, "metadata.version", OCSF_VERSION)
    setNestedField(r, "metadata.product.vendor_name", VENDOR_NAME)
    setNestedField(r, "metadata.product.name", PRODUCT_NAME)
    setNestedField(r, "dataSource.category", "security")
    setNestedField(r, "dataSource.vendor", VENDOR_NAME)
    setNestedField(r, "dataSource.name", PRODUCT_NAME)
    __FEATURE__

    if CLASS_UID == 2004 then setNestedField(r, "finding_info.product_uid", PRODUCT_UID) end

    local mapped = {}
    local mappedVals = {}
    for _, m in ipairs(MAP) do
        mapped[m.source] = true
        local v = getPath(e, m.source)
        if not isEmpty(v) then
            if m.number then v = tonumber(v) or v end
            if m.time then v = toEpochMs(v) or v end
            setNestedField(r, m.target, v)
            if type(v) == "string" and string.len(v) >= 4 then mappedVals[v] = true end
        end
    end
__EXTRA__
    local obs = {}
    local function addObs(name, type_id, value)
        if not isEmpty(value) then table.insert(obs, { name = name, type_id = type_id, value = tostring(value) }) end
    end
    if r.src_endpoint then addObs("src_endpoint.ip", 2, r.src_endpoint.ip) end
    if r.dst_endpoint then addObs("dst_endpoint.ip", 2, r.dst_endpoint.ip) end
    if r.http_request and r.http_request.url then
        addObs("http_request.url.hostname", 1, r.http_request.url.hostname)
        addObs("http_request.url.url_string", 6, r.http_request.url.url_string)
    end
    if r.actor and r.actor.user then addObs("actor.user.name", 4, r.actor.user.name) end
    if r.file and r.file.hashes and r.file.hashes[1] then addObs("file.hashes", 8, r.file.hashes[1].value) end
    if #obs > 0 then r.observables = obs end

    -- everything not mapped or consumed goes under unmapped, walking nested objects
    local function copyUnmapped(src, prefix)
        for k, v in pairs(src) do
            local path = prefix .. tostring(k)
            local dup = type(v) == "string" and string.len(v) >= 4 and mappedVals[v]
            if not mapped[path] and not CONSUMED[path] and not isEmpty(v) and not dup then
                if type(v) == "table" and #v == 0 then
                    copyUnmapped(v, path .. ".")
                else
                    setNestedField(r, "unmapped." .. path, v)
                end
            end
        end
    end
    copyUnmapped(e, "")
    return r
end
"""

GEN_MITRE_EXTRA = r"""
    local function listOf(v)
        if isEmpty(v) then return {} end
        if type(v) == "table" then return v end
        return { v }
    end
    local tactics = listOf(getPath(e, __TAC__))
    local techs = listOf(getPath(e, __TEC__))
    local n = math.max(#tactics, #techs)
    for i = 1, n do
        local base = "finding_info.attacks[" .. (i - 1) .. "]"
        if tactics[i] then setNestedField(r, base .. ".tactic.name", tostring(tactics[i])) end
        if techs[i] then setNestedField(r, base .. ".technique.name", tostring(techs[i])) end
    end
"""


def generate_serializer(text, vendor="", product="", version="", forced="auto", pattern=""):
    recs = parse_records(text, keep_header=True)
    fmt, spec = None, {}
    if recs and all(isinstance(r.get("message"), str) and set(r) <= {"message", "host", "source_type", "timestamp", "service"} for r in recs):
        found = sniff([r["message"] for r in recs], forced, pattern)
        if found:
            fmt, spec, recs = found["fmt"], found["spec"], found["recs"]
        else:
            raise ApiError("Could not recognise the log format. Trickle reads JSON, CEF, LEEF, key=value, Palo Alto PAN-OS CSV, "
                           "XML events, Apache/Nginx access logs, and CSV/TSV/W3C logs with a header row. For anything else pick "
                           "Custom pattern under the paste box and describe the line with a grok-style pattern.")
    if fmt in ("panos", "xml", "apache", "table", "w3c", "grok", "kv", "json", "cef", "leef") and not recs:
        raise ApiError("No events found after reading the sample.")
    vendor, product = (vendor or "").strip(), (product or "").strip()
    if "/" in vendor and not product:          # Vendor / Product typed in one box
        vendor, product = [x.strip() for x in vendor.split("/", 1)]
    elif "/" in product and not vendor:
        vendor, product = [x.strip() for x in product.split("/", 1)]
    if fmt:                                    # CEF and LEEF headers carry both
        vendor = vendor or (recs[0].get("device_vendor") or "").strip()
        product = product or (recs[0].get("device_product") or "").strip()
    if fmt == "panos":
        vendor, product = vendor or "Palo Alto Networks", product or "PAN-OS"
    def flat_paths(d, prefix=""):
        for k, v in d.items():
            path = prefix + str(k)
            if isinstance(v, dict) and v:
                yield from flat_paths(v, path + ".")
            else:
                yield path

    keys = []
    for r in recs:
        for k in flat_paths(r):
            if k not in keys:
                keys.append(k)
    by_norm = {}
    for k in keys:
        by_norm.setdefault(_norm(k), k)

    def pick(options):
        for o in options:
            if o in by_norm:
                return by_norm[o]
        return None

    time_keys = [by_norm[n] for n in GEN_TIME_KEYS if n in by_norm]
    sev_key = pick(GEN_SEV_KEYS)
    act_key = pick(GEN_ACTION_KEYS)
    tac_key = next((k for k in keys if "mitre" in _norm(k) and "tactic" in _norm(k)), None)
    tec_key = next((k for k in keys if "mitre" in _norm(k) and "technique" in _norm(k) and "sub" not in _norm(k)), None)
    mitre_keys = [k for k in keys if "mitre" in _norm(k)]

    if not time_keys and "starttime" in by_norm:
        time_keys = [by_norm["starttime"]]   # used for time, and also mapped to start_time
    time_consumed = {k for k in time_keys if _norm(k) not in ("starttime", "endtime", "start", "end")}
    consumed = time_consumed | {k for k in (sev_key, act_key) if k} | set(mitre_keys)
    if fmt:
        consumed |= {k for k in keys if k in LOG_CONSUMED}
    maps, used_targets = [], set()
    for k in keys:
        if k in consumed:
            continue
        if fmt == "panos" and k == "category":
            continue   # URL category, not a finding type
        nested = "." in k and fmt in (None, "json", "kv", "cef", "leef")
        hit = (LOG_ALIASES.get(_norm(k)) if fmt and fmt != "json" and not nested else None) or GEN_ALIASES.get(_norm(k))
        if hit is None and nested and fmt in (None, "json"):
            hit = None   # nested fields map only when the full path has an alias; the rest go to unmapped
        if hit and hit[0] not in used_targets:
            used_targets.add(hit[0])
            maps.append((k, hit[0], hit[1]))
            if hit[0] == "finding_info.title":
                maps.append((k, "malware[0].name", "s"))
    gap = gap_maps(recs, product or vendor, maps, used_targets, keys)
    mapped_names = {m[0] for m in maps}

    nset = {m[1] for m in maps}
    has = lambda p: any(t.startswith(p) for t in nset)
    if has("finding_info") or tac_key:
        cls, cname, cat, catname, activity = 2004, "Detection Finding", 2, "Findings", 1
    elif has("http_request"):
        cls, cname, cat, catname, activity = 4002, "HTTP Activity", 4, "Network Activity", 0
    elif has("query."):
        cls, cname, cat, catname, activity = 4003, "DNS Activity", 4, "Network Activity", 6
    elif has("src_endpoint") or has("dst_endpoint"):
        cls, cname, cat, catname, activity = 4001, "Network Activity", 4, "Network Activity", -1
    else:
        cls, cname, cat, catname, activity = 0, "Base Event", 0, "Uncategorized", 0

    def q(s):
        return lua_str(s)

    map_lines = []
    for src, tgt, num in maps:
        flag = ", number = true" if num == "n" or num is True else (", time = true" if num == "t" else "")
        map_lines.append("    { source = %s, target = %s%s }," % (q(src), q(tgt), flag))
    cons_lines = ["    [%s] = true," % q(k) for k in sorted(consumed)]

    code = GEN_TEMPLATE
    extra = ""
    if tac_key or tec_key:
        extra = GEN_MITRE_EXTRA.replace("__TAC__", q(tac_key) if tac_key else "nil").replace("__TEC__", q(tec_key) if tec_key else "nil")
    vendor = vendor or "Vendor"
    product = product or vendor
    version = (version or "").strip()
    if not re.match(r"^\d+\.\d+\.\d+(-dev)?$", version):
        version = "1.8.0"
    et_key, st_key = by_norm.get("eventtype"), by_norm.get("eventsubtype")
    if fmt == "panos":
        et_key, st_key = by_norm.get("type"), by_norm.get("subtype")
    if et_key and st_key:
        feature = 'setNestedField(r, "metadata.product.feature.name", tostring(e[%s] or "") .. " / " .. tostring(e[%s] or ""))' % (q(et_key), q(st_key))
    elif et_key or st_key:
        feature = 'setNestedField(r, "metadata.product.feature.name", tostring(e[%s]))' % q(et_key or st_key)
    else:
        feature = "-- no event_type field found, so no feature name"
    uid = re.sub(r"[^a-z0-9]+", "_", product.lower()).strip("_") or "vendor"
    if fmt:
        parse_use = ('    local envelope_ts = nil\n    if type(event.message) == "string" then\n        local parsed = parseLine(event.message)\n'
                     '        if parsed then\n            e = parsed\n            envelope_ts = event.timestamp\n        end\n    end')
        parse_time = ('    -- last resort only: the envelope timestamp is ingest time, not event time\n'
                      '    if not r.time and envelope_ts then\n        local ms2 = toEpochMs(envelope_ts)\n        if ms2 then r.time = ms2 end\n    end')
        parse_funcs = build_parse_funcs(fmt, spec)
    else:
        parse_use = parse_time = parse_funcs = ""
    for a, b in [("__CEF_FUNCS__", parse_funcs), ("__CEF_USE__", parse_use), ("__CEF_TIME__", parse_time), ("__FEATURE__", feature), ("__PRODUCT_UID__", q(uid)), ("__VERSION__", version), ("__VENDOR_Q__", q(vendor)), ("__PRODUCT_Q__", q(product)), ("__VENDOR__", re.sub(r"[^\x20-\x7e]", "", vendor)),
                 ("__CLASS_NAME__", cname), ("__CLASS_UID__", str(cls)), ("__CAT_UID__", str(cat)),
                 ("__CAT_NAME__", catname), ("__ACTIVITY__", str(activity)),
                 ("__MAP__", "\n".join(map_lines)), ("__CONSUMED__", "\n".join(cons_lines)),
                 ("__TIME_FIELDS__", ", ".join(q(k) for k in time_keys)),
                 ("__SEV_FIELD__", q(sev_key) if sev_key else "nil"),
                 ("__ACTION_FIELD__", q(act_key) if act_key else "nil"),
                 ("__EXTRA__", extra)]:
        code = code.replace(a, b)
    unmapped = [k for k in keys if k not in mapped_names and k not in consumed]
    return {"code": code, "class_name": cname, "class_uid": cls, "fmt": fmt or "json", "spec": spec, "gap": gap, "format": FORMAT_NAMES.get(fmt, "JSON") if fmt else "JSON", "vendor": vendor, "product": product,
            "mapped": [{"source": m[0], "target": m[1]} for m in maps],
            "handled": sorted(consumed), "unmapped": unmapped}


MAX_LOG_TYPES = 20


COLLECTOR_TIMEOUT = 30


def run_collector(src):
    """Run a DPM collector Lua against the mock API. Returns records, the request transcript and any errors."""
    code = str(src.get("code") or "")
    if not code.strip():
        raise ApiError("Paste a collector Lua script first, or press Insert starter collector.")
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        raise ApiError("The collector is larger than 1 MB.")
    lua = find_lua()
    if not lua:
        raise ApiError("No Lua interpreter found. Install one with: brew install luajit", 409)
    mock_cfg = src.get("mock") if isinstance(src.get("mock"), dict) else {}
    rec_text = str(mock_cfg.get("records") or "").strip()
    records = parse_records(rec_text) if rec_text else []
    api = mockapi.MockApi(mock_cfg, records)
    if api.config_error:
        raise ApiError(api.config_error)
    cfg_text = str(src.get("config") or "").strip()
    try:
        config = json.loads(cfg_text) if cfg_text else {}
    except ValueError:
        raise ApiError("The collector config is not valid JSON.")
    keys = [k.strip() for k in re.split(r"[,\s]+", str(src.get("chkpt_keys") or "")) if k.strip()][:20]
    seed_text = str(src.get("chkpt_seed") or "").strip()
    try:
        seed = json.loads(seed_text) if seed_text else {}
    except ValueError:
        raise ApiError("Checkpoint seeds must be a JSON object such as {\"initial_since\": \"2026-11-01T00:00:00Z\"}.")
    if not isinstance(seed, dict):
        raise ApiError("Checkpoint seeds must be a JSON object.")
    def _seed_val(v):
        # {now_ms-2h} and {now_s-6h} expand to epoch milliseconds or seconds relative to the run time (units s, m, h, d)
        def sub(m):
            now = time.time()
            delta = 0
            if m.group(2):
                delta = (1 if m.group(2) == "+" else -1) * int(m.group(3)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(4) or "s"]
            t = now + delta
            return str(int(t * 1000)) if m.group(1) == "ms" else str(int(t))
        return re.sub(r"\{now_(ms|s)(?:([+-])(\d+)([smhd])?)?\}", sub, v)
    seed = {k: _seed_val(v) for k, v in seed.items() if isinstance(v, str)}
    run_dir = Path(tempfile.mkdtemp(prefix="pipelab_col_"))
    out = {"ok": True, "records": [], "transcript": api.transcript, "logs": [], "errors": [], "printed": [], "requests": 0}
    try:
        (run_dir / "collector.lua").write_text(code, encoding="utf-8")
        (run_dir / "settings.json").write_text(json.dumps({"config": config, "chkpt_keys": keys, "chkpt_seed": seed, "max_requests": 50}), encoding="utf-8")
        proc = subprocess.Popen([lua, str(HERE / "collector_runner.lua"), "collector.lua", "settings.json"], cwd=str(run_dir),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=clean_env())
        timer = threading.Timer(COLLECTOR_TIMEOUT, proc.kill)
        timer.start()
        try:
            for line in proc.stdout:
                line = line.rstrip("\n")
                try:
                    m = json.loads(line)
                except ValueError:
                    if line.strip():
                        out["printed"].append(line[:300])
                    continue
                t = m.get("t") if isinstance(m, dict) else None
                if t == "req":
                    resp = api.handle(m.get("params") or {})
                    proc.stdin.write(json.dumps(resp) + "\n")
                    proc.stdin.flush()
                elif t == "emit":
                    if len(out["records"]) < MAX_RECORDS and isinstance(m.get("log"), dict):
                        out["records"].append(m["log"])
                    elif not isinstance(m.get("log"), dict):
                        out["errors"].append("emit { log = ... } must be a table, got %s" % type(m.get("log")).__name__)
                elif t == "log":
                    out["logs"].append("%s: %s" % (m.get("level"), m.get("msg")))
                elif t in ("error", "fatal"):
                    out["errors"].append(("%s: " % m["where"] if m.get("where") else "") + tidy(str(m.get("error"))))
                    if t == "fatal":
                        out["ok"] = False
                elif t == "done":
                    out["requests"] = m.get("requests", 0)
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
            proc.wait(timeout=5)
            timer.cancel()
        if proc.returncode not in (0, None) and not out["errors"]:
            out["errors"].append("The collector runner stopped (timed out after %d seconds?)." % COLLECTOR_TIMEOUT)
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
    out["ok"] = out["ok"] and not out["errors"]
    out["auth_failures"] = sum(1 for t in api.transcript if t["auth_ok"] is False)
    out["warnings"] = [t["warn"] for t in api.transcript if t.get("warn")][:5]
    return out


def norm_pipeline(p):
    """Multi-type record source: merge every filled box into the single record stream the rest of Trickle expects."""
    src = (p or {}).get("source") or {}
    if src.get("type") == "collector":          # the last collector run left its events in text
        if not str(src.get("text", "")).strip():
            raise ApiError("Run the collector first (Source, Run collector). Its emitted events are what the next step receives.")
        src["type"] = "record"
        return p
    if src.get("type") == "record" and src.get("multi") and isinstance(src.get("types"), list):
        lines = []
        for t in src["types"][:MAX_LOG_TYPES]:
            if isinstance(t, dict) and str(t.get("text", "")).strip():
                lines.extend(json.dumps(r, separators=(",", ":")) for r in parse_records(t["text"]))
        src["text"] = "\n".join(lines)
        if not lines:
            raise ApiError("Every log type box is empty. Paste at least one event.")
    return p


def generate_multi(types, vendor="", product="", version=""):
    """One embedded serializer per pasted log type, plus a processEvent that picks the closest one by field names."""
    sel = [t for t in (types or [])[:MAX_LOG_TYPES] if isinstance(t, dict) and str(t.get("text", "")).strip()]
    filled = [(str(t.get("name", "")).strip(), t.get("text", "")) for t in sel]
    t_forced = [str(t.get("format") or "auto") for t in sel]
    t_pattern = [str(t.get("pattern") or "") for t in sel]
    if not filled:
        raise ApiError("Paste at least one event into a log type box first.")
    parts, summary = [], {"mapped": [], "handled": set(), "unmapped": [], "types": []}
    chunks = []
    for i, (name, text) in enumerate(filled, 1):
        recs = parse_records(text, keep_header=True)
        g = generate_serializer(text, vendor, product, version, t_forced[i - 1], t_pattern[i - 1])
        vendor, product = g["vendor"], g["product"]
        label = name or "Log type %d" % i
        keys = sorted({k for r in recs for k in r}) if g["fmt"] == "json" and not all(set(r) == {"message"} for r in recs) else []
        inner = g["code"]
        if "function processEvent(event)" not in inner:
            raise ApiError("Internal error: generated serializer has no processEvent.")
        inner = inner.replace("function processEvent(event)", "function process_%d(event)" % i, 1)
        match = None
        if g["fmt"] != "json" or "local function parseLine" in inner:
            sp = g["spec"] or {}
            extra = ""
            if g["fmt"] == "panos" and sp.get("ptype"):
                extra = ("    local score = 1\n    if string.upper(tostring(p.type or \"\")) ~= %s then return 0 end\n" % lua_str(sp["ptype"].upper()))
                if sp.get("psub") and sp["ptype"].upper() != "TRAFFIC":
                    extra += "    if tostring(p.subtype or \"\") == %s then score = 2 end\n" % lua_str(sp["psub"])
                extra += "    return score\n"
            else:
                extra = "    return 1\n"
            match = ("    match_%d = function(line)\n        local p = parseLine(line)\n        if not p then return 0 end\n" % i
                     + "".join("    " + ln + "\n" for ln in extra.rstrip("\n").split("\n")) + "    end")
            inner = inner.rstrip() + "\n" + match
        chunks.append((i, label, keys, inner))
        summary["mapped"].extend(g["mapped"])
        if g.get("gap"):
            summary.setdefault("gaps", []).append(g["gap"])
        summary["handled"].update(g["handled"])
        summary["unmapped"].extend(g["unmapped"])
        summary["types"].append({"name": label, "class_name": g["class_name"], "class_uid": g["class_uid"]})
    out = ["-- OCSF serializer GENERATED by Trickle from %d log types." % len(chunks),
           "-- Each type below has its own serializer. processEvent picks the closest one by field names.",
           "-- Rules honored: no dollar-sigil tokens, single-line strings, ASCII comments.", ""]
    out.append("local " + ", ".join("process_%d" % i for i, *_ in chunks))
    out.append("local " + ", ".join("match_%d" % i for i, *_ in chunks))
    for i, label, keys, inner in chunks:
        out += ["", "-- ---- type %d: %s ----" % (i, re.sub(r"[^\x20-\x7e]", "", label)), "do", inner.rstrip(), "end"]
    out += ["", "local TYPES = {"]
    for i, label, keys, inner in chunks:
        out.append("    { name = %s, fn = process_%d, match = match_%d, keys = { %s } }," % (lua_str(label), i, i, ", ".join("[%s] = true" % lua_str(k) for k in keys)))
    out += ["}", "",
            "function processEvent(event)",
            "    if event == nil then return {} end",
            "    local e = event",
            '    if type(event.message) == "table" then e = event.message end',
            "    local best, bestScore = TYPES[1], -1",
            "    if type(event.message) == \"string\" then",
            "        local top = 0",
            "        for _, t in ipairs(TYPES) do",
            "            if t.match then",
            "                local sc = t.match(event.message)",
            "                if sc > top then top = sc; best = t end",
            "            end",
            "        end",
            "        local r0 = best.fn(event)",
            "        if type(r0) == \"table\" then",
            "            if r0.metadata == nil then r0.metadata = {} end",
            "            if r0.metadata.product == nil then r0.metadata.product = {} end",
            "            if r0.metadata.product.feature == nil then r0.metadata.product.feature = { name = best.name } end",
            "        end",
            "        return r0",
            "    end",
            "    for _, t in ipairs(TYPES) do",
            "        local hit, total, extra = 0, 0, 0",
            "        for k in pairs(t.keys) do",
            "            total = total + 1",
            "            if e[k] ~= nil then hit = hit + 1 end",
            "        end",
            "        for k in pairs(e) do",
            "            if not t.keys[k] then extra = extra + 1 end",
            "        end",
            "        local score = hit / (total + extra + 0.0001)",
            "        if score > bestScore then best, bestScore = t, score end",
            "    end",
            "    local r = best.fn(event)",
            "    if type(r) == \"table\" then",
            "        if r.metadata == nil then r.metadata = {} end",
            "        if r.metadata.product == nil then r.metadata.product = {} end",
            "        if r.metadata.product.feature == nil then r.metadata.product.feature = { name = best.name } end",
            "    end",
            "    return r",
            "end", ""]
    names = [t["class_name"] + " (" + str(t["class_uid"]) + ")" for t in summary["types"]]
    return {"code": "\n".join(out), "class_name": "%d log types: %s" % (len(chunks), ", ".join(names)), "class_uid": "multiple",
            "format": "JSON", "vendor": vendor, "product": product, "mapped": summary["mapped"],
            "handled": sorted(summary["handled"]), "unmapped": summary["unmapped"], "types": summary["types"],
            "gap": _merge_gaps(summary.get("gaps"))}


def _merge_gaps(gaps):
    if not gaps:
        return None
    oks = [g for g in gaps if g.get("state") == "ok"]
    if not oks:
        return gaps[0]
    return {"state": "ok", "name": oks[0]["name"], "rules": oks[0]["rules"], "added": [a for g in oks for a in g["added"]],
            "unresolved": sorted({u for g in oks for u in g["unresolved"]})[:40], "unresolved_count": sum(g["unresolved_count"] for g in oks)}


def to_lua(v):
    if v is None:
        return "nil"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return lua_str(v)
    if isinstance(v, list):
        return "{" + ",".join(to_lua(x) for x in v) + "}"
    if isinstance(v, dict):
        return "{" + ",".join("[%s]=%s" % (lua_str(str(k)), to_lua(x))
                              for k, x in v.items() if x is not None) + "}"
    return lua_str(str(v))


def load_serializer_code(step):
    path = str(step.get("path", "")).strip()
    if path:
        fp = Path(path).expanduser()
        if not fp.is_file():
            raise ApiError("Serializer file not found: %s" % path)
        if fp.stat().st_size > MAX_CODE_BYTES:
            raise ApiError("Serializer file is larger than 1 MB.")
        return fp.read_text(encoding="utf-8", errors="replace")
    code = str(step.get("code", ""))
    if not code.strip():
        raise ApiError("The Lua serializer step is empty. Paste your serializer or give a file path.")
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        raise ApiError("Serializer code is larger than 1 MB.")
    return code


def lint_lua(code):
    """Console-validator and config-loader traps (dpm-lua-creation rules 6, 7, 10)."""
    lines = code.splitlines()
    findings = []

    def add(rule, detail, nums):
        if nums:
            findings.append({"rule": rule, "detail": detail, "lines": nums[:12]})

    def hits(pattern, code_only=True):
        rx = re.compile(pattern)
        res = []
        for n, l in enumerate(lines, 1):
            if code_only and re.match(r"^\s*--", l):
                continue
            if rx.search(l):
                res.append(n)
        return res

    add("trailing string concatenation", "The console validator rejects strings continued with .. at the end of a line. Keep each string on one line.", hits(r"\.\.[ \t]*$"))
    add("assignment value on the next line", "The console validator reads an empty right-hand side as 'expected a value'.", hits(r"[^=~<>]=[ \t]*$"))
    add("apostrophe in a comment", "A stray apostrophe in a comment can trip the console lexer. Use plain ASCII.", [n for n, l in enumerate(lines, 1) if re.match(r"^\s*--.*'", l)])
    add("Lua 5.3+ syntax", "The console validator is Lua 5.1 flavoured: no //, bit operators, goto or hex literals.", sorted(set(hits(r"[^:]//") + hits(r"<<") + hits(r">>") + hits(r"0[xX][0-9a-fA-F]") + hits(r"\bgoto\b"))))
    add("$identifier in source", "The dataplane config loader treats $name as a required environment variable, even in comments.", hits(r"\$[A-Za-z_]", code_only=False))
    if not re.search(r"function\s+processEvent\b|processEvent\s*=", code):
        findings.append({"rule": "no processEvent", "detail": "Define a global function processEvent(record).", "lines": []})
    missing = [k for k in ("dataSource.category", "dataSource.vendor", "dataSource.name") if k not in code]
    if missing:
        findings.append({"rule": "dataSource fields missing",
                         "detail": "Serializers should stamp dataSource.category, dataSource.vendor and dataSource.name next to metadata.product.* so events appear in XDR search. Not found in the code: %s." % ", ".join(missing),
                         "lines": []})
    return findings


# ---------------------------------------------------------------------------
# Diff and OCSF checks
# ---------------------------------------------------------------------------

def flatten(obj, prefix=""):
    leaves = {}

    def put(path, v):
        if isinstance(v, dict) and v:
            leaves.update(flatten(v, path))
        elif isinstance(v, list) and v:
            leaves.update(flatten(v, path))
        else:
            leaves[path] = v

    if isinstance(obj, dict):
        for k, v in obj.items():
            put(("%s.%s" % (prefix, k)) if prefix else str(k), v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            put("%s[%d]" % (prefix, i), v)
    return leaves


def norm(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v == int(v) and abs(v) < 1e15:
        return str(int(v))
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True)
    return str(v)


def type_name(v):
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if v is None:
        return "null"
    return "object" if isinstance(v, dict) else "array"


KIND_ORDER = ["moved", "changed", "retyped", "unmapped", "dropped", "added", "empty", "unchanged"]


def diff_record(inp, out):
    """Compare a raw record with the serializer output.

    Matching is by value, so it is a good guide, not proof: when a value was
    transformed (for example an ISO time turned into epoch milliseconds) it
    shows up as dropped plus added.
    """
    fi, fo = flatten(inp), flatten(out)
    by_val = {}
    for q, w in fo.items():
        by_val.setdefault(norm(w), []).append(q)
    claimed = set()
    rows = []
    for p, v in fi.items():
        nv = norm(v)
        if p in fo:
            claimed.add(p)
            same = norm(fo[p]) == nv
            if same and type_name(v) == type_name(fo[p]):
                kind = "unchanged"
            elif same:
                kind = "retyped"
            else:
                kind = "changed"
            rows.append({"kind": kind, "path": p, "from": v, "to": fo[p], "out": [p]})
            continue
        if nv in (None, "", "{}", "[]"):
            # An empty input field is often carried along (typically under unmapped).
            twins = [q for q, w in fo.items() if norm(w) in (None, "", "{}", "[]")
                     and (q == "unmapped." + p or q.split(".")[-1] == p.split(".")[-1])]
            if twins:
                claimed.update(twins)
                rows.append({"kind": "unmapped" if all(q.startswith("unmapped") for q in twins) else "moved",
                             "path": p, "from": v, "to": fo[twins[0]], "out": twins[:4], "retyped": False})
            else:
                rows.append({"kind": "empty", "path": p, "from": v})
            continue
        cands = by_val.get(nv, [])
        if cands:
            last = p.split(".")[-1]
            cands = sorted(cands, key=lambda q: (q.split(".")[-1] != last, q.startswith("unmapped"), q))
            claimed.update(cands)
            all_unmapped = all(q.startswith("unmapped") for q in cands)
            retyped = type_name(v) != type_name(fo[cands[0]])
            rows.append({"kind": "unmapped" if all_unmapped else "moved", "path": p, "from": v,
                         "to": fo[cands[0]], "out": cands[:4], "retyped": retyped})
        else:
            rows.append({"kind": "dropped", "path": p, "from": v})
    for q, w in fo.items():
        if q not in claimed:
            rows.append({"kind": "added", "path": q, "to": w})
    rows.sort(key=lambda r: (KIND_ORDER.index(r["kind"]), r["path"]))
    summary = {}
    for r in rows:
        summary[r["kind"]] = summary.get(r["kind"], 0) + 1
    return {"rows": rows, "summary": summary}


def ocsf_checks(out):
    f = flatten(out)

    def g(path):
        return f.get(path)

    def present(*paths):
        return all(g(x) not in (None, "") for x in paths)

    checks = []
    checks.append(("class_uid, category_uid and activity_id are set",
                   present("class_uid", "category_uid", "activity_id")))
    cu, au, tu = g("class_uid"), g("activity_id"), g("type_uid")
    ok_type = all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (cu, au, tu)) and tu == cu * 100 + au
    checks.append(("type_uid = class_uid x 100 + activity_id", bool(ok_type)))
    t = g("time")
    checks.append(("time is a number in epoch milliseconds",
                   isinstance(t, (int, float)) and not isinstance(t, bool) and 1e11 <= t < 1e14))
    checks.append(("metadata.version is set", present("metadata.version")))
    checks.append(("metadata.product.vendor_name and name are set",
                   present("metadata.product.vendor_name", "metadata.product.name")))
    checks.append(("dataSource.category, vendor and name are set (XDR search)",
                   present("dataSource.category", "dataSource.vendor", "dataSource.name")))
    checks.append(("dataSource vendor and name mirror metadata.product",
                   present("dataSource.vendor", "dataSource.name") and
                   g("dataSource.vendor") == g("metadata.product.vendor_name") and
                   g("dataSource.name") == g("metadata.product.name")))
    return checks


# ---------------------------------------------------------------------------
# Running things
# ---------------------------------------------------------------------------

def strip_tail(path, n=60):
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return []
    lines = [ANSI.sub("", l).rstrip() for l in text.splitlines() if l.strip()]
    return lines[-n:]


def read_tap(path, keep_events=0):
    events = nbytes = 0
    samples = []
    kept = []
    if not Path(path).exists():
        return 0, 0, samples, kept
    with open(path, "rb") as f:
        for line in f:
            if not line.strip():
                continue
            events += 1
            nbytes += len(line)
            if len(samples) < SAMPLE_LIMIT:
                samples.append(line.decode("utf-8", "replace").strip())
            if len(kept) < keep_events:
                try:
                    kept.append(json.loads(line))
                except ValueError:
                    pass
    return events, nbytes, samples, kept


def free_port():
    with socket.socket() as s:
        s.bind((LOCAL, 0))
        return s.getsockname()[1]


def load_file_input(src):
    path = str(src.get("path", "")).strip()
    if path:
        fp = Path(path).expanduser()
        if not fp.is_file():
            raise ApiError("File not found: %s" % path)
        if fp.stat().st_size > MAX_INPUT_BYTES:
            raise ApiError("File is larger than %d MB." % (MAX_INPUT_BYTES // 1024 // 1024))
        data = fp.read_bytes()
    else:
        data = str(src.get("text", "")).encode("utf-8")
    if not data.strip():
        raise ApiError("The file source has no input. Give it a path or paste some log lines.")
    if not data.endswith(b"\n"):
        data += b"\n"
    return data


def http_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def wait_for_port(port, proc, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection((LOCAL, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def check_serializer_loads(code, lua, run_dir):
    """Load the serializer in a throwaway run with no records. Returns an error string or None."""
    ser = Path(run_dir) / "serializer.lua"
    rec = Path(run_dir) / "records.lua"
    ser.write_text(code, encoding="utf-8")
    rec.write_text("return {}", encoding="utf-8")
    r = subprocess.run([lua, str(HERE / "lua_runner.lua"), str(ser), str(rec)],
                       capture_output=True, text=True, timeout=60, env=clean_env(), cwd=str(run_dir))
    for line in r.stdout.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("fatal"):
            return tidy(obj["fatal"])
        if obj.get("loaded"):
            return None
    return tidy((r.stderr or "The Lua interpreter produced no output.").strip()[:1500])


def validate_pipeline(p):
    run_dir = Path(tempfile.mkdtemp(prefix="pipelab_"))
    try:
        cfg, _stages, meta = build_config(p, run_dir, http_port=free_port())
        parts = []
        ok = True
        if cfg is not None:
            vec = find_vector()
            if not vec:
                raise ApiError("Vector is not installed yet.", 409)
            (run_dir / "data").mkdir()
            cfg_path = run_dir / "vector.json"
            cfg_path.write_text(json.dumps(cfg, indent=2))
            r = subprocess.run([vec, "validate", str(cfg_path)], capture_output=True,
                               text=True, timeout=60, env=clean_env())
            ok = r.returncode == 0
            parts.append(ANSI.sub("", (r.stdout or "") + (r.stderr or "")).strip())
        else:
            parts.append("No Vector steps: the raw record goes straight to the serializer.")
        if meta["post"]:
            vec = find_vector()
            if not vec:
                raise ApiError("Vector is not installed yet.", 409)
            pcfg, _ps = build_post_config(meta["post"], run_dir, len(p.get("transforms") or []) - len(meta["post"]))
            (run_dir / "data_post").mkdir(exist_ok=True)
            pp = run_dir / "vector_post.json"
            pp.write_text(json.dumps(pcfg, indent=2))
            r2 = subprocess.run([vec, "validate", str(pp)], capture_output=True, text=True, timeout=60, env=clean_env())
            if r2.returncode != 0:
                ok = False
            parts.append("Steps after the serializer: " + ANSI.sub("", (r2.stdout or "") + (r2.stderr or "")).strip())
        if meta["lua"]:
            code = load_serializer_code(meta["lua"])
            lua = find_lua()
            if not lua:
                raise ApiError("No Lua interpreter found. Install one with: brew install luajit", 409)
            err = check_serializer_loads(code, lua, run_dir)
            if err:
                ok = False
                parts.append("Lua serializer: " + err)
            else:
                parts.append("Lua serializer: loads and defines processEvent.")
            for f in lint_lua(code):
                parts.append("Lint (%s)%s: %s" % (f["rule"], (" lines " + ", ".join(map(str, f["lines"]))) if f["lines"] else "", f["detail"]))
        return {"ok": ok, "output": "\n".join(x for x in parts if x)}
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def stage_from_events(st, events):
    lines = [json.dumps(e) for e in events]
    return dict(st, events=len(lines), bytes=sum(len(l) + 1 for l in lines),
                samples=lines[:SAMPLE_LIMIT])


def execute_vector(vec, cfg, stages, meta, p, run_dir, port):
    """Run Vector for the source and Vector steps. Returns a result dict."""
    cfg_path = run_dir / "vector.json"
    cfg_path.write_text(json.dumps(cfg, indent=2))
    (run_dir / "data").mkdir(exist_ok=True)

    input_bytes = None
    http_body = None
    if meta["mode"] == "stdin":
        input_bytes = load_file_input(p["source"])
    elif meta["mode"] == "stdin_json":
        recs = meta.get("json_records") or parse_records(p["source"].get("text", ""))
        input_bytes = ("\n".join(json.dumps(r) for r in recs) + "\n").encode("utf-8")
    elif meta["mode"] == "http":
        http_body = str(p["source"].get("body", ""))
        if not http_body.strip():
            raise ApiError("The HTTP source has no body to send. Paste some events.")
        if not http_body.endswith("\n"):
            http_body += "\n"
        if len(http_body.encode()) > MAX_INPUT_BYTES:
            raise ApiError("HTTP body is larger than %d MB." % (MAX_INPUT_BYTES // 1024 // 1024))

    if meta["saved_path"] and not meta["lua"]:
        OUT_DIR.mkdir(exist_ok=True)
        try:
            Path(meta["saved_path"]).unlink()
        except FileNotFoundError:
            pass

    v = subprocess.run([vec, "validate", str(cfg_path)], capture_output=True,
                       text=True, timeout=60, env=clean_env())
    if v.returncode != 0:
        msg = ANSI.sub("", (v.stdout or "") + (v.stderr or "")).strip()
        return {"ok": False, "stage": "validate", "error": msg or "Vector rejected the config."}

    out_f = open(run_dir / "stdout.log", "wb")
    err_f = open(run_dir / "stderr.log", "wb")
    started = time.time()
    proc = subprocess.Popen(
        [vec, "--config", str(cfg_path)],
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=out_f, stderr=err_f, env=clean_env())

    feed_done_at = started
    grace = 10.0
    if meta["mode"] == "generator":
        grace = 15.0 + meta.get("count", 0) / 20000.0
    elif input_bytes is not None:
        def feed():
            try:
                proc.stdin.write(input_bytes)
            except (BrokenPipeError, OSError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
        threading.Thread(target=feed, daemon=True).start()
        grace = 15.0 + len(input_bytes) / 1_000_000.0 * 4
    elif meta["mode"] == "http":
        if not wait_for_port(port, proc):
            proc.terminate()
            proc.wait(timeout=20)
            out_f.close()
            err_f.close()
            return {"ok": False, "stage": "start",
                    "error": "Vector did not start listening on the HTTP port.",
                    "log": strip_tail(run_dir / "stderr.log")}
        ctype = "application/json" if meta["http_format"] != "text" else "text/plain"
        req = urllib.request.Request("http://127.0.0.1:%d/" % port, data=http_body.encode(),
                                     method="POST", headers={"Content-Type": ctype})
        try:
            http_opener().open(req, timeout=30).read()
        except Exception as exc:  # noqa: BLE001
            proc.terminate()
            proc.wait(timeout=20)
            out_f.close()
            err_f.close()
            return {"ok": False, "stage": "send",
                    "error": "Vector refused the HTTP request: %s" % exc,
                    "log": strip_tail(run_dir / "stderr.log")}
        feed_done_at = time.time()
        grace = 3.0 + len(http_body) / 1_000_000.0 * 2

    timed_out = False
    stopped_early = False
    while True:
        if proc.poll() is not None:
            break
        now = time.time()
        if now - started > MAX_RUN_SECONDS:
            timed_out = True
            break
        if now - feed_done_at >= grace:
            stopped_early = True  # listeners never exit on their own
            break
        time.sleep(0.2)

    if proc.poll() is None:
        proc.terminate()  # graceful: lets the file sinks flush
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    out_f.close()
    err_f.close()
    duration = time.time() - started

    results = []
    last_events = []
    for idx, st in enumerate(stages):
        is_last = idx == len(stages) - 1
        ev, nb, samples, kept = read_tap(run_dir / ("tap_%s.ndjson" % st["id"]),
                                         SER_EVENT_LIMIT if (is_last and meta["lua"]) else 0)
        if is_last:
            last_events = kept
        results.append(dict(st, events=ev, bytes=nb, samples=samples))

    printed = None
    if meta["sink"] == "console" and not meta["lua"]:
        lines = [l for l in (run_dir / "stdout.log").read_text(errors="replace").splitlines() if l.strip()]
        printed = {"events": len(lines), "lines": lines[:PRINT_LIMIT]}

    saved = None
    if meta["saved_path"] and not meta["lua"] and Path(meta["saved_path"]).exists():
        sp = Path(meta["saved_path"])
        saved = {"path": str(sp), "bytes": sp.stat().st_size}

    log = strip_tail(run_dir / "stderr.log", 80)
    problems = [l for l in log if re.search(r"\b(ERROR|WARN)\b", l)]
    ok = (proc.returncode in (0, -15, 143, -9)) or stopped_early
    return {
        "ok": ok, "stage": "run", "duration": round(duration, 2),
        "exit_code": proc.returncode, "timed_out": timed_out, "stopped_early": stopped_early,
        "vector_version": vector_version(vec), "stages": results,
        "printed": printed, "saved": saved, "log": log, "problems": problems[:30],
        "error": None if ok else "Vector exited with code %s. See the Vector log tab." % proc.returncode,
        "last_events": last_events,
    }


def tidy(msg):
    """Hide the temporary run folder in Lua error messages."""
    return re.sub(r"[^\s:'\"]*serializer\.lua", "serializer.lua", str(msg))


def run_serializer(code, events, lua, run_dir):
    truncated = len(events) > SER_EVENT_LIMIT
    events = events[:SER_EVENT_LIMIT]
    ser = run_dir / "serializer.lua"
    rec = run_dir / "records.lua"
    ser.write_text(code, encoding="utf-8")
    rec.write_text("return " + to_lua(events), encoding="utf-8")
    try:
        r = subprocess.run([lua, str(HERE / "lua_runner.lua"), str(ser), str(rec)],
                           capture_output=True, text=True, timeout=120, env=clean_env(), cwd=str(run_dir))
    except subprocess.TimeoutExpired:
        return {"ok": False, "fatal": "The serializer took longer than 120 seconds and was stopped."}

    by_i = {}
    noise = []
    for line in r.stdout.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            if line.strip():
                noise.append(line)
            continue
        if obj.get("fatal"):
            return {"ok": False, "fatal": tidy(obj["fatal"]), "lint": lint_lua(code)}
        if "i" in obj:
            by_i[obj["i"]] = obj
    if not by_i and events:
        return {"ok": False, "fatal": tidy((r.stderr or "The Lua interpreter produced no results.").strip()[:1500]),
                "lint": lint_lua(code)}

    records = []
    outputs = []
    check_acc = {}
    errors = dropped = 0
    for idx, ev in enumerate(events):
        o = by_i.get(idx + 1)
        entry = {"index": idx + 1, "input": ev if idx < SER_DIFF_RECORDS else None}
        if o is None:
            entry.update(ok=False, error="No result came back for this record.")
            errors += 1
        elif o.get("error"):
            entry.update(ok=False, error=tidy(o["error"]), logs=o.get("logs") or [])
            errors += 1
        elif o.get("dropped"):
            entry.update(ok=True, dropped=True, logs=o.get("logs") or [])
            dropped += 1
        else:
            out = o.get("out") or {}
            outputs.append(out)
            entry.update(ok=True, logs=o.get("logs") or [])
            if idx < SER_DIFF_RECORDS:
                entry["output"] = out
                entry["diff"] = diff_record(ev, out)
            for name, passed in ocsf_checks(out):
                c = check_acc.setdefault(name, {"name": name, "passed": 0, "failed": 0, "first_fail": None})
                if passed:
                    c["passed"] += 1
                else:
                    c["failed"] += 1
                    if c["first_fail"] is None:
                        c["first_fail"] = idx + 1
        records.append(entry)
    checks = list(check_acc.values())
    return {
        "ok": True, "fatal": None, "total": len(events), "errors": errors, "dropped": dropped,
        "truncated": truncated, "checks": checks, "records": records[:SER_DIFF_RECORDS + 200],
        "lint": lint_lua(code), "stdout": noise[:20], "stderr": (r.stderr or "").strip()[:800],
        "outputs": outputs,
    }


def find_busted():
    return _first_executable([os.environ.get("BUSTED_BIN"), shutil.which("busted"),
                              str(Path.home() / ".luarocks" / "bin" / "busted"),
                              "/opt/homebrew/bin/busted", "/usr/local/bin/busted"])


def run_busted(p):
    """Run spec_live/generic_spec.lua (Busted) against the pipeline's serializer and raw records."""
    busted = find_busted()
    if not busted:
        raise ApiError("Busted is not installed. In Docker it is built in (rebuild with docker compose up -d --build). "
                       "On your Mac: brew install luajit luarocks, then luarocks --lua-version 5.1 "
                       "--lua-dir=\"$(brew --prefix luajit)\" --local install busted", 409)
    step = None
    for t in (p.get("transforms") or []):
        if t.get("type") == "lua":
            step = t
    if not step:
        raise ApiError("Add a Lua serializer step first.")
    src = p.get("source") or {}
    if src.get("type") != "record":
        raise ApiError("Busted checks run against the Raw record(s) source. Set the Source to Raw record(s).")
    recs = parse_records(src.get("text", ""))[:SER_EVENT_LIMIT]
    code = load_serializer_code(step)
    run_dir = Path(tempfile.mkdtemp(prefix="pipelab_busted_"))
    try:
        ser = run_dir / "serializer.lua"
        rec = run_dir / "records.lua"
        ser.write_text(code, encoding="utf-8")
        rec.write_text("return " + to_lua(recs), encoding="utf-8")
        env = clean_env()
        env["SERIALIZER_PATH"] = str(ser)
        env["SAMPLE_PATH"] = str(rec)
        try:
            r = subprocess.run([busted, "--output=TAP", str(HERE / "spec_live" / "generic_spec.lua")],
                               capture_output=True, text=True, timeout=120, env=env, cwd=str(run_dir))
        except subprocess.TimeoutExpired:
            raise ApiError("Busted took longer than 120 seconds and was stopped.")
        raw = tidy(ANSI.sub("", (r.stdout or "") + (r.stderr or "")))
        tests, cur = [], None
        for line in raw.splitlines():
            m = re.match(r"^(not ok|ok)\s+\d+\s*-?\s*(.*)$", line)
            if m:
                nm = m.group(2)
                skip = "# SKIP" in nm
                if skip:
                    before, _sep, after = nm.partition("# SKIP")
                    nm = (before.strip(" -") or after.strip(" -")) or "skipped check"
                cur = {"ok": m.group(1) == "ok", "name": nm, "detail": "", "skipped": skip}
                tests.append(cur)
            elif cur is not None and line.startswith("#") and not cur["ok"]:
                cur["detail"] += line.lstrip("# ").rstrip() + "\n"
        for t in tests:
            nm = re.sub(r"^record \d+\s+", "", t["name"])
            fx = BUSTED_FIXES.get(nm)
            if fx and not t["ok"] and not t["skipped"] and not (fx[0] == "time_ms" and "seconds" not in t["detail"]):
                t["fix"], t["fix_note"] = fx
        skipped = sum(1 for t in tests if t["skipped"])
        passed = sum(1 for t in tests if t["ok"] and not t["skipped"])
        failed = len(tests) - passed - skipped
        crashed = (not tests) and r.returncode != 0
        return {"ok": failed == 0 and not crashed and bool(tests), "passed": passed, "failed": failed, "skipped": skipped,
                "tests": tests, "records": len(recs), "raw": raw[:6000] if (crashed or failed) else ""}
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def run_pipeline(p):
    if not RUN_LOCK.acquire(blocking=False):
        raise ApiError("Another run is still in progress.", 409)
    run_dir = Path(tempfile.mkdtemp(prefix="pipelab_"))
    try:
        port = free_port()
        cfg, stages, meta = build_config(p, run_dir, http_port=port)

        code = lua = None
        if meta["lua"]:
            code = load_serializer_code(meta["lua"])
            lua = find_lua()
            if not lua:
                raise ApiError("No Lua interpreter found. Install one with: brew install luajit", 409)

        if cfg is None:  # raw records straight into the serializer
            recs = parse_records(p["source"].get("text", ""))
            res = {"ok": True, "stage": "run", "duration": 0.0, "exit_code": None, "timed_out": False,
                   "stopped_early": False, "vector_version": None,
                   "stages": [stage_from_events(stages[0], recs)], "printed": None, "saved": None,
                   "log": [], "problems": [], "error": None, "last_events": recs}
        else:
            vec = find_vector()
            if not vec:
                raise ApiError("Vector is not installed yet.", 409)
            res = execute_vector(vec, cfg, stages, meta, p, run_dir, port)
            if not res.get("ok"):
                res.pop("last_events", None)
                return res

        events = res.pop("last_events", [])
        if meta["lua"]:
            started = time.time()
            ser = run_serializer(code, events, lua, run_dir)
            ser["duration"] = round(time.time() - started, 2)
            if not ser.get("ok"):
                return {"ok": False, "stage": "serializer", "error": ser.get("fatal") or "Serializer failed.",
                        "lint": ser.get("lint", []), "log": res.get("log", [])}
            outputs = ser.pop("outputs")
            res["coverage"] = detection_coverage(outputs, events)
            lines = [json.dumps(o) for o in outputs]
            res["stages"].append({"id": "serializer", "label": "lua serializer", "kind": "transform",
                                  "events": len(lines), "bytes": sum(len(l) + 1 for l in lines),
                                  "samples": lines[:SAMPLE_LIMIT]})
            if meta["post"]:
                vec2 = find_vector()
                if not vec2:
                    raise ApiError("Vector is not installed yet (needed for steps after the serializer).", 409)
                pr = run_post(vec2, meta["post"], outputs, run_dir, len(res["stages"]) - 1)
                if not pr.get("ok"):
                    return {"ok": False, "stage": "after-serializer", "error": pr.get("error"), "log": res.get("log", [])}
                res["stages"].extend(pr["stages"])
                res["log"] = (res.get("log") or []) + pr.get("log", [])
                outputs = pr["outputs"]
                lines = [json.dumps(o) for o in outputs]
            if meta["sink"] == "console":
                res["printed"] = {"events": len(lines), "lines": lines[:PRINT_LIMIT]}
            elif meta["sink"] == "file":
                OUT_DIR.mkdir(exist_ok=True)
                sp = Path(meta["saved_path"])
                sp.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
                res["saved"] = {"path": str(sp), "bytes": sp.stat().st_size}
            res["serializer"] = ser
        return res
    finally:
        RUN_LOCK.release()
        shutil.rmtree(run_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Saved pipelines
# ---------------------------------------------------------------------------

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.,()&+-]{0,59}$")


def pipeline_path(name):
    if not NAME_RE.match(name or ""):
        raise ApiError("Pipeline names can use letters, numbers, spaces and . , _ - ( ) & + (max 60). Slashes and other symbols are not allowed because the name becomes a file name.")
    return PIPE_DIR / (name + ".json")


# ---------------------------------------------------------------------------
# Settings and detection coverage (off by default)
# ---------------------------------------------------------------------------

SETTINGS_DEFAULTS = {"detection_coverage": False, "busted_button": True, "gap_generation": False, "collector_testing": False}
MAX_DETECTION_BYTES = 100 * 1024 * 1024
_DET_CACHE = {}


def settings_path():
    return PIPE_DIR / ".trickle-settings.json"


def load_settings():
    cfg = dict(SETTINGS_DEFAULTS)
    try:
        saved = json.loads(settings_path().read_text())
        for k in SETTINGS_DEFAULTS:
            if isinstance(saved.get(k), bool):
                cfg[k] = saved[k]
    except (OSError, ValueError):
        pass
    return cfg


def save_settings(body):
    cfg = load_settings()
    for k in SETTINGS_DEFAULTS:
        if k in body:
            if not isinstance(body[k], bool):
                raise ApiError("Setting %s must be true or false." % k)
            cfg[k] = body[k]
    PIPE_DIR.mkdir(exist_ok=True)
    settings_path().write_text(json.dumps(cfg, indent=2))
    return cfg


def find_detections_file():
    """The detection export lives at a fixed location chosen by the operator, never taken from a request."""
    cands = [os.environ.get("DETECTIONS_FILE"),
             "/data/detections/extracted.json" if IN_DOCKER else None,
             str(HERE / "data" / "detections" / "extracted.json")]
    for c in cands:
        if c:
            p = Path(c).expanduser()
            if p.is_file():
                return p
    return None


def _vstr(v):
    """Rule values as text. Numbers count (winEventLog.id = 4662); booleans and nulls do not."""
    if isinstance(v, str):
        return v
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v)
    return None


def load_detection_index(path):
    """dataSource.name (lowercase) -> {name, rules{id: name}, fields{field: {id: name}}}. Cached by mtime."""
    st = path.stat()
    key = (str(path), st.st_mtime, st.st_size)
    if key in _DET_CACHE:
        return _DET_CACHE[key]
    if st.st_size > MAX_DETECTION_BYTES:
        raise ApiError("The detection file is larger than %d MB." % (MAX_DETECTION_BYTES // 1024 // 1024))
    data = json.loads(path.read_text(encoding="utf-8"))
    idx = {}
    for r in data.get("results", []):
        rid = r.get("id") or r.get("name") or "?"
        rname = r.get("name") or rid
        for q in r.get("queries", []):
            qtext = q.get("query") or ""
            def _valid_key(k, _t=qtext):
                """The export's pair_list contains fragments and rule-computed names; keep only real event fields."""
                if not k or k.startswith("_"):
                    return False
                if not _t:
                    return True
                m = re.search(r"(?<![\w.])" + re.escape(k) + r"(?![\w.])", _t)
                if not m:
                    return False
                return "." in k or re.search(r"(?<![\w.])" + re.escape(k) + r"(?![\w.])", _t.split("\n|")[0]) is not None
            def _negated(k, _t=qtext):
                """Inside not (...) or !=: an exclusion, so the rule does not need that field to exist."""
                return bool(_t and (re.search(r"\bnot\s*\([^)]*" + re.escape(k), _t) or re.search(re.escape(k) + r"\s*!=", _t)))
            pl = [p for p in q.get("pair_list", []) if p.get("key") == "dataSource.name" or (_valid_key(p.get("key")) and not _negated(p.get("key")))]
            names = {p.get("value") for p in pl if p.get("key") == "dataSource.name" and p.get("op") == "="
                     and isinstance(p.get("value"), str)}
            for n in names:
                if n.strip().lower() == "sentinelone":      # does not go through this pipeline
                    continue
                ent = idx.setdefault(n.lower(), {"name": n, "rules": {}, "fields": {}})
                ent["rules"][rid] = rname
                ent.setdefault("queries", []).append((rid, rname, tuple(
                    (p.get("key"), p.get("op"), tuple(x for x in (_vstr(v) for v in (p.get("value") if isinstance(p.get("value"), list) else [p.get("value")]))
                                                      if x and x != ":anycase"))
                    for p in pl if p.get("key") and p.get("key") != "dataSource.name")))
                for p in pl:
                    k = p.get("key")
                    if k and k != "dataSource.name":
                        ent["fields"].setdefault(k, {})[rid] = rname
                        vs = p.get("value")
                        for v in (vs if isinstance(vs, list) else [vs]):
                            v = _vstr(v)
                            if v and v != ":anycase" and p.get("op"):
                                ent.setdefault("values", {}).setdefault(k, {}).setdefault(p["op"], set()).add(v)
    _DET_CACHE.clear()
    _DET_CACHE[key] = idx
    return idx


def _tokens(s):
    return set(re.findall(r"[a-z0-9]+", s.lower()))


def near_sources(name, idx, limit=3):
    import difflib
    tn, out = _tokens(name), []
    for ent in idx.values():
        tc = _tokens(ent["name"])
        shared = tn & tc
        jac = len(shared) / max(1, len(tn | tc))
        ratio = difflib.SequenceMatcher(None, name.lower(), ent["name"].lower()).ratio()
        score = max(ratio, jac) + 0.3 * len(shared)
        has_word = any(len(t) >= 3 for t in shared)      # a shared word, or a very close spelling
        if (has_word and score >= 0.45) or ratio >= 0.8:
            out.append((score, ent))
    out.sort(key=lambda x: -x[0])
    return [{"name": e["name"], "rules": len(e["rules"]), "fields": len(e["fields"])} for _s, e in out[:limit]]


def _present_paths(obj, prefix="", acc=None):
    acc = set() if acc is None else acc
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = prefix + str(k)
            if v in (None, "", [], {}):
                continue
            acc.add(path)
            if isinstance(v, dict):
                _present_paths(v, path + ".", acc)
    return acc



def _leaves(obj, prefix="", acc=None):
    acc = {} if acc is None else acc
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = prefix + str(k)
            if isinstance(v, dict):
                _leaves(v, p + ".", acc)
            elif isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v) != "":
                acc.setdefault(p, []).append(str(v))
    return acc


def expected_values(field, ent, cap=200):
    """What the rules compare this field against: [{op, values, more}]. Display only."""
    out = []
    for op, vals in ((ent.get("values") or {}).get(field) or {}).items():
        vs = sorted(vals, key=str.lower)
        out.append({"op": op, "values": vs[:cap], "more": max(0, len(vs) - cap)})
    out.sort(key=lambda x: (x["op"] not in ("=", "in"), x["op"]))
    return out


def label_in(c, inputs, outputs):
    return c["where"] == "input"


def recommend_sources(field, ent, inputs, outputs):
    """Suggest which source field could feed a missing detection field. Never changes anything."""
    ops = (ent.get("values") or {}).get(field) or {}
    exact = {v.lower() for op in ("=", "in") for v in ops.get(op, ())}
    contains = [v.lower() for v in ops.get("contains", ()) if len(v) >= 3]
    rx = []
    for pat in sorted(ops.get("matches", ()))[:40]:
        if len(pat) <= 200:
            try:
                rx.append((pat, re.compile(pat, re.I)))
            except re.error:
                pass
    orig = {v.lower(): v for vs in ops.values() for v in vs}
    last = _norm(field.split(".")[-1])
    cands = {}
    for label, recs in (("input", inputs), ("output", outputs)):
        for r in recs or []:
            for path, vals in _leaves(r if label == "input" else (r.get("unmapped") or {}), "" if label == "input" else "unmapped.").items():
                for v in vals:
                    lv = v.lower()
                    why_hit = ([lv] if lv in exact else []) + [c for c in contains if c in lv]
                    if len(v) <= 300:
                        why_hit += [pat for pat, rc in rx if rc.search(v)]
                    hit = bool(why_hit)
                    name_hit = _norm(path.split(".")[-1]) == last
                    if hit or name_hit:
                        c = cands.setdefault(path, {"source": path, "example": v[:60], "value_match": 0, "name_match": name_hit,
                                                    "records": 0, "where": label, "matched": []})
                        for w in why_hit:
                            w = orig.get(w, w)
                            if w not in c["matched"]:
                                c["matched"].append(w)
                        if hit and v[:60] not in c.setdefault("examples", []) and len(c["examples"]) < 4:
                            c["examples"].append(v[:60])
                        c["value_match"] += 1 if hit else 0
                        c["records"] += 1
    for p in [p for p in cands if p.startswith("unmapped.") and p[len("unmapped."):] in cands]:
        cands.pop(p)      # same value already offered under its raw name
    ranked = sorted(cands.values(), key=lambda c: (-c["value_match"], not c["name_match"], c["where"] != "input", c["source"]))
    out = []
    for c in ranked[:3]:
        if c["value_match"] and c["name_match"]:
            why = "same name, and its value is one the rules look for"
        elif c["value_match"]:
            why = "its value is one the rules look for"
        else:
            why = "same name as the detection field"
        item = {"source": c["source"], "example": c["example"], "why": why, "where": c["where"],
                "fixable": bool(c["value_match"]), "matched": c["matched"][:3], "examples": c.get("examples", [])[:4],
                "seen": c["records"], "total": len(inputs if label_in(c, inputs, outputs) else outputs or []) or 1,
                "name_match": c["name_match"],
                "fix_source": c["source"][len("unmapped."):] if c["source"].startswith("unmapped.") else c["source"]}
        if c["where"] == "input":     # is the value already carried somewhere in the output?
            for o in outputs or []:
                um = (o.get("unmapped") or {}) if isinstance(o, dict) else {}
                if c["source"] in um:
                    item["currently"] = "unmapped." + c["source"]
                    break
        out.append(item)
    return out


GROUP_KEYS = ("event.type", "metadata.log_name")


def _get_path(o, path):
    """Value at a dotted path. Accepts nested objects, literal dotted keys ("event.type": ...), and mixes of both."""
    if not isinstance(o, dict):
        return o if isinstance(o, (str, int, float)) and not isinstance(o, bool) else None
    if path in o:
        return _get_path(o[path], "") if isinstance(o[path], dict) else (o[path] if isinstance(o[path], (str, int, float)) and not isinstance(o[path], bool) else None)
    parts = path.split(".")
    for i in range(1, len(parts)):
        head = ".".join(parts[:i])
        if head in o and isinstance(o[head], dict):
            v = _get_path(o[head], ".".join(parts[i:]))
            if v is not None:
                return v
    return None


def _cond_ok(value, op, vals):
    if value is None:
        return False
    v = str(value).lower()
    if op in ("=", "in"):
        return v in {x.lower() for x in vals}
    if op == "contains":
        return any(x.lower() in v for x in vals)
    if op == "matches":
        for pat in vals[:20]:
            try:
                if len(pat) <= 200 and re.search(pat, str(value), re.I):
                    return True
            except re.error:
                pass
        return False
    return True      # operators we do not judge never exclude a rule


def group_coverage(hit, recs):
    """Per (event.type, metadata.log_name) group: which rules can match it and which of those have every field they need."""
    groups = {}
    for o in recs:
        key = tuple(_get_path(o, k) for k in GROUP_KEYS)
        groups.setdefault(key, []).append(o)
    out = []
    for key, grecs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        paths = [_present_paths(o) for o in grecs]
        rules = {}        # rid -> {name, need:set}
        for rid, rname, pairs in hit.get("queries", []):
            applies = True
            for k, op, vals in pairs:
                if k in GROUP_KEYS and not _cond_ok(key[GROUP_KEYS.index(k)], op, vals):
                    applies = False
                    break
            if applies:
                r = rules.setdefault(rid, {"name": rname, "need": set()})
                r["need"].update(k for k, _op, _v in pairs)
        pres = lambda f: any(f in p for p in paths)
        field_rules = {}
        rule_rows = []
        for rid, r in rules.items():
            miss = sorted(f for f in r["need"] if not pres(f))
            rule_rows.append({"name": r["name"], "ready": not miss, "missing": miss})
            for f in miss:
                field_rules.setdefault(f, set()).add(r["name"])
        fields = [{"field": f, "rules": len(rn), "rule_names": sorted(rn)[:5],
                   "expects": expected_values(f, hit, 40)} for f, rn in field_rules.items()]
        fields.sort(key=lambda x: (-x["rules"], x["field"]))
        rule_rows.sort(key=lambda x: (x["ready"], x["name"]))
        out.append({"event_type": key[0], "log_name": key[1], "records": len(grecs), "applicable": len(rules),
                    "ready": sum(1 for x in rule_rows if x["ready"]), "missing_fields": fields, "rules": rule_rows[:200]})
    return out


def _fmt_vals(vals, n=3):
    vs = [str(v) for v in vals[:n]]
    return ", ".join(vs) + (" ..." if len(vals) > n else "")


def classify_gaps(hit, recs, paths):
    """Which absent fields are a real gap and which are expected for the events in this run.
    A rule applies to a record when every field it filters on that the record has satisfies the rule,
    and at least one does. A field the rule needs but the record lacks is then a gap. A rule an event
    does not satisfy is why its fields are merely expected."""
    ready = set()
    gaps = {}         # field -> {"rules": {name}, "records": set(idx), "because": str}
    skipped = {}      # field -> {"rules": {name}, "needs": str}
    applicable = set()
    for i, (o, ps) in enumerate(zip(recs[:500], paths)):
        for rid, rname, pairs in hit.get("queries", []):
            present = [(k, op, vals) for k, op, vals in pairs if k in ps]
            fail = None
            passed = 0
            for k, op, vals in present:
                v = _get_path(o, k)
                if v is None or not vals:
                    continue
                if _cond_ok(v, op, vals):
                    passed += 1
                else:
                    fail = (k, op, vals, v)
                    break
            missing = [k for k, _op, _v in pairs if k not in ps]
            if fail:
                for k in missing:
                    d = skipped.setdefault(k, {"rules": set(), "needs": ""})
                    d["rules"].add(rname)
                    if not d["needs"]:
                        d["needs"] = "%s %s %s (this run has %s)" % (fail[0], OP_WORDS.get(fail[1], fail[1]), _fmt_vals(fail[2]), str(fail[3])[:40])
            elif passed:
                applicable.add(rid)
                if not missing:
                    ready.add(rname)
                for k in missing:
                    g = gaps.setdefault(k, {"rules": set(), "records": set(), "because": ""})
                    g["rules"].add(rname)
                    g["records"].add(i)
                    if not g["because"]:
                        g["because"] = ", ".join("%s %s %s" % (pk, OP_WORDS.get(pop, pop), _fmt_vals(pv)) for pk, pop, pv in present[:2] if pv)
    return gaps, skipped, len(applicable), sorted(ready)


OP_WORDS = {"=": "=", "in": "is one of", "contains": "contains", "matches": "matches"}


def detection_coverage(outputs, inputs=None):
    """None when the feature is off, the file is missing, or nothing matches. Otherwise a report per dataSource.name."""
    if not load_settings().get("detection_coverage"):
        return None
    path = find_detections_file()
    if not path or not outputs:
        return None
    idx = load_detection_index(path)
    by_name = {}
    for o in outputs:
        ds = o.get("dataSource") if isinstance(o, dict) else None
        n = ds.get("name") if isinstance(ds, dict) else None
        if not n and isinstance(o, dict):
            n = o.get("dataSource.name")
        if isinstance(n, str) and n.strip() and n.strip().lower() != "sentinelone":
            by_name.setdefault(n, []).append(o)
    sources = []
    for name, recs in by_name.items():
        hit = idx.get(name.lower())
        if hit is None:
            sug = near_sources(name, idx)
            if sug:   # no match and nothing close: stay silent
                sources.append({"state": "near", "name": name, "records": len(recs), "suggestions": sug})
            continue
        paths = [_present_paths(o) for o in recs]
        gaps, skipped, n_applicable, ready = classify_gaps(hit, recs, paths)
        fields = []
        for fname, rules in hit["fields"].items():
            present = sum(1 for p in paths if fname in p)
            gap = gaps.get(fname)
            if gap:
                status = "missing"
            elif present:
                status = "present"
            else:
                status = "expected"
            f = {"field": fname, "rules": len(rules), "present": present, "total": len(recs), "status": status,
                 "rule_names": sorted(set(rules.values()))[:5], "expects": expected_values(fname, hit)}
            if gap:
                f["gap_rules"] = sorted(gap["rules"])[:5]
                f["gap_records"] = len(gap["records"])
                f["because"] = gap["because"]
                f["suggestions"] = recommend_sources(fname, hit, inputs, recs)
            elif status == "expected":
                sk = skipped.get(fname) or {}
                f["needs"] = sk.get("needs", "")
                f["suggestions"] = recommend_sources(fname, hit, inputs, recs)
            fields.append(f)
        order = {"missing": 0, "expected": 1, "present": 2}
        fields.sort(key=lambda f: (order[f["status"]], -f["rules"], f["field"]))
        missing = [f for f in fields if f["status"] == "missing"]
        sources.append({"state": "match", "name": hit["name"], "records": len(recs), "rules": len(hit["rules"]),
                        "applicable_rules": n_applicable, "ready_rules": ready[:50], "ready_count": len(ready), "expected": sum(1 for f in fields if f["status"] == "expected"),
                        "fields": fields, "missing": len(missing), "failed": bool(missing),
                        "groups": group_coverage(hit, recs)})
    return {"sources": sources} if sources else None


GAP_SKIP = {"dataSource.name", "dataSource.vendor", "dataSource.category"}


def gap_maps(recs, name, maps, used_targets, keys):
    """Detection-aware Generate: add mappings for fields the product's detections look for, when a source field in
    the sample carries a value those rules compare against. Off unless the setting is on. Returns a summary or None."""
    if not load_settings().get("gap_generation"):
        return None
    path = find_detections_file()
    if not path:
        return {"state": "nofile"}
    hit = load_detection_index(path).get((name or "").lower())
    if not hit:
        return {"state": "nomatch", "name": name}
    added, unresolved = [], []
    fields = sorted(hit["fields"].items(), key=lambda kv: (-len(kv[1]), kv[0]))[:80]
    keyset = set(keys)
    for field, rules in fields:
        if field in used_targets or field in GAP_SKIP:
            continue
        pick = next((x for x in recommend_sources(field, hit, recs, [])
                     if x["fixable"] and x["where"] == "input" and x["source"] in keyset), None)
        if pick:
            vals = [v for ev in expected_values(field, hit, cap=50) for v in ev["values"]]
            numeric = bool(vals) and all(re.match(r"^-?\d+$", v) for v in vals)
            maps.append((pick["source"], field, "n" if numeric else "s"))
            used_targets.add(field)
            added.append({"field": field, "source": pick["source"], "matched": pick["matched"][:3], "rules": len(rules)})
        else:
            unresolved.append(field)
    return {"state": "ok", "name": hit["name"], "rules": len(hit["rules"]), "added": added, "unresolved": unresolved[:40],
            "unresolved_count": len(unresolved)}


FIX_FIELD_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-\[\]]{0,119}$")


def fix_lua(step, source, target):
    """Add a mapping source -> target to a Lua serializer. Returns the patched code. Needs the standard shape
    (local r = {}, local e = ..., setNestedField, a final 'return r'), which generated and Cato serializers have."""
    if not (FIX_FIELD_RE.match(source or "") and FIX_FIELD_RE.match(target or "")):
        raise ApiError("Field names may only use letters, numbers, dots, dashes and underscores.")
    return _apply_fix(load_serializer_code(step), source, target)


# Busted checks that have a safe, mechanical Lua fix. Check name -> (fix id, what the fix adds).
BUSTED_FIXES = {
    "type_uid equals class_uid * 100 + activity_id": ("type_uid", "Sets type_uid = class_uid * 100 + activity_id"),
    "time is a number in epoch milliseconds": ("time_ms", "Converts time to a number and multiplies seconds by 1000"),
    "severity_id is a number": ("severity_id", "Makes severity_id a number (0 when unknown)"),
    "metadata.version is set": ("metadata_version", "Sets metadata.version to 1.8.0"),
    "dataSource.* is set and mirrors metadata.product.*": ("datasource", "Copies metadata.product vendor and name into dataSource, category security"),
    "does not keep the original message (no raw_data)": ("raw_data", "Removes raw_data from the output"),
    "does not copy values already mapped into other fields into unmapped": ("dedupe_unmapped", "Drops unmapped values that already appear in a mapped field"),
}
_BUSTED_BODY = {
    "type_uid": ["if type(r.class_uid) == \"number\" and type(r.activity_id) == \"number\" then",
                 "    r.type_uid = r.class_uid * 100 + r.activity_id", "end"],
    "time_ms": ["if type(r.time) == \"string\" then r.time = tonumber(r.time) or r.time end",
                "if type(r.time) == \"number\" and r.time < 100000000000 then r.time = r.time * 1000 end"],
    "severity_id": ["if type(r.severity_id) ~= \"number\" then r.severity_id = tonumber(r.severity_id) or 0 end"],
    "metadata_version": ["if type(r.metadata) ~= \"table\" or r.metadata.version == nil then",
                         "    setNestedField(r, \"metadata.version\", \"1.8.0\")", "end"],
    "datasource": ["local p = r.metadata and r.metadata.product",
                   "if type(p) == \"table\" then",
                   "    if p.vendor_name then setNestedField(r, \"dataSource.vendor\", p.vendor_name) end",
                   "    if p.name then setNestedField(r, \"dataSource.name\", p.name) end",
                   "end",
                   "if r.dataSource == nil or r.dataSource.category == nil then setNestedField(r, \"dataSource.category\", \"security\") end"],
    "raw_data": ["r.raw_data = nil"],
    "dedupe_unmapped": ["local seen = {}",
                        "local function collect(t, top)",
                        "    for k, v in pairs(t) do",
                        "        if not (top and k == \"unmapped\") then",
                        "            if type(v) == \"table\" then collect(v, false)",
                        "            elseif type(v) == \"string\" and string.len(v) >= 4 then seen[v] = true end",
                        "        end",
                        "    end",
                        "end",
                        "collect(r, true)",
                        "local function prune(t)",
                        "    for k, v in pairs(t) do",
                        "        if type(v) == \"table\" then prune(v)",
                        "        elseif type(v) == \"string\" and string.len(v) >= 4 and seen[v] then t[k] = nil end",
                        "    end",
                        "end",
                        "if type(r.unmapped) == \"table\" then prune(r.unmapped) end"],
}


def _apply_busted(code, fid):
    if fid not in _BUSTED_BODY:
        raise ApiError("Unknown Busted fix.")
    for need, why in (("function processEvent", "no processEvent function"), ("setNestedField", "no setNestedField helper"),
                      ("local r = {}", "the result table is not called r")):
        if need not in code:
            raise ApiError("Cannot fix this Lua automatically (%s). Edit the Lua by hand." % why)
    marker = "-- trickle-fix: busted from %s" % fid
    if marker in code:
        raise ApiError("This fix is already in the Lua.")
    body = "".join("        " + ln + "\n" for ln in _BUSTED_BODY[fid])
    block = "    " + marker + "\n    do\n" + body + "    end\n"
    m = list(re.finditer(r"^([ \t]*)return r[ \t]*\r?\n[ \t]*end[ \t]*\r?\n?\s*$", code, re.M))
    if not m:
        raise ApiError("Cannot fix this Lua automatically (could not find the end of processEvent).")
    pos = m[-1].start()
    return code[:pos] + block + code[pos:]


def _apply_fix(code, source, target):
    if target == "busted":
        return _apply_busted(code, source)
    for need, why in (("function processEvent", "no processEvent function"), ("setNestedField", "no setNestedField helper"),
                      ("local r = {}", "the result table is not called r"), ("local e = ", "the input record is not called e")):
        if need not in code:
            raise ApiError("Cannot fix this Lua automatically (%s). Edit the Lua by hand." % why)
    marker = "-- trickle-fix: %s from %s" % (target, source)
    if marker in code:
        raise ApiError("This fix is already in the Lua (%s)." % target)
    if "." in source:
        if "function getPath" not in code:
            raise ApiError("Cannot fix this Lua automatically (the source is nested and the Lua has no getPath helper).")
        get = 'getPath(e, "%s")' % source
    else:
        get = 'e["%s"]' % source
    block = (
        "    " + marker + "\n"
        "    do\n"
        "        local fixv = " + get + "\n"
        "        if fixv ~= nil and fixv ~= \"\" then\n"
        "            setNestedField(r, \"" + target + "\", fixv)\n"
        + ("            if r.unmapped then r.unmapped[\"" + source + "\"] = nil end\n" if "." not in source else "")
        + "        end\n"
        "    end\n")
    m = list(re.finditer(r"^([ \t]*)return r[ \t]*\r?\n[ \t]*end[ \t]*\r?\n?\s*$", code, re.M))
    if not m:
        raise ApiError("Cannot fix this Lua automatically (could not find the end of processEvent).")
    pos = m[-1].start()
    return code[:pos] + block + code[pos:]


def collect_lua():
    """Every Lua serializer Trickle knows about: saved pipelines first, then .lua files in the data folder."""
    out, seen = [], set()
    PIPE_DIR.mkdir(exist_ok=True)
    for f in sorted(PIPE_DIR.glob("*.json")):
        if not NAME_RE.match(f.stem):
            continue
        try:
            p = json.loads(f.read_text())
        except ValueError:
            continue
        for t in p.get("transforms") or []:
            if isinstance(t, dict) and t.get("type") == "lua":
                try:
                    code = load_serializer_code(t)
                except ApiError:
                    continue
                out.append({"id": "pipeline:" + f.stem, "label": f.stem, "kind": "pipeline", "file": "pipelines/" + f.stem.replace("/", "_") + ".lua",
                            "code": code, "vendor": t.get("vendor", ""), "product": t.get("product", ""), "ocsf": t.get("ocsf", "")})
                break
    for d in ([Path("/data")] if IN_DOCKER else []) + [HERE / "data"]:
        if d.is_dir():
            for f in sorted(d.glob("*.lua")):
                if f.name in seen or f.stat().st_size > MAX_CODE_BYTES:
                    continue
                seen.add(f.name)
                out.append({"id": "file:" + f.name, "label": f.name, "kind": "file", "file": "data/" + f.name, "zip": False,
                            "code": f.read_text(encoding="utf-8", errors="replace"), "vendor": "", "product": "", "ocsf": ""})
    return out


def lua_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for e in collect_lua():
            if e.get("zip") is False:      # bundled examples are not your work
                continue
            z.writestr(e["file"], e["code"])
    return buf.getvalue()


def fix_many(step, fixes):
    """Apply several fixes in order. Returns (code, applied, skipped[{target, reason}])."""
    code = load_serializer_code(step)
    applied, skipped = [], []
    for f in fixes[:50]:
        src, tgt = str((f or {}).get("source", "")), str((f or {}).get("target", ""))
        try:
            if not (FIX_FIELD_RE.match(src) and FIX_FIELD_RE.match(tgt)):
                raise ApiError("Bad field name.")
            code = _apply_fix(code, src, tgt)
            applied.append({"source": src, "target": tgt})
        except ApiError as e:
            skipped.append({"target": tgt, "reason": str(e)})
    return code, applied, skipped


def unfix_lua(step, source, target):
    """Remove a block that Fix added. Works on the marker comment, so hand edits elsewhere are kept."""
    if not (FIX_FIELD_RE.match(source or "") and FIX_FIELD_RE.match(target or "")):
        raise ApiError("Field names may only use letters, numbers, dots, dashes and underscores.")
    code = load_serializer_code(step)
    marker = re.escape("-- trickle-fix: %s from %s" % (target, source))
    new, n = re.subn(r"^[ \t]*" + marker + r"[ \t]*\r?\n[ \t]*do[ \t]*\r?\n(?:.*\r?\n)*?    end[ \t]*\r?\n", "", code, count=1, flags=re.M)
    if not n:
        raise ApiError("That fix is not in the Lua (it may have been edited by hand).")
    return new


def list_pipelines():
    PIPE_DIR.mkdir(exist_ok=True)
    return [{"name": f.stem, "updated": int(f.stat().st_mtime)} for f in sorted(PIPE_DIR.glob("*.json"))
            if NAME_RE.match(f.stem)]


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "PipelineLab/2.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _allowed_host(self):
        host = (self.headers.get("Host") or "").lower()
        ok = {"127.0.0.1:%d" % PORT, "localhost:%d" % PORT} | set(EXTRA_HOSTS)
        if host not in ok:
            return False
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in {"http://" + h for h in ok}:
            return False
        return True

    def _send(self, status, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        for hk, hv in (extra or {}).items():
            self.send_header(hk, hv)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj))

    def _read_json(self):
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            raise ApiError("Content-Type must be application/json.", 415)
        n = int(self.headers.get("Content-Length") or 0)
        if n > 2 * MAX_INPUT_BYTES:
            raise ApiError("Request too large.", 413)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ApiError("Request body is not valid JSON.")

    def _dispatch(self, method):
        if not self._allowed_host():
            return self._json(403, {"error": "Forbidden host or origin."})
        path = self.path.split("?", 1)[0]
        try:
            if method == "GET" and path in ("/", "/index.html"):
                return self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            if method == "GET" and path == "/api/status":
                vec, lua = find_vector(), find_lua()
                return self._json(200, {
                    "vector": bool(vec), "version": vector_version(vec) if vec else None,
                    "lua": bool(lua), "lua_path": lua, "docker": IN_DOCKER, "busted": bool(find_busted()), "settings": load_settings(), "detections_file": bool(find_detections_file()),
                    "install": "brew trust vectordotdev/brew && brew tap vectordotdev/brew && brew install vector",
                    "install_lua": "brew install luajit"})
            if method == "GET" and path == "/api/lua":
                return self._json(200, collect_lua())
            if method == "GET" and path == "/api/lua.zip":
                return self._send(200, lua_zip(), "application/zip",
                                  {"Content-Disposition": 'attachment; filename="trickle-lua.zip"'})
            if method == "GET" and path == "/api/pipelines":
                return self._json(200, list_pipelines())
            m = re.match(r"^/api/pipelines/(.+)$", path)
            if m:
                name = unquote(m.group(1))
                f = pipeline_path(name)
                if method == "GET":
                    if not f.exists():
                        raise ApiError("No such pipeline.", 404)
                    return self._send(200, f.read_text())
                if method == "PUT":
                    body = self._read_json()
                    PIPE_DIR.mkdir(exist_ok=True)
                    body["name"] = name
                    f.write_text(json.dumps(body, indent=2))
                    return self._json(200, {"ok": True})
                if method == "DELETE":
                    if f.exists():
                        f.unlink()
                    return self._json(200, {"ok": True})
            if method == "POST" and path == "/api/config":
                cfg, _s, meta = build_config(norm_pipeline(self._read_json()), "<run-dir>", http_port=8686)
                note = None
                if cfg is None:
                    note = "No Vector config: with a raw record source and no Vector steps, the record goes straight to the Lua serializer."
                elif meta["lua"]:
                    note = "The Lua serializer is not part of this config. It runs after Vector, in lua_runner.lua, and the destination applies to its output." + (" Steps after the serializer run in a second Vector pass over the OCSF records." if meta["post"] else "")
                return self._json(200, {"config": cfg, "note": note})
            if method == "POST" and path == "/api/generate":
                b = self._read_json()
                if isinstance(b.get("types"), list):
                    return self._json(200, generate_multi(b["types"], b.get("vendor", ""), b.get("product", ""), b.get("version", "")))
                return self._json(200, generate_serializer(b.get("text", ""), b.get("vendor", ""), b.get("product", ""), b.get("version", ""), b.get("format") or "auto", b.get("pattern") or ""))
            if method == "POST" and path == "/api/collector":
                return self._json(200, run_collector(self._read_json()))
            if method == "POST" and path == "/api/detect":
                b = self._read_json()
                return self._json(200, detect_info(b.get("text", ""), b.get("format") or "auto", b.get("pattern") or ""))
            if method == "POST" and path == "/api/fixlua":
                b = self._read_json()
                before = load_serializer_code(b.get("step") or {})
                if isinstance(b.get("fixes"), list):
                    code, applied, skipped = fix_many(b.get("step") or {}, b["fixes"])
                    return self._json(200, {"code": code, "before": before, "applied": applied, "skipped": skipped})
                return self._json(200, {"code": fix_lua(b.get("step") or {}, str(b.get("source", "")), str(b.get("target", ""))), "before": before})
            if method == "POST" and path == "/api/unfixlua":
                b = self._read_json()
                before = load_serializer_code(b.get("step") or {})
                return self._json(200, {"code": unfix_lua(b.get("step") or {}, str(b.get("source", "")), str(b.get("target", ""))), "before": before})
            if method == "GET" and path == "/api/settings":
                return self._json(200, {"settings": load_settings(), "detections_file": bool(find_detections_file())})
            if method == "POST" and path == "/api/settings":
                cfg = save_settings(self._read_json())
                return self._json(200, {"settings": cfg, "detections_file": bool(find_detections_file())})
            if method == "POST" and path == "/api/busted":
                return self._json(200, run_busted(norm_pipeline(self._read_json())))
            if method == "POST" and path == "/api/validate":
                return self._json(200, validate_pipeline(norm_pipeline(self._read_json())))
            if method == "POST" and path == "/api/run":
                return self._json(200, run_pipeline(norm_pipeline(self._read_json())))
            raise ApiError("Not found.", 404)
        except ApiError as exc:
            return self._json(exc.status, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write("Unhandled error: %r\n" % exc)
            return self._json(500, {"error": "Internal error: %s" % exc})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")


def cli_generate(argv):
    """python3 server.py --generate sample.json [Vendor] [version] -> prints Lua (used by the Busted specs)."""
    text = Path(argv[0]).read_text()
    vendor = argv[1] if len(argv) > 1 else ""
    version = argv[2] if len(argv) > 2 else ""
    sys.stdout.write(generate_serializer(text, vendor, vendor, version)["code"])


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--generate":
        return cli_generate(sys.argv[2:])
    PIPE_DIR.mkdir(exist_ok=True)
    try:
        httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as exc:
        sys.exit("Could not listen on %s:%d (%s). Try PORT=9000 python3 server.py" % (HOST, PORT, exc))
    vec, lua = find_vector(), find_lua()
    print("Trickle running at http://127.0.0.1:%d (listening on %s)" % (PORT, HOST))
    print("Vector: %s" % (vector_version(vec) if vec else "NOT FOUND. Install with: brew trust vectordotdev/brew && brew tap vectordotdev/brew && brew install vector"))
    print("Lua:    %s" % (lua if lua else "NOT FOUND (needed for the serializer step). Install with: brew install luajit"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    main()
