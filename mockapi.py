"""Fake vendor API for Trickle's collector runner. No sockets: the runner hands each fetch{} request here.

Auth modes: none, darktrace (self-signed HMAC-SHA1 DTAPI headers), host (the DPM host source injects auth, so the script should send none), basic, apikey, bearer,
oauth2_basic (client_secret_basic), oauth2_post (client_secret_post).
Paging styles: none, link (Link: rel="next" header, Okta style), search_after (X-Search_after header, JumpCloud style),
cursor (next_cursor in the body), page (page number), odata (@odata.nextLink with $skiptoken, Microsoft Graph),
offset (limit and offset query parameters, Netskope), graphql (first/after in the query text, nodes and pageInfo, Wiz),
jsonapi (links.next relative path with starting_after, Snyk), cursor_items (cursor in the JSON body, items/cursor/has_more, 1Password).
Shape "template" returns a JSON envelope with {{records}}, {{records:0:2}}, {{now_iso}} and {{now_ms}} tokens (Proofpoint).
Any URL whose last path segment is "token" (or ends with /token) is the token endpoint for the OAuth2 modes;
every other URL is the data endpoint. The data endpoint serves the pasted records in one response.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlunparse

AUTH_MODES = ("none", "host", "darktrace", "basic", "apikey", "bearer", "oauth2_basic", "oauth2_post")
PAGING = ("none", "link", "search_after", "cursor", "page", "odata", "offset", "graphql", "jsonapi", "cursor_items")
SHAPES = ("array", "data", "events", "value", "result", "items", "template")
SINGLE_START = ("sinceTime", "created_after", "start_time", "since", "starttime", "from", "after")
LIMIT_KEYS = ("$top", "limit", "per_page", "page_size", "pageSize", "maxResults", "max_results")
TIME_PAIRS = (("starttime", "endtime"), ("insertionstarttime", "insertionendtime"), ("start", "end"), ("from", "to"), ("since", "until"), ("start_time", "end_time"))
CURSOR_KEYS = ("cursor", "next", "page_token", "after_cursor", "starting_after")


def _hdr(headers, name):
    n = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == n:
            return v if isinstance(v, str) else str(v)
    return None


def _basic(headers):
    h = _hdr(headers, "Authorization")
    if not h or not h.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(h[6:].strip(), validate=True).decode("utf-8")
    except Exception:
        return ("", "")
    cid, _, sec = raw.partition(":")
    return cid, sec


def _bearer(headers):
    h = _hdr(headers, "Authorization")
    if h and h.lower().startswith("bearer "):
        return h[7:].strip()
    return None


def _qs(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    return str(v)


def _mask(headers):
    """What the collector sent, with secrets hidden: enough to see which scheme it used."""
    out = {}
    for k, v in (headers or {}).items():
        lk = str(k).lower()
        v = v if isinstance(v, str) else str(v)
        if lk == "authorization":
            scheme, _, rest = v.partition(" ")
            out[k] = scheme + " " + (rest[:4] + "..." if rest else "(empty)")
        elif "key" in lk or "token" in lk or "secret" in lk:
            out[k] = v[:4] + "..." if v else "(empty)"
        else:
            out[k] = v
    return out


class MockApi:
    def __init__(self, cfg, records):
        cfg = cfg or {}
        self.config_error = None
        self.mode = cfg.get("auth") if cfg.get("auth") in AUTH_MODES else "none"
        self.client_id = str(cfg.get("client_id") or "")
        self.client_secret = str(cfg.get("client_secret") or "")
        self.key_header = str(cfg.get("key_header") or "x-api-key")
        self.key_value = str(cfg.get("key_value") or "")
        self.bearer_token = str(cfg.get("bearer_token") or "")
        self.shape = cfg.get("shape") if cfg.get("shape") in SHAPES else "array"
        self.time_unit = cfg.get("time_unit") if cfg.get("time_unit") in ("ms", "s", "iso", "iso_mixed") else "ms"
        self.fail_status = str(cfg.get("fail_status") or "").strip()
        try:
            self.fail_on = int(cfg.get("fail_on_call") or 0)
        except (TypeError, ValueError):
            self.fail_on = 0
        self.data_n = 0
        self.windows = {}
        self.template = None
        tt = str(cfg.get("body_template") or "").strip()
        if self.shape == "template":
            try:
                self.template = json.loads(tt) if tt else {"records": "{{records}}"}
            except ValueError:
                self.template = None
                self.config_error = "The response template must be valid JSON, for example {\"events\": \"{{records}}\", \"queryEndTime\": \"{{now_iso}}\"}."
        try:
            self.ttl = int(cfg.get("token_ttl") or 3600)
        except (TypeError, ValueError):
            self.ttl = 3600
        self.paging = cfg.get("paging") if cfg.get("paging") in PAGING else "none"
        try:
            self.page_size = max(0, int(cfg.get("page_size") or 0))
        except (TypeError, ValueError):
            self.page_size = 0
        self.link_last = "always" if cfg.get("link_last") == "always" else "omit"
        self.lower = cfg.get("header_case") != "asis"
        self.public_token = str(cfg.get("public_token") or "")
        self.private_token = str(cfg.get("private_token") or "")
        self.time_field = str(cfg.get("time_field") or "").strip()
        self.time_fields = [f.strip() for f in self.time_field.split(",") if f.strip()]
        self.window_mode = cfg.get("window_mode") if cfg.get("window_mode") in ("filter", "spread") else "off"
        self.routes = {}
        rt = str(cfg.get("routes") or "").strip()
        if rt:
            try:
                v = json.loads(rt)
                if not isinstance(v, dict):
                    raise ValueError("not an object")
                self.routes = {("/" + str(k).strip("/")): val for k, val in v.items()}
            except ValueError:
                self.config_error = 'Extra endpoints must be a JSON object such as {"/status": {"version": "1"}, "/groups": [{...}]}.'
        self.records = records
        self.tokens = set()
        self.n = 0
        self.transcript = []

    def _resp(self, status, body, note, req, headers=None, auth_ok=None, kind="data", warn=None):
        text = body if isinstance(body, str) else json.dumps(body)
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        if self.lower:
            h = {k.lower(): v for k, v in h.items()}
        self.transcript.append({"n": self.n, "method": req["method"], "url": req["url"], "status": status, "kind": kind,
                                "note": note, "auth_ok": auth_ok, "warn": warn, "sent": _mask(req["headers"]),
                                "body_sent": (req["body"] or "")[:300], "reply": text[:200],
                                "reply_headers": {k: (v if isinstance(v, str) else str(v))[:160] for k, v in h.items() if k.lower() != "content-type"}})
        return {"status": status, "body": text, "headers": h}

    def _is_token_url(self, url):
        seg = urlparse(url).path.rstrip("/").lower()
        return self.mode.startswith("oauth2") and (seg.endswith("/token") or seg == "token")

    def handle(self, params):
        self.n += 1
        url = str(params.get("url") or "")
        q = params.get("query")
        if isinstance(q, dict) and q:
            sep = "&" if "?" in url else "?"
            url += sep + urlencode(sorted((str(k), _qs(v)) for k, v in q.items()))
        req = {"method": str(params.get("method") or "GET").upper(), "url": url,
               "headers": params.get("headers") if isinstance(params.get("headers"), dict) else {},
               "body": params.get("body") if isinstance(params.get("body"), str) else ""}
        if self._is_token_url(req["url"]):
            return self._token(req)
        return self._data(req)

    # -- token endpoint ---------------------------------------------------
    def _token(self, req):
        if req["method"] != "POST":
            return self._resp(405, {"error": "method_not_allowed"}, "token endpoint needs POST", req, auth_ok=False, kind="token")
        form = {k: v[0] for k, v in parse_qs(req["body"], keep_blank_values=True).items()}
        if form.get("grant_type") != "client_credentials":
            return self._resp(400, {"error": "unsupported_grant_type", "error_description": "grant_type must be client_credentials"},
                              "body needs grant_type=client_credentials (form encoded, Content-Type application/x-www-form-urlencoded)",
                              req, auth_ok=False, kind="token")
        basic = _basic(req["headers"])
        in_body = "client_id" in form or "client_secret" in form
        if self.mode == "oauth2_basic":
            if basic is None:
                msg = ("client_secret_basic was requested but the credentials were found in the request body (client_secret_post)"
                       if in_body else "credentials missing in both header and body")
                return self._resp(401, {"error": "invalid_client", "error_description": msg}, msg, req, auth_ok=False, kind="token")
            ok = basic == (self.client_id, self.client_secret)
            why = "Authorization: Basic base64(client_id:client_secret) matched" if ok else "client_id or client_secret did not match the mock settings"
        else:
            cid, sec = form.get("client_id"), form.get("client_secret")
            if cid is None and sec is None:
                msg = ("client_secret_post was requested but the credentials were sent in an Authorization: Basic header (client_secret_basic)"
                       if basic is not None else "credentials missing in both header and body")
                return self._resp(401, {"error": "invalid_client", "error_description": msg}, msg, req, auth_ok=False, kind="token")
            ok = (cid, sec) == (self.client_id, self.client_secret)
            why = "client_id and client_secret in the body matched" if ok else "client_id or client_secret did not match the mock settings"
        if not ok:
            return self._resp(401, {"error": "invalid_client", "error_description": "invalid client credentials"}, why, req, auth_ok=False, kind="token")
        tok = "mock-" + secrets.token_hex(12)
        self.tokens.add(tok)
        body = {"access_token": tok, "token_type": "Bearer", "expires_in": self.ttl}
        if form.get("scope"):
            body["scope"] = form["scope"]
        return self._resp(200, body, why, req, auth_ok=True, kind="token")

    # -- data endpoint ----------------------------------------------------
    def _data(self, req):
        ok, why, hdrs, warn = True, "no auth required", {}, None
        h = req["headers"]
        if self.mode == "host":
            why = "auth is injected by the host source in DPM, so the script needs none"
            sent = [k for k in h if str(k).lower() in ("authorization", "x-api-key", "api-key") or "token" in str(k).lower() or "key" in str(k).lower()]
            if sent:
                warn = ("the script sent %s. A host that injects auth overwrites it on every call, so remove it from the script"
                        % ", ".join(str(k) for k in sent))
        elif self.mode == "darktrace":
            ok, why, code = self._darktrace(req)
            if not ok:
                return self._resp(code, {"error": why}, why, req, auth_ok=False)
        elif self.mode == "basic":
            b = _basic(h)
            ok = b == (self.client_id, self.client_secret)
            why = ("Authorization: Basic matched" if ok else
                   ("no Authorization: Basic header" if b is None else "Basic credentials did not match the mock settings"))
            hdrs = {"WWW-Authenticate": "Basic"}
        elif self.mode == "apikey":
            got = _hdr(h, self.key_header)
            ok = got is not None and got == self.key_value
            why = ("%s matched" % self.key_header) if ok else ("header %s was not sent" % self.key_header if got is None else "%s value did not match the mock key" % self.key_header)
        elif self.mode == "bearer":
            t = _bearer(h)
            ok = t is not None and t == self.bearer_token
            why = "Authorization: Bearer matched" if ok else ("no Authorization: Bearer header" if t is None else "bearer token did not match the mock token")
            hdrs = {"WWW-Authenticate": "Bearer"}
        elif self.mode.startswith("oauth2"):
            t = _bearer(h)
            ok = t is not None and t in self.tokens
            if ok:
                why = "Bearer token was the one the mock token endpoint issued"
            elif t is None:
                why = "no Authorization: Bearer header (did the token call succeed and is the token passed on?)"
            else:
                why = "bearer token was not issued by the mock token endpoint"
            hdrs = {"WWW-Authenticate": "Bearer"}
        if not ok:
            return self._resp(401, {"error": "unauthorized", "message": why}, why, req, hdrs, auth_ok=False)
        self.data_n += 1
        if self.fail_on and self.fail_status and self.data_n == self.fail_on:
            if self.fail_status.lower() == "gql":
                return self._resp(200, {"errors": [{"message": "injected GraphQL error"}], "data": None},
                                  "injected: HTTP 200 with a GraphQL errors body and null data (data call %d)" % self.data_n, req, auth_ok=True)
            try:
                code = int(self.fail_status)
            except ValueError:
                code = 500
            return self._resp(code, {"error": "injected failure"}, "injected: HTTP %d on data call %d" % (code, self.data_n), req, auth_ok=True)
        recs, obj, tnote = self._records_for(req)
        if self.shape == "template" and obj is None and self.template is not None:
            return self._resp(200, self._render(self.template, recs), why + tnote + "; template reply", req, auth_ok=True, warn=warn)
        if obj is not None:
            return self._resp(200, obj, why + "; single object reply" + tnote, req, auth_ok=True, warn=warn)
        body, extra, pnote = self._page(req, recs)
        return self._resp(200, body, why + tnote + pnote, req, extra, auth_ok=True, warn=warn)

    def _darktrace(self, req):
        h = req["headers"]
        tok, date, sig = _hdr(h, "DTAPI-Token"), _hdr(h, "DTAPI-Date"), _hdr(h, "DTAPI-Signature")
        miss = [n for n, v in (("DTAPI-Token", tok), ("DTAPI-Date", date), ("DTAPI-Signature", sig)) if not v]
        if miss:
            return False, "missing header " + ", ".join(miss), 400
        if tok != self.public_token:
            return False, "DTAPI-Token does not match the mock public token", 400
        try:
            d = datetime.fromisoformat(str(date).replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            skew = abs((datetime.now(timezone.utc) - d).total_seconds())
        except ValueError:
            return False, "DTAPI-Date is not an ISO 8601 timestamp: " + str(date), 400
        if skew > 300:
            return False, "DTAPI-Date is %d seconds from the server clock (limit 300)" % skew, 400
        u = urlparse(req["url"])
        pairs = sorted(parse_qsl(u.query, keep_blank_values=True), key=lambda kv: kv[0])
        api_str = u.path + "?" + "&".join("%s=%s" % kv for kv in pairs) if pairs else u.path

        def sign(a):
            return hmac.new(self.private_token.encode(), ("%s\n%s\n%s" % (a, self.public_token, date)).encode(), hashlib.sha1).hexdigest()

        if str(sig).lower() == sign(api_str):
            return True, "Darktrace HMAC-SHA1 signature matched for " + api_str, 200
        hint = ""
        if str(sig).lower() == sign(u.path):
            hint = " (it signed the path only: the signature must include the sorted query string)"
        elif pairs and str(sig).lower() == sign(u.path + "?" + "&".join("%s=%s" % kv for kv in parse_qsl(u.query, keep_blank_values=True))):
            hint = " (it signed the query in a different order: sort the keys)"
        return False, "signature mismatch: the mock signed %r with the private token%s. Invalid Public/Private Token or the signed string differs from the request" % (api_str, hint), 400

    # -- routes and time windows -------------------------------------------
    @staticmethod
    def _ms(v):
        try:
            n = float(v)
            return int(n if n >= 1e11 else n * 1000)
        except (TypeError, ValueError):
            pass
        try:
            d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return int(d.timestamp() * 1000)
        except ValueError:
            return None

    def _render(self, node, recs):
        if isinstance(node, str):
            m = re.fullmatch(r"\{\{records(?::(\d*):(\d*))?\}\}", node)
            if m:
                if m.group(1) is None:
                    return list(recs)
                return list(recs)[int(m.group(1) or 0):(int(m.group(2)) if m.group(2) else None)]
            now = datetime.now(timezone.utc)
            return node.replace("{{now_iso}}", now.strftime("%Y-%m-%dT%H:%M:%SZ")).replace("{{now_ms}}", str(int(now.timestamp() * 1000)))
        if isinstance(node, list):
            return [self._render(x, recs) for x in node]
        if isinstance(node, dict):
            return {k: self._render(v, recs) for k, v in node.items()}
        return node

    @staticmethod
    def _jbody(req):
        try:
            v = json.loads(req["body"]) if req["body"] else {}
        except ValueError:
            return {}
        return v if isinstance(v, dict) else {}

    @staticmethod
    def _gql_root(jb):
        m = re.search(r"\{\s*(\w+)\s*[({]", str(jb.get("query", "")))
        return m.group(1) if m else None

    @staticmethod
    def _get(rec, path):
        cur = rec
        for p in path.split("."):
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return None
        return cur

    @staticmethod
    def _set(rec, path, val):
        parts = path.split(".")
        cur = rec
        for p in parts[:-1]:
            if not isinstance(cur.get(p), dict):
                cur[p] = {}
            cur = cur[p]
        cur[parts[-1]] = val

    def _fmt(self, t, i):
        if self.time_unit == "ms":
            return t
        if self.time_unit == "s":
            return t // 1000
        dt = datetime.fromtimestamp(t / 1000, timezone.utc)
        if self.time_unit == "iso_mixed" and i % 2:
            return dt.astimezone(timezone(timedelta(hours=5, minutes=30))).strftime("%Y-%m-%dT%H:%M:%S") + "+05:30"
        if self.time_unit == "iso_mixed":
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _window(self, req, qp, jb):
        src = {k: v for k, v in qp}
        for k, v in jb.items():
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                src.setdefault(k, v)
        for a, b in TIME_PAIRS:
            if a in src and b in src:
                return self._ms(src[a]), self._ms(src[b])
        fm = re.search(r"\bge\s+(\S+)\s+and\s+\w+\s+le\s+(\S+)", str(src.get("$filter", "")))
        if fm:
            return self._ms(fm.group(1)), self._ms(fm.group(2))
        now = int(time.time() * 1000)
        for k in SINGLE_START:
            if k in src:
                lo = self._ms(src[k])
                if lo is not None:
                    return lo, now
        m = re.search(r"\{\s*after:\s*\"([^\"]+)\"", str(jb.get("query", "")))
        if m:
            lo = self._ms(m.group(1))
            if lo is not None:
                return lo, now
        return None, None

    def _records_for(self, req):
        u = urlparse(req["url"])
        path = "/" + u.path.strip("/")
        qp = parse_qsl(u.query, keep_blank_values=True)
        jb = self._jbody(req)
        keys = []
        if self.paging == "graphql" and self._gql_root(jb):
            keys.append("gql:" + self._gql_root(jb))
        keys += [path + "?" + k + "=" + v for k, v in qp]
        keys.append(path)
        rkey = next((k for k in keys if k in self.routes), path)
        recs, note = self.records, ""
        if rkey in self.routes:
            val = self.routes[rkey]
            if not isinstance(val, list):
                return [], val, ""
            recs, note = val, "; route " + rkey
        if self.window_mode == "off" or not self.time_fields:
            return recs, None, note
        lo, hi = self._window(req, qp, jb)
        if lo is None or hi is None:
            if rkey in self.windows:
                lo, hi = self.windows[rkey]
                note += "; reusing the window from the first call"
            else:
                return recs, None, note + "; no time window in the request"
        else:
            self.windows[rkey] = (lo, hi)
        if self.window_mode == "spread":
            n = len(recs)
            out = []
            for i, rec in enumerate(recs):
                c = json.loads(json.dumps(rec)) if isinstance(rec, dict) else rec
                if isinstance(c, dict):
                    t = self._fmt(lo + (hi - lo) * (i + 1) // (n + 1), i)
                    present = [f for f in self.time_fields if self._get(c, f) is not None]
                    for f in (present or self.time_fields[:1]):
                        self._set(c, f, t)
                out.append(c)
            return out, None, note + "; %d record(s) spread across the window %d-%d" % (n, lo, hi)
        out = []
        for rec in recs:
            t = None
            if isinstance(rec, dict):
                for f in self.time_fields:
                    if self._get(rec, f) is not None:
                        t = self._ms(self._get(rec, f))
                        break
            if t is not None and lo <= t <= hi:
                out.append(rec)
        return out, None, note + "; window %d-%d kept %d of %d" % (lo, hi, len(out), len(recs))

    def _gql_page(self, req, recs):
        jb = self._jbody(req)
        qtext = str(jb.get("query", ""))
        root = self._gql_root(jb) or "items"
        stripped = re.sub(r"filterBy:\s*\{[^{}]*\{[^{}]*\}\s*\}", "", qtext)
        m = re.search(r"\bafter:\s*\"([^\"]*)\"", stripped)
        cursor = m.group(1) if m else ""
        fm = re.search(r"\bfirst:\s*(\d+)", qtext)
        first = int(fm.group(1)) if fm else 100
        limit = min(first, self.page_size) if self.page_size else first
        total = len(recs)
        try:
            start = max(0, int(cursor.split("-")[-1])) if cursor else 0
        except ValueError:
            start = 0
        end = min(total, start + max(1, limit))
        body = {"data": {root: {"nodes": recs[start:end], "pageInfo": {"hasNextPage": end < total, "endCursor": "gc-%d" % end}}}}
        note = "; %s records %d-%d of %d, hasNextPage %s" % (root, start + 1 if end > start else start, end, total, str(end < total).lower())
        return body, {}, note

    def _wrap(self, recs, more=None):
        if self.shape == "array" and more is None:
            return recs
        key = self.shape if self.shape in ("events", "value", "result", "items") else "data"
        out = {key: recs}
        out.update(more or {})
        return out

    def _page(self, req, recs):
        total = len(recs)
        if self.paging == "graphql":
            return self._gql_page(req, recs)
        if self.paging == "none":
            return self._wrap(recs), {}, ""
        u = urlparse(req["url"])
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        try:
            jb = json.loads(req["body"]) if req["body"] else {}
        except ValueError:
            jb = {}
        jb = jb if isinstance(jb, dict) else {}
        limit = 0
        for k in LIMIT_KEYS:
            v = q.get(k, jb.get(k))
            try:
                if v is not None and int(v) > 0:
                    limit = int(v)
                    break
            except (TypeError, ValueError):
                pass
        if self.page_size:
            limit = min(limit, self.page_size) if limit else self.page_size
        limit = limit or 1000

        def idx(v):
            try:
                return max(0, int(str(v).split("-")[-1]))
            except (TypeError, ValueError):
                return 0

        extra, wrapper = {}, None
        if self.paging == "link":
            start = idx(q.get("after"))
            end = min(total, start + limit)
            base = urlunparse((u.scheme, u.netloc, u.path, "", "", ""))
            def link(after):
                qq = dict(q)
                qq["after"] = str(after)
                return "<%s?%s>" % (base, urlencode(qq))
            parts = ['<%s>; rel="self"' % req["url"]]
            if end < total or self.link_last == "always":
                parts.append(link(end) + '; rel="next"')
            extra = {"Link": ", ".join(parts)}
            note = "; records %d-%d of %d, Link %s" % (start + 1 if end > start else start, end, total, "has rel=next" if len(parts) > 1 else "has no rel=next (last page)")
        elif self.paging == "search_after":
            sa = q.get("search_after") or jb.get("search_after")
            start = idx(sa[-1]) if isinstance(sa, list) and sa else (idx(sa) if sa else 0)
            end = min(total, start + limit)
            extra = {"X-Result-Count": str(end - start), "X-Limit": str(limit), "X-Sort": "ASC",
                     "X-Search_after": json.dumps([1576181718000 + end, "idx-%d" % end])}
            note = "; records %d-%d of %d, X-Result-Count %d vs X-Limit %d" % (start + 1 if end > start else start, end, total, end - start, limit)
        elif self.paging == "odata":
            tok = q.get("$skiptoken")
            start = idx(tok) if tok else 0
            end = min(total, start + limit)
            wrapper = {}
            if end < total:
                nxt = re.sub(r"[?&]\$skiptoken=[^&]*", "", req["url"])
                nxt += ("&" if "?" in nxt else "?") + "$skiptoken=st-%d" % end
                wrapper["@odata.nextLink"] = nxt
            note = "; records %d-%d of %d, %s" % (start + 1 if end > start else start, end, total, "has @odata.nextLink" if wrapper else "no @odata.nextLink (last page)")
        elif self.paging == "jsonapi":
            start = idx(q.get("starting_after"))
            end = min(total, start + limit)
            wrapper = {"jsonapi": {"version": "1.0"}}
            if end < total:
                rel = u.path + ("?" + u.query if u.query else "")
                rel = re.sub(r"[?&]starting_after=[^&]*", "", rel)
                wrapper["links"] = {"next": rel + ("&" if "?" in rel else "?") + "starting_after=jc-%d" % end}
            note = "; records %d-%d of %d, %s" % (start + 1 if end > start else start, end, total, "links.next present" if "links" in wrapper else "no links.next (last page)")
        elif self.paging == "cursor_items":
            cur = jb.get("cursor") or q.get("cursor")
            start = idx(cur) if cur else 0
            end = min(total, start + limit)
            wrapper = {"cursor": "oc-%d" % end, "has_more": end < total}
            note = "; %s, records %d-%d of %d, has_more %s" % ("cursor given" if cur else "no cursor", start + 1 if end > start else start, end, total, str(end < total).lower())
        elif self.paging == "offset":
            start = idx(q.get("offset") or jb.get("offset"))
            end = min(total, start + limit)
            note = "; offset %d, limit %d, returned %d of %d" % (start, limit, end - start, total)
        elif self.paging == "cursor":
            cur = next((q.get(k) or jb.get(k) for k in CURSOR_KEYS if q.get(k) or jb.get(k)), None)
            start = idx(cur)
            end = min(total, start + limit)
            wrapper = {"next_cursor": ("c-%d" % end) if end < total else None, "has_more": end < total}
            note = "; records %d-%d of %d, next_cursor %s" % (start + 1 if end > start else start, end, total, wrapper["next_cursor"])
        else:
            page = 1
            try:
                page = max(1, int(q.get("page", jb.get("page", 1))))
            except (TypeError, ValueError):
                pass
            start = (page - 1) * limit
            end = min(total, start + limit)
            pages = max(1, -(-total // limit))
            extra = {"X-Total-Count": str(total), "X-Total-Pages": str(pages), "X-Page": str(page)}
            note = "; page %d of %d, records %d-%d of %d" % (page, pages, start + 1 if end > start else start, end, total)
        return self._wrap(recs[start:end], wrapper), extra, note
