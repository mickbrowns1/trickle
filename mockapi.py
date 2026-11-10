"""Fake vendor API for Trickle's collector runner. No sockets: the runner hands each fetch{} request here.

Auth modes: none, basic, apikey, bearer, oauth2_basic (client_secret_basic), oauth2_post (client_secret_post).
Any URL whose last path segment is "token" (or ends with /token) is the token endpoint for the OAuth2 modes;
every other URL is the data endpoint. The data endpoint serves the pasted records in one response.
"""
import base64
import json
import secrets
from urllib.parse import parse_qs, urlparse

AUTH_MODES = ("none", "basic", "apikey", "bearer", "oauth2_basic", "oauth2_post")


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
        self.mode = cfg.get("auth") if cfg.get("auth") in AUTH_MODES else "none"
        self.client_id = str(cfg.get("client_id") or "")
        self.client_secret = str(cfg.get("client_secret") or "")
        self.key_header = str(cfg.get("key_header") or "x-api-key")
        self.key_value = str(cfg.get("key_value") or "")
        self.bearer_token = str(cfg.get("bearer_token") or "")
        self.shape = cfg.get("shape") if cfg.get("shape") in ("array", "data", "events") else "array"
        try:
            self.ttl = int(cfg.get("token_ttl") or 3600)
        except (TypeError, ValueError):
            self.ttl = 3600
        self.records = records
        self.tokens = set()
        self.n = 0
        self.transcript = []

    def _resp(self, status, body, note, req, headers=None, auth_ok=None, kind="data"):
        text = body if isinstance(body, str) else json.dumps(body)
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        self.transcript.append({"n": self.n, "method": req["method"], "url": req["url"], "status": status, "kind": kind,
                                "note": note, "auth_ok": auth_ok, "sent": _mask(req["headers"]),
                                "body_sent": (req["body"] or "")[:300], "reply": text[:200]})
        return {"status": status, "body": text, "headers": h}

    def _is_token_url(self, url):
        seg = urlparse(url).path.rstrip("/").lower()
        return self.mode.startswith("oauth2") and (seg.endswith("/token") or seg == "token")

    def handle(self, params):
        self.n += 1
        req = {"method": str(params.get("method") or "GET").upper(), "url": str(params.get("url") or ""),
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
        ok, why, hdrs = True, "no auth required", {}
        h = req["headers"]
        if self.mode == "basic":
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
        recs = self.records
        body = recs if self.shape == "array" else {("data" if self.shape == "data" else "events"): recs}
        return self._resp(200, body, why, req, auth_ok=True)
