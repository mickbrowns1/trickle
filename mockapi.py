"""Fake vendor API for Trickle's collector runner. No sockets: the runner hands each fetch{} request here.

Auth modes: none, host (the DPM host source injects auth, so the script should send none), basic, apikey, bearer,
oauth2_basic (client_secret_basic), oauth2_post (client_secret_post).
Paging styles: none, link (Link: rel="next" header, Okta style), search_after (X-Search_after header, JumpCloud style),
cursor (next_cursor in the body), page (page number).
Any URL whose last path segment is "token" (or ends with /token) is the token endpoint for the OAuth2 modes;
every other URL is the data endpoint. The data endpoint serves the pasted records in one response.
"""
import base64
import json
import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

AUTH_MODES = ("none", "host", "basic", "apikey", "bearer", "oauth2_basic", "oauth2_post")
PAGING = ("none", "link", "search_after", "cursor", "page")
LIMIT_KEYS = ("limit", "per_page", "page_size", "pageSize", "maxResults", "max_results")
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
        self.paging = cfg.get("paging") if cfg.get("paging") in PAGING else "none"
        try:
            self.page_size = max(0, int(cfg.get("page_size") or 0))
        except (TypeError, ValueError):
            self.page_size = 0
        self.link_last = "always" if cfg.get("link_last") == "always" else "omit"
        self.lower = cfg.get("header_case") != "asis"
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
        ok, why, hdrs, warn = True, "no auth required", {}, None
        h = req["headers"]
        if self.mode == "host":
            why = "auth is injected by the host source in DPM, so the script needs none"
            sent = [k for k in h if str(k).lower() in ("authorization", "x-api-key", "api-key") or "token" in str(k).lower() or "key" in str(k).lower()]
            if sent:
                warn = ("the script sent %s. A host that injects auth overwrites it on every call, so remove it from the script"
                        % ", ".join(str(k) for k in sent))
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
        body, extra, pnote = self._page(req)
        return self._resp(200, body, why + pnote, req, extra, auth_ok=True, warn=warn)

    # -- paging -----------------------------------------------------------
    def _wrap(self, recs, more=None):
        if self.shape == "array" and more is None:
            return recs
        key = "events" if self.shape == "events" else "data"
        out = {key: recs}
        out.update(more or {})
        return out

    def _page(self, req):
        recs, total = self.records, len(self.records)
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
