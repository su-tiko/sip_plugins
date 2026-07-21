#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Generic JSON API v1 plugin for SIP.

This plugin intentionally keeps helpers dependency-light so they can be tested
outside a running SIP controller.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import time
from pathlib import Path

try:  # SIP runtime imports
    import gv
    from helpers import jsave, read_log, restart, run_once, run_program, stop_stations, stop_onrain, clear_mm
    import gpio_pins
    from urls import urls
    import web
    from webpages import ProtectedPage
except Exception:  # Test/import fallback outside SIP
    gv = None
    jsave = None
    read_log = None
    restart = None
    run_once = None
    run_program = None
    stop_stations = None
    stop_onrain = None
    clear_mm = None
    gpio_pins = None
    urls = []
    class ProtectedPage(object):
        pass
    class _WebFallback:
        @staticmethod
        def input():
            return {}
        class ctx:
            env = {}
        @staticmethod
        def header(*args, **kwargs):
            return None
    web = _WebFallback()

API_VERSION = "v1"
PLUGIN_VERSION = "0.1.0"
TOKEN_FILE = Path("./data/api_tokens.json")

try:
    urls.extend([
        u"/api/v1/status", u"plugins.api.status",
        u"/api/v1/stations", u"plugins.api.stations",
        u"/api/v1/station", u"plugins.api.station",
        u"/api/v1/programs", u"plugins.api.programs",
        u"/api/v1/program", u"plugins.api.program",
        u"/api/v1/runonce", u"plugins.api.runonce_api",
        u"/api/v1/config", u"plugins.api.config",
        u"/api/v1/logs", u"plugins.api.logs",
        u"/api/v1/server", u"plugins.api.server",
        u"/api/v1/auth/tokens", u"plugins.api.auth_tokens",
        u"/api/v1/openapi.json", u"plugins.api.openapi_json",
    ])
except Exception:
    pass


def _json_default(value):
    if value == float("inf"):
        return None
    return str(value)


def _set_json_headers():
    try:
        web.header("Content-Type", "application/json")
        web.header("Cache-Control", "no-store")
    except Exception:
        pass


def response_ok(data=None, meta=None):
    _set_json_headers()
    payload = {"ok": True, "data": data if data is not None else {}, "error": None, "meta": {"api_version": API_VERSION, "plugin_version": PLUGIN_VERSION}}
    if meta:
        payload["meta"].update(meta)
    return json.dumps(payload, default=_json_default)


def response_error(code, message, status="400", data=None):
    _set_json_headers()
    try:
        web.ctx.status = status
    except Exception:
        pass
    return json.dumps({"ok": False, "data": data, "error": {"code": code, "message": message}, "meta": {"api_version": API_VERSION, "plugin_version": PLUGIN_VERSION}})


def _token_salt():
    return secrets.token_hex(16)


def _hash_token(raw, salt):
    return hashlib.sha256((salt + raw).encode("utf-8")).hexdigest()


def create_token_record(name, scopes=None, expires_at=None):
    raw = "sip_" + secrets.token_urlsafe(32)
    salt = _token_salt()
    now = int(time.time())
    record = {
        "id": secrets.token_hex(8),
        "name": name,
        "scopes": scopes or ["read", "write"],
        "salt": salt,
        "token_hash": _hash_token(raw, salt),
        "created_at": now,
        "expires_at": expires_at,
        "revoked": False,
    }
    return raw, record


def verify_token(raw, record):
    if not raw or record.get("revoked"):
        return False
    exp = record.get("expires_at")
    if exp and int(exp) < int(time.time()):
        return False
    candidate = _hash_token(raw, record.get("salt", ""))
    return hmac.compare_digest(candidate, record.get("token_hash", ""))


def _load_tokens():
    if not TOKEN_FILE.exists():
        return {"tokens": []}
    try:
        return json.loads(TOKEN_FILE.read_text())
    except Exception:
        return {"tokens": []}


def _save_tokens(data):
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = TOKEN_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(TOKEN_FILE)
    os.chmod(TOKEN_FILE, 0o600)


def _token_metadata(record):
    return {k: record.get(k) for k in ("id", "name", "scopes", "created_at", "expires_at", "revoked")}


def _bearer_token():
    try:
        header = web.ctx.env.get("HTTP_AUTHORIZATION", "")
    except Exception:
        header = ""
    if header.lower().startswith("bearer "):
        return header.split(None, 1)[1].strip()
    return None


def _authorized():
    raw = _bearer_token()
    if not raw:
        return True  # ProtectedPage/session auth still applies inside SIP.
    for record in _load_tokens().get("tokens", []):
        if verify_token(raw, record):
            return True
    return False


def _body():
    try:
        raw = getattr(web, "data", lambda: b"")()
        if raw:
            return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except Exception:
        pass
    try:
        return dict(web.input())
    except Exception:
        return {}


def _station_dict(idx):
    if gv is None:
        return {"id": idx + 1, "name": f"S{idx + 1:02d}", "state": 0}
    bid = idx // 8
    return {
        "id": idx + 1,
        "name": gv.snames[idx] if idx < len(gv.snames) else f"S{idx + 1:02d}",
        "state": int(gv.srvals[idx]) if idx < len(gv.srvals) else 0,
        "enabled": int((gv.sd.get("show", [255])[bid] >> (idx % 8)) & 1) if bid < len(gv.sd.get("show", [])) else 1,
        "master": int((gv.sd.get("mo", [0])[bid] >> (idx % 8)) & 1) if bid < len(gv.sd.get("mo", [])) else 0,
        "ignore_rain": int((gv.sd.get("ir", [0])[bid] >> (idx % 8)) & 1) if bid < len(gv.sd.get("ir", [])) else 0,
        "ignore_water_level": int((gv.sd.get("iw", [0])[bid] >> (idx % 8)) & 1) if bid < len(gv.sd.get("iw", [])) else 0,
        "remaining": max(0, int(gv.rs[idx][1] - gv.now)) if idx < len(gv.rs) and gv.rs[idx][1] not in (0, float("inf")) else 0,
        "program": gv.rs[idx][3] if idx < len(gv.rs) else 0,
    }


def _programs():
    if gv is None:
        return []
    return [{"id": i + 1, **p} for i, p in enumerate(gv.pd)]


def _status():
    if gv is None:
        return {"enabled": None, "stations": []}
    return {
        "system_name": gv.sd.get("name", "SIP"),
        "enabled": bool(gv.sd.get("en")),
        "manual_mode": bool(gv.sd.get("mm")),
        "rain_delay": gv.sd.get("rd"),
        "rain_sensed": gv.sd.get("rs"),
        "water_level": gv.sd.get("wl"),
        "busy": bool(getattr(gv, "bsy", False)),
        "running_program": getattr(gv, "pon", 0),
        "stations": [_station_dict(i) for i in range(gv.sd.get("nst", len(getattr(gv, "srvals", []))))],
    }


class status(ProtectedPage):
    def GET(self):
        return response_ok(_status())


class stations(ProtectedPage):
    def GET(self):
        count = gv.sd.get("nst", 0) if gv is not None else 0
        return response_ok([_station_dict(i) for i in range(count)])


class station(ProtectedPage):
    def GET(self):
        q = _body()
        ident = q.get("id") or q.get("name")
        if gv is None:
            return response_ok({})
        if str(ident).isdigit():
            idx = int(ident) - 1
        else:
            idx = gv.snames.index(str(ident))
        return response_ok(_station_dict(idx))

    def POST(self):
        if not _authorized():
            return response_error("unauthorized", "Invalid bearer token", "401 Unauthorized")
        data = _body()
        action = data.get("action")
        if gv is None:
            return response_ok({"action": action, "dry_run": True})
        if action in {"stop-all", "stop_all"}:
            stop_stations()
            return response_ok({"stopped": "all"})
        return response_ok({"accepted": action})


class programs(ProtectedPage):
    def GET(self):
        return response_ok(_programs())


class program(ProtectedPage):
    def GET(self):
        q = _body()
        ident = q.get("id")
        programs = _programs()
        if ident:
            return response_ok(programs[int(ident) - 1])
        return response_ok(programs)

    def POST(self):
        if not _authorized():
            return response_error("unauthorized", "Invalid bearer token", "401 Unauthorized")
        data = _body()
        action = data.get("action")
        if gv is None:
            return response_ok({"action": action, "dry_run": True})
        if action == "run":
            run_program(int(data.get("id")) - 1)
        elif action in {"enable", "disable"}:
            idx = int(data.get("id")) - 1
            gv.pd[idx]["enabled"] = 1 if action == "enable" else 0
            jsave(gv.pd, "programData")
        elif action == "create":
            gv.pd.append(data.get("program", {}))
            jsave(gv.pd, "programData")
        elif action == "update":
            idx = int(data.get("id")) - 1
            gv.pd[idx].update(data.get("program", {}))
            jsave(gv.pd, "programData")
        return response_ok({"action": action})


class runonce_api(ProtectedPage):
    def POST(self):
        if not _authorized():
            return response_error("unauthorized", "Invalid bearer token", "401 Unauthorized")
        data = _body()
        if gv is not None and data.get("action") == "stop":
            stop_stations()
        return response_ok({"accepted": data})


class config(ProtectedPage):
    def GET(self):
        q = _body()
        if gv is None:
            return response_ok({})
        key = q.get("key")
        return response_ok({key: gv.sd.get(key)} if key else gv.sd)

    def POST(self):
        if not _authorized():
            return response_error("unauthorized", "Invalid bearer token", "401 Unauthorized")
        data = _body()
        if gv is not None and data.get("key"):
            gv.sd[data["key"]] = data.get("value")
            jsave(gv.sd, "sd")
        return response_ok({"updated": data.get("key")})


class logs(ProtectedPage):
    def GET(self):
        if read_log is None:
            return response_ok([])
        return response_ok(read_log())
    def POST(self):
        if not _authorized():
            return response_error("unauthorized", "Invalid bearer token", "401 Unauthorized")
        if _body().get("action") == "clear":
            Path("./data/log.json").write_text("")
        return response_ok({"cleared": True})


class server(ProtectedPage):
    def GET(self):
        return response_ok({"sip_version": getattr(gv, "ver_str", None) if gv else None, "plugin_version": PLUGIN_VERSION})
    def POST(self):
        if not _authorized():
            return response_error("unauthorized", "Invalid bearer token", "401 Unauthorized")
        data = _body()
        if data.get("action") == "restart" and restart is not None:
            restart(2)
        return response_ok({"accepted": data.get("action")})


class auth_tokens(ProtectedPage):
    def GET(self):
        return response_ok([_token_metadata(r) for r in _load_tokens().get("tokens", [])])

    def POST(self):
        data = _body()
        action = data.get("action")
        store = _load_tokens()
        if action == "create":
            scopes = [s.strip() for s in str(data.get("scope", "read,write")).split(",") if s.strip()]
            raw, record = create_token_record(data.get("name", "token"), scopes=scopes, expires_at=data.get("expires_at"))
            store.setdefault("tokens", []).append(record)
            _save_tokens(store)
            meta = _token_metadata(record)
            meta["token"] = raw
            return response_ok(meta)
        if action == "revoke":
            token_id = data.get("id")
            for record in store.get("tokens", []):
                if record.get("id") == token_id:
                    record["revoked"] = True
            _save_tokens(store)
            return response_ok({"revoked": token_id})
        return response_error("invalid_action", "Expected action=create or action=revoke")


class openapi_json(object):
    def GET(self):
        _set_json_headers()
        path = Path(__file__).with_name("openapi.json")
        try:
            return path.read_text()
        except Exception:
            return response_ok({"openapi": "3.1.0", "paths": {}})
