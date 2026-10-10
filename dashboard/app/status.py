"""
A tiny shared "health board". Each collector updates its own entry so the UI's
Status page can show what's working and what isn't (last success, last error).
"""
from .db import now_iso

status: dict[str, dict] = {
    "lapi": {"enabled": False, "ok": None, "last_ok": None, "last_error": None, "info": {}},
    "npm": {"enabled": False, "ok": None, "last_ok": None, "last_error": None, "info": {}},
    "syslog": {"enabled": False, "ok": None, "last_ok": None, "last_error": None, "info": {}},
    "geoip": {"enabled": False, "ok": None, "last_ok": None, "last_error": None, "info": {}},
    "cloudflare": {"enabled": False, "ok": None, "last_ok": None, "last_error": None, "info": {}},
}


def ok(name: str, **info):
    s = status[name]
    s["ok"] = True
    s["last_ok"] = now_iso()
    s["info"].update(info)


def fail(name: str, err: Exception | str):
    s = status[name]
    s["ok"] = False
    s["last_error"] = f"{now_iso()}  {err}"
