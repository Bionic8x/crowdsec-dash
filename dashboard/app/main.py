"""
Web server + background collectors.

Run locally:   uvicorn app.main:app --port 8088
In Docker:     see the Dockerfile.

Starlette is the small ASGI framework FastAPI is built on. Each route is a plain
async function that returns JSON. The collectors are asyncio tasks started in
the `lifespan` hook, so a single process does everything.
"""
import asyncio
import base64
import contextlib
import ipaddress
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import geoip, queries, status
from .collectors import cloudflare, lapi, npm_logs, syslog_fw
from .config import settings
from .db import db

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("dash")
STATIC = os.path.join(os.path.dirname(__file__), "..", "static")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def q(request: Request, name: str, default=None):
    return request.query_params.get(name, default)


def qint(request: Request, name: str, default: int, maximum: int = 5000) -> int:
    try:
        return max(1, min(int(request.query_params.get(name, default)), maximum))
    except ValueError:
        return default


class BadRequest(Exception):
    """Raised for malformed query parameters; turned into a 400 by the handler below."""


def qint_opt(request: Request, name: str) -> int | None:
    v = request.query_params.get(name)
    if not v:
        return None
    try:
        return int(v)
    except ValueError:
        raise BadRequest(f"'{name}' must be a whole number") from None


async def bad_request(request, exc):
    return j({"error": str(exc)}, 400)


def j(data, code=200):
    return JSONResponse(data, status_code=code)


async def run_q(fn, *args):
    """Queries are blocking sqlite calls; run them off the event loop."""
    return await asyncio.to_thread(fn, *args)


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
async def index(request):
    return FileResponse(os.path.join(STATIC, "index.html"))


async def health(request):
    return j({"status": "ok"})


def npm_bouncer_status() -> dict:
    """The optional npm-bouncer container writes its state to a shared volume; show it like a collector."""
    try:
        with open(settings.npm_bouncer_status_file) as f:
            st = json.load(f)
        updated = datetime.fromisoformat(st["updated"].replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError):
        return {"enabled": False, "ok": None, "last_ok": None, "last_error": None,
                "info": {"note": "not running (optional: blocks banned IPs inside NPM, SETUP.md step 9)"}}
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    if age > 120:
        since = f"{age / 3600:.1f}h" if age >= 3600 else f"{int(age // 60)}m"
        error = (f"no update for {since}: the crowdsec-npm-bouncer container has stopped, usually because NPM "
                 "restarted (backup or update). Fix: docker compose up -d --force-recreate npm-bouncer. "
                 "To make this automatic, install scripts/npm-bouncer-watchdog.sh (SETUP.md step 9).")
    else:
        error = st.get("error")
    ok = bool(st.get("ok")) and not error
    labels = {"banned": "IPs blocked in NPM", "skipped": "skipped (LAN / Cloudflare / invalid)",
              "last_reload": "last nginx reload", "origins": "decision origins"}
    info = {label: st[k] for k, label in labels.items() if st.get(k) is not None}
    return {"enabled": True, "ok": ok, "last_ok": st["updated"] if ok else None,
            "last_error": f"{st['updated']}  {error}" if error else None, "info": info}


async def api_status(request):
    return j({
        "collectors": {**status.status, "npm_bouncer": npm_bouncer_status()},
        "counts": await run_q(queries.counts),
        "config": {
            "lapi_url": settings.lapi_url, "lapi_machine_id": settings.lapi_machine_id,
            "npm_log_dir": settings.npm_log_dir, "syslog_port": settings.syslog_port,
            "fw_actions": settings.fw_actions, "fw_interfaces": settings.fw_interfaces,
            "cloudflare_token": bool(settings.cf_api_token), "cf_fetch_events": settings.cf_fetch_events,
            "retention_days": settings.retention_days, "allow_write": settings.allow_write,
        },
        "cloudflare_ranges": cloudflare.cf_ranges(),
    })


async def api_overview(request):
    return j(await run_q(queries.overview, q(request, "range", "24h")))


async def api_geo(request):
    return j(await run_q(queries.geo_points, q(request, "range", "24h"), q(request, "layer", "threats")))


async def api_decisions(request):
    return j(await run_q(queries.decisions, q(request, "state", "active"), q(request, "q", ""), qint(request, "limit", 500)))


async def api_alerts(request):
    return j(await run_q(queries.alerts, q(request, "q", ""), qint(request, "limit", 300)))


async def api_requests(request):
    return j(await run_q(queries.requests, q(request, "host"), q(request, "status"), q(request, "ip"),
                         q(request, "q"), qint(request, "limit", 200, 1000), qint_opt(request, "before")))


async def api_firewall(request):
    return j({
        "events": await run_q(queries.firewall, q(request, "ip"), q(request, "crowdsec") == "1", qint_opt(request, "port"),
                              qint(request, "limit", 200, 1000), qint_opt(request, "before")),
        "summary": await run_q(queries.firewall_summary, q(request, "range", "24h")),
    })


async def api_hosts(request):
    return j(await run_q(queries.hosts, q(request, "range", "24h")))


async def api_ip(request):
    return j(await run_q(queries.ip_detail, request.path_params["ip"]))


async def api_cf_events(request):
    return j(await run_q(db.all, "SELECT * FROM cf_events ORDER BY ts DESC LIMIT ?", (qint(request, "limit", 300),)))


async def api_ban(request):
    if not settings.allow_write:
        return j({"error": "write actions disabled (set ALLOW_WRITE=true)"}, 403)
    try:
        body = await request.json()
    except ValueError:
        return j({"error": "request body must be JSON"}, 400)
    if not isinstance(body, dict) or not isinstance(body.get("ip"), str):
        return j({"error": 'expected {"ip": "...", "duration": "4h", "reason": "..."}'}, 400)
    try:
        res = await asyncio.to_thread(lapi.add_ban, body["ip"].strip(), str(body.get("duration") or "4h"),
                                      str(body.get("reason") or ""))
    except Exception as e:
        return j({"error": str(e)}, 400)
    try:
        await asyncio.to_thread(lapi.sync_once, False)  # pull the new decision right away
    except Exception as e:  # the ban itself worked; the next regular poll will pick it up
        log.warning("sync after ban failed: %s", e)
    return j({"ok": True, "result": res})


async def api_unban(request):
    if not settings.allow_write:
        return j({"error": "write actions disabled (set ALLOW_WRITE=true)"}, 403)
    try:
        res = await asyncio.to_thread(lapi.delete_decision, int(request.path_params["id"]))
        return j({"ok": True, "result": res})
    except Exception as e:
        return j({"error": str(e)}, 400)


# ---------------------------------------------------------------------------
# request guards: Host check, HTTP basic auth, CSRF check for write actions
# ---------------------------------------------------------------------------
def host_allowed(host_header: str) -> bool:
    """Only answer to IP addresses, localhost and ALLOWED_HOSTS. A DNS-rebinding attack
    arrives with the attacker's own domain in the Host header, so it is refused here."""
    if "*" in settings.allowed_hosts:
        return True
    host = host_header.strip().lower()
    if host.startswith("["):  # [::1]:8088
        host = host[1:host.find("]")]
    elif host.count(":") == 1:  # name:port or 1.2.3.4:port
        host = host.rsplit(":", 1)[0]
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    for pat in settings.allowed_hosts:
        pat = pat.lower()
        if host == pat or (pat.startswith("*.") and host.endswith(pat[1:])):
            return True
    return False


class HostGuard(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path == "/api/health" or host_allowed(request.headers.get("host", "")):
            return await call_next(request)
        log.warning("refused request for Host %r (add it to ALLOWED_HOSTS if it's yours)", request.headers.get("host"))
        return Response("Unknown host name. Add it to ALLOWED_HOSTS in .env to use it.", 421)


class BasicAuth(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path == "/api/health":
            return await call_next(request)
        if not settings.dash_password:
            if settings.allow_no_auth:
                return await call_next(request)
            return Response("crowdsec-dash has no password. Set DASH_PASSWORD in .env "
                            "(or ALLOW_NO_AUTH=true to run it open) and restart the container.", 503)
        header = request.headers.get("authorization", "")
        if header.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(header[6:]).partition(b":")
                # compare bytes: compare_digest refuses str with non-ASCII characters
                user_ok = secrets.compare_digest(user, (settings.dash_user or "admin").encode())
                pw_ok = secrets.compare_digest(pw, settings.dash_password.encode())
                if user_ok and pw_ok:
                    return await call_next(request)
            except Exception:
                pass
        return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="crowdsec-dash"'})


class WriteGuard(BaseHTTPMiddleware):
    """Cross-site request forgery protection for POST/DELETE.

    Browsers attach saved Basic-auth credentials to cross-site form posts, and a form can
    send a body that parses as JSON. Requiring a custom header defeats that: another site
    can't add one without a CORS preflight, which we never approve. The Origin check is a
    second layer for browsers that send it."""

    async def dispatch(self, request, call_next):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)
        if request.headers.get("x-dash-request") != "1":
            return j({"error": "missing X-Dash-Request header"}, 403)
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
            return j({"error": "cross-origin request refused"}, 403)
        return await call_next(request)


# ---------------------------------------------------------------------------
# background tasks
# ---------------------------------------------------------------------------
async def housekeeping():
    while True:
        try:
            await asyncio.to_thread(db.prune, settings.retention_days)
        except Exception as e:
            log.warning("prune failed: %s", e)
        await asyncio.sleep(3600)
        try:
            await asyncio.to_thread(geoip.init)  # picks up a fresh monthly db when one is due
        except Exception as e:
            log.warning("geoip reload failed: %s", e)


def _log_crash(task: asyncio.Task):
    if not task.cancelled() and task.exception():
        log.error("background task %s stopped", task.get_name(), exc_info=task.exception())


@contextlib.asynccontextmanager
async def lifespan(app):
    if not settings.dash_password:
        if settings.allow_no_auth:
            log.warning("DASH_PASSWORD is empty and ALLOW_NO_AUTH=true: anyone who can reach the dashboard can use it")
        else:
            log.error("DASH_PASSWORD is empty: the dashboard will refuse requests until it is set (or ALLOW_NO_AUTH=true)")
    await asyncio.to_thread(geoip.init)
    tasks = []
    for c in (cloudflare.run, lapi.run, npm_logs.run, syslog_fw.run, housekeeping):
        t = asyncio.create_task(c(), name=f"{c.__module__}.{c.__name__}")
        t.add_done_callback(_log_crash)
        tasks.append(t)
    log.info("crowdsec-dash started on :%s", settings.port)
    yield
    for t in tasks:
        t.cancel()


routes = [
    Route("/", index),
    Route("/api/health", health),
    Route("/api/status", api_status),
    Route("/api/overview", api_overview),
    Route("/api/geo", api_geo),
    Route("/api/decisions", api_decisions),
    Route("/api/decisions", api_ban, methods=["POST"]),
    Route("/api/decisions/{id:int}", api_unban, methods=["DELETE"]),
    Route("/api/alerts", api_alerts),
    Route("/api/requests", api_requests),
    Route("/api/firewall", api_firewall),
    Route("/api/hosts", api_hosts),
    Route("/api/ip/{ip:str}", api_ip),
    Route("/api/cloudflare/events", api_cf_events),
    Mount("/static", StaticFiles(directory=STATIC), name="static"),
]

app = Starlette(
    routes=routes,
    lifespan=lifespan,
    middleware=[Middleware(HostGuard), Middleware(BasicAuth), Middleware(WriteGuard)],  # outermost first
    exception_handlers={BadRequest: bad_request},
)
