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
import logging
import os
import secrets

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


async def api_status(request):
    return j({
        "collectors": status.status,
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
    before = q(request, "before")
    return j(await run_q(queries.requests, q(request, "host"), q(request, "status"), q(request, "ip"),
                         q(request, "q"), qint(request, "limit", 200, 1000), int(before) if before else None))


async def api_firewall(request):
    before = q(request, "before")
    return j({
        "events": await run_q(queries.firewall, q(request, "ip"), q(request, "crowdsec") == "1", q(request, "port"),
                              qint(request, "limit", 200, 1000), int(before) if before else None),
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
    body = await request.json()
    try:
        res = await asyncio.to_thread(lapi.add_ban, body["ip"].strip(), body.get("duration", "4h"),
                                      body.get("reason") or "manual ban from crowdsec-dash")
        await asyncio.to_thread(lapi.sync_once, False)  # pull the new decision right away
        return j({"ok": True, "result": res})
    except Exception as e:
        return j({"error": str(e)}, 400)


async def api_unban(request):
    if not settings.allow_write:
        return j({"error": "write actions disabled (set ALLOW_WRITE=true)"}, 403)
    try:
        res = await asyncio.to_thread(lapi.delete_decision, int(request.path_params["id"]))
        return j({"ok": True, "result": res})
    except Exception as e:
        return j({"error": str(e)}, 400)


# ---------------------------------------------------------------------------
# optional HTTP basic auth (DASH_USER / DASH_PASSWORD)
# ---------------------------------------------------------------------------
class BasicAuth(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not settings.dash_password or request.url.path == "/api/health":
            return await call_next(request)
        header = request.headers.get("authorization", "")
        if header.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
                if secrets.compare_digest(user, settings.dash_user or "admin") and secrets.compare_digest(pw, settings.dash_password):
                    return await call_next(request)
            except Exception:
                pass
        return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="crowdsec-dash"'})


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
        await asyncio.to_thread(geoip.init)  # picks up a fresh monthly db when one is due


@contextlib.asynccontextmanager
async def lifespan(app):
    await asyncio.to_thread(geoip.init)
    tasks = [asyncio.create_task(c()) for c in
             (cloudflare.run, lapi.run, npm_logs.run, syslog_fw.run, housekeeping)]
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

app = Starlette(routes=routes, lifespan=lifespan, middleware=[Middleware(BasicAuth)])
