"""
CrowdSec LAPI collector.

How CrowdSec stores things:
  * An **alert** is created when a scenario "overflows" (e.g. 10 failed logins
    from one IP in 30s). It records the source IP, the scenario, and the events.
  * A **decision** is attached to an alert: "ban 1.2.3.4 for 4h". Your OPNsense
    firewall bouncer pulls decisions and puts the IPs in a pf table that blocks them.

The dashboard registers as a *machine* (watcher) - same as an agent or cscli.
It logs in with POST /v1/watchers/login to get a JWT, then:
  * GET /v1/alerts?since=<duration>   -> new alerts (with their decisions)
  * GET /v1/alerts?has_active_decision=true -> what is banned right now
The second call lets us notice decisions removed early (cscli decisions delete),
because LAPI just stops returning them.
"""
import asyncio
import ipaddress
import json
import logging
from datetime import datetime

import requests

from .. import geoip, status
from ..config import settings
from ..db import db, iso, now_iso, utcnow
from ..timeutil import norm_ts, parse_go_duration

log = logging.getLogger("lapi")


class LapiClient:
    def __init__(self):
        self.token = None
        self.session = requests.Session()
        self.session.verify = settings.lapi_verify_tls
        self.session.headers["User-Agent"] = "crowdsec-dash/1.0"

    def login(self):
        r = self.session.post(
            f"{settings.lapi_url}/v1/watchers/login",
            json={"machine_id": settings.lapi_machine_id, "password": settings.lapi_password, "scenarios": []},
            timeout=20,
        )
        if r.status_code != 200:
            raise RuntimeError(f"login failed ({r.status_code}): {r.text[:200]}")
        self.token = r.json()["token"]
        self.session.headers["Authorization"] = f"Bearer {self.token}"

    def request(self, method: str, path: str, **kw):
        if not self.token:
            self.login()
        kw.setdefault("timeout", 60)
        r = self.session.request(method, f"{settings.lapi_url}{path}", **kw)
        if r.status_code == 401:  # JWT expired -> log in again once
            self.login()
            r = self.session.request(method, f"{settings.lapi_url}{path}", **kw)
        r.raise_for_status()
        return r.json() if r.content else None

    def alerts(self, **params):
        params.setdefault("limit", 0)  # 0 = no limit
        if not settings.lapi_include_capi:
            params.setdefault("include_capi", "false")
        return self.request("GET", "/v1/alerts", params=params) or []

    def heartbeat(self):
        try:
            self.request("GET", "/v1/heartbeat")
        except Exception:
            pass


client = LapiClient()


# ---------------------------------------------------------------------------
# Active-decision index, used by the firewall collector to tag drops as "CrowdSec"
# ---------------------------------------------------------------------------
class ActiveIndex:
    def __init__(self):
        self.ips: set[str] = set()
        self.nets: list = []

    def reload(self):
        rows = db.all("SELECT scope, value FROM decisions WHERE until > ?", (now_iso(),))
        ips, nets = set(), []
        for r in rows:
            if (r["scope"] or "").lower() == "range":
                try:
                    nets.append(ipaddress.ip_network(r["value"], strict=False))
                except ValueError:
                    pass
            else:
                ips.add(r["value"])
        self.ips, self.nets = ips, nets

    def contains(self, ip: str) -> bool:
        if ip in self.ips:
            return True
        if self.nets:
            try:
                a = ipaddress.ip_address(ip)
                return any(a in n for n in self.nets)
            except ValueError:
                pass
        return False


active_index = ActiveIndex()


# ---------------------------------------------------------------------------
# Converting LAPI JSON into rows
# ---------------------------------------------------------------------------
def _meta_dict(items) -> dict:
    return {m.get("key"): m.get("value") for m in (items or []) if m.get("key")}


def _alert_row(a: dict):
    src = a.get("source") or {}
    meta = _meta_dict(a.get("meta"))
    target = meta.get("target_fqdn")
    event_meta = []
    for ev in (a.get("events") or [])[:20]:
        em = _meta_dict(ev.get("meta"))
        event_meta.append(em)
        target = target or em.get("target_fqdn")
    # alert "context" values sometimes arrive JSON-encoded lists: '["jellyfin.example.com"]'
    if target and target.startswith("["):
        try:
            target = (json.loads(target) or [None])[0]
        except ValueError:
            pass
    ip = src.get("ip") or (src.get("value") if (src.get("scope") or "").lower() == "ip" else None)
    # CrowdSec usually enriches the source with country/ASN/coords; fill gaps from our own GeoIP db
    g = geoip.lookup(ip) if ip else {}
    return (
        a["id"], norm_ts(a.get("created_at")), norm_ts(a.get("start_at")), norm_ts(a.get("stop_at")),
        a.get("scenario"), a.get("message"), a.get("events_count"), a.get("machine_id"),
        int(bool(a.get("simulated"))), a.get("kind"),
        src.get("scope"), src.get("value"), ip,
        src.get("cn") or g.get("country"), src.get("as_number") or g.get("asn"), src.get("as_name") or g.get("as_name"),
        src.get("latitude") or g.get("lat"), src.get("longitude") or g.get("lon"),
        target, json.dumps({"meta": meta, "events": event_meta}),
    )


def _decision_rows(a: dict):
    created = norm_ts(a.get("created_at")) or now_iso()
    for d in a.get("decisions") or []:
        until = norm_ts(d.get("until"))
        if not until:  # older LAPI: only a remaining "duration" like "3h59m"
            dur = parse_go_duration(d.get("duration"))
            until = iso(utcnow() + dur) if dur is not None else created
        yield (
            d["id"], a["id"], d.get("origin"), d.get("type"), d.get("scope"), d.get("value"),
            d.get("scenario"), d.get("duration"), until, created, int(bool(d.get("simulated"))),
        )


def store_alerts(alerts: list[dict]):
    db.executemany(
        """INSERT INTO alerts(id,created_at,start_at,stop_at,scenario,message,events_count,machine_id,simulated,kind,
                              scope,value,ip,country,as_number,as_name,lat,lon,target_host,meta)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET events_count=excluded.events_count, stop_at=excluded.stop_at""",
        [_alert_row(a) for a in alerts],
    )
    db.executemany(
        """INSERT INTO decisions(id,alert_id,origin,type,scope,value,scenario,duration,until,created_at,simulated)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET until=excluded.until, duration=excluded.duration""",
        [row for a in alerts for row in _decision_rows(a)],
    )


def sync_once(first: bool):
    """One poll cycle. Runs in a worker thread."""
    last = db.get_kv("lapi_last_poll")
    if first and not last:
        since = settings.lapi_lookback
    else:
        # ask for everything since our last poll, plus a 2 minute overlap
        secs = 3600
        if last:
            secs = int((utcnow() - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds()) + 120
        since = f"{max(secs, 60)}s"
    started = now_iso()
    new_alerts = client.alerts(since=since)
    store_alerts(new_alerts)

    # Reconcile: what's *actually* active right now?
    active_alerts = client.alerts(has_active_decision="true")
    store_alerts(active_alerts)
    active_ids = {d["id"] for a in active_alerts for d in (a.get("decisions") or [])}
    now = now_iso()
    # decisions we think are active but LAPI no longer returns -> they were deleted/expired early
    stale = db.all("SELECT id FROM decisions WHERE until > ?", (now,))
    gone = [(now, r["id"]) for r in stale if r["id"] not in active_ids]
    db.executemany("UPDATE decisions SET until=? WHERE id=?", gone)

    db.set_kv("lapi_last_poll", started)
    active_index.reload()
    client.heartbeat()
    return len(new_alerts), len(active_ids), len(gone)


async def run():
    if not settings.lapi_url:
        status.status["lapi"]["info"]["note"] = "LAPI_URL not set"
        return
    status.status["lapi"]["enabled"] = True
    active_index.reload()
    first = True
    while True:
        try:
            n_new, n_active, n_gone = await asyncio.to_thread(sync_once, first)
            first = False
            status.ok("lapi", url=settings.lapi_url, machine=settings.lapi_machine_id,
                      last_batch=n_new, active_decisions=n_active, removed_early=n_gone)
        except Exception as e:
            log.warning("LAPI poll failed: %s", e)
            status.fail("lapi", e)
            client.token = None
        await asyncio.sleep(settings.lapi_poll_seconds)


# ---------------------------------------------------------------------------
# Write actions (only when ALLOW_WRITE=true)
# ---------------------------------------------------------------------------
def delete_decision(decision_id: int):
    res = client.request("DELETE", f"/v1/decisions/{decision_id}")
    db.execute("UPDATE decisions SET until=? WHERE id=?", (now_iso(), decision_id))
    active_index.reload()
    return res


def add_ban(ip: str, duration: str = "4h", reason: str = "manual ban from crowdsec-dash"):
    """Create a ban the same way `cscli decisions add` does: push an alert carrying a decision."""
    ipaddress.ip_address(ip)  # raises ValueError on bad input
    now = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    alert = {
        "scenario": reason,
        "scenario_hash": "",
        "scenario_version": "",
        "message": f"{reason}: ban {ip} for {duration}",
        "events_count": 1,
        "start_at": now,
        "stop_at": now,
        "capacity": 0,
        "leakspeed": "0",
        "simulated": False,
        "events": [],
        "source": {"scope": "Ip", "value": ip, "ip": ip},
        "decisions": [{
            "duration": duration, "origin": "cscli", "scenario": reason,
            "scope": "Ip", "type": "ban", "value": ip,
        }],
    }
    res = client.request("POST", "/v1/alerts", json=[alert])
    return res
