"""
Cloudflare integration (optional - everything else works without it).

Three things live here:

1. Cloudflare's edge IP ranges. If NPM logs show one of these as the client,
   the request came *through* Cloudflare and NPM didn't restore the real visitor
   IP. CrowdSec would then be judging (and banning!) Cloudflare itself.
   This works with no API token.

2. DNS sync (needs CF_API_TOKEN with Zone:Read + DNS:Read). For every hostname we
   learn whether it's proxied (orange cloud) or DNS-only (grey cloud). That
   matters because your OPNsense firewall bouncer can only block traffic that
   connects to you directly:
     - DNS-only  -> attacker connects to your WAN IP -> firewall ban works
     - proxied   -> attacker connects to Cloudflare; Cloudflare connects to you.
                    Banning the attacker's IP on OPNsense does nothing.

3. Security events (optional, CF_FETCH_EVENTS=true, needs Zone > Analytics:Read):
   what Cloudflare's own WAF / bot rules blocked before it reached you.
"""
import asyncio
import fnmatch
import ipaddress
import logging
from datetime import timedelta

import requests

from .. import status
from ..config import settings
from ..db import db, iso, now_iso, utcnow
from ..timeutil import norm_ts

log = logging.getLogger("cloudflare")
API = "https://api.cloudflare.com/client/v4"

# Published at https://www.cloudflare.com/ips/ - refreshed at startup when reachable.
CF_RANGES_DEFAULT = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
_cf_nets = [ipaddress.ip_network(c) for c in CF_RANGES_DEFAULT]

# hostname -> proxied (True/False). Loaded from the cf_hosts table.
_host_cache: dict[str, bool] = {}


def is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _cf_nets)


def cf_ranges() -> list[str]:
    return [str(n) for n in _cf_nets]


def refresh_ranges():
    global _cf_nets
    try:
        r = requests.get(f"{API}/ips", timeout=15)
        r.raise_for_status()
        res = r.json()["result"]
        nets = [ipaddress.ip_network(c) for c in res["ipv4_cidrs"] + res["ipv6_cidrs"]]
        if nets:
            _cf_nets = nets
    except Exception as e:
        log.info("could not refresh Cloudflare IP list (using built-in list): %s", e)


def host_proxied(host: str):
    """True = proxied, False = DNS-only, None = not a Cloudflare-managed name."""
    if not host:
        return None
    host = host.lower()
    if host in _host_cache:
        return _host_cache[host]
    for name, proxied in _host_cache.items():  # wildcard records like *.example.com
        if name.startswith("*.") and fnmatch.fnmatch(host, name):
            return proxied
    return None


def load_host_cache():
    global _host_cache
    _host_cache = {r["name"]: bool(r["proxied"]) for r in db.all("SELECT name, proxied FROM cf_hosts")}


# ---------------------------------------------------------------------------
# API calls (run in a thread; requests is blocking)
# ---------------------------------------------------------------------------
def _get(path: str, params=None):
    r = requests.get(
        f"{API}{path}",
        headers={"Authorization": f"Bearer {settings.cf_api_token}"},
        params=params or {},
        timeout=30,
    )
    data = r.json()
    if not data.get("success", False):
        raise RuntimeError(f"Cloudflare API {path}: {data.get('errors')}")
    return data


def _paged(path: str, per_page: int = 50):
    page = 1
    while True:
        p = {"page": page, "per_page": per_page}
        data = _get(path, p)
        yield from data["result"]
        info = data.get("result_info") or {}
        if page >= (info.get("total_pages") or 1):
            break
        page += 1


def sync_dns():
    zones = list(_paged("/zones"))
    rows = []
    for z in zones:
        for rec in _paged(f"/zones/{z['id']}/dns_records", per_page=100):
            if rec["type"] not in ("A", "AAAA", "CNAME"):
                continue
            rows.append((rec["name"].lower(), z["name"], rec["type"], rec["content"], int(bool(rec.get("proxied"))), now_iso()))
    db.execute("DELETE FROM cf_hosts")
    db.executemany(
        "INSERT OR REPLACE INTO cf_hosts(name,zone,record_type,content,proxied,updated_at) VALUES(?,?,?,?,?,?)", rows
    )
    load_host_cache()
    return zones, len(rows)


GQL = """
query ($zone: string, $since: Time) {
  viewer {
    zones(filter: {zoneTag: $zone}) {
      firewallEventsAdaptive(filter: {datetime_geq: $since}, limit: 1000, orderBy: [datetime_ASC]) {
        datetime action source clientIP clientCountryName clientRequestHTTPHost
        clientRequestPath clientRequestHTTPMethodName userAgent ruleId rayName
      }
    }
  }
}
"""


def fetch_events(zones):
    """Each zone keeps its own cursor: a query returns at most 1000 events, so one busy zone
    may still be catching up while another is current. The cursor is inclusive (datetime_geq)
    and rows are de-duplicated by ray id, so events sharing the cursor's second aren't lost."""
    default_since = db.get_kv("cf_events_since") or iso(utcnow() - timedelta(hours=6))  # pre-per-zone state
    total = 0
    for z in zones:
        key = f"cf_events_since:{z['id']}"
        since = db.get_kv(key) or default_since
        newest = since
        r = requests.post(
            f"{API}/graphql",
            headers={"Authorization": f"Bearer {settings.cf_api_token}"},
            json={"query": GQL, "variables": {"zone": z["id"], "since": since}},
            timeout=30,
        )
        data = r.json()
        if data.get("errors"):
            raise RuntimeError(f"GraphQL ({z['name']}): {data['errors'][0].get('message')}")
        zl = (data.get("data") or {}).get("viewer", {}).get("zones") or []
        events = zl[0]["firewallEventsAdaptive"] if zl else []
        rows = []
        for e in events:
            ts = norm_ts(e["datetime"]) or now_iso()
            rows.append((
                e["rayName"], ts, e["action"], e["source"], e["clientIP"],
                e["clientCountryName"], e["clientRequestHTTPHost"], e["clientRequestPath"],
                e["clientRequestHTTPMethodName"], e["userAgent"], e["ruleId"],
            ))
            newest = max(newest, ts)
        db.executemany(
            "INSERT OR IGNORE INTO cf_events(ray,ts,action,source,ip,country,host,path,method,ua,rule_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows,
        )
        if len(events) >= 1000:
            log.info("cloudflare: %s has more than 1000 new events; the rest arrive on the next polls", z["name"])
        db.set_kv(key, newest)
        total += len(rows)
    return total


async def run():
    load_host_cache()
    await asyncio.to_thread(refresh_ranges)
    if not settings.cf_api_token:
        status.status["cloudflare"]["info"]["note"] = "No CF_API_TOKEN - only edge-IP detection is active"
        return
    status.status["cloudflare"]["enabled"] = True
    zones = []
    last_dns = 0.0
    loop = asyncio.get_running_loop()
    while True:
        try:
            if not zones or loop.time() - last_dns > settings.cf_sync_minutes * 60:
                zones, n = await asyncio.to_thread(sync_dns)
                last_dns = loop.time()
                status.ok("cloudflare", zones=[z["name"] for z in zones], dns_records=n)
            if settings.cf_fetch_events:
                n = await asyncio.to_thread(fetch_events, zones)
                status.ok("cloudflare", last_events_batch=n)
        except Exception as e:
            log.warning("cloudflare: %s", e)
            status.fail("cloudflare", e)
        await asyncio.sleep(settings.cf_events_poll_minutes * 60 if settings.cf_fetch_events else settings.cf_sync_minutes * 60)
