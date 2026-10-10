"""
IP -> country / city / coordinates / ASN, using the free DB-IP "Lite" databases.

DB-IP Lite is CC BY 4.0 and needs no account: the files are published monthly at
  https://download.db-ip.com/free/dbip-city-lite-YYYY-MM.mmdb.gz
  https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.mmdb.gz
We download them on startup if missing or older than ~35 days.
(Attribution "IP geolocation by DB-IP" is shown in the UI footer, as the license asks.)
"""
import gzip
import ipaddress
import logging
import os
import shutil
import time
from datetime import date
from functools import lru_cache

import requests

from . import status
from .config import settings

log = logging.getLogger("geoip")

try:
    import maxminddb  # reads .mmdb files
except ImportError:  # pragma: no cover - lets the app run (without geo) if the lib is missing
    maxminddb = None

_city = None
_asn = None
_private = [ipaddress.ip_network(c) for c in settings.lan_cidrs]

FILES = {"city": "dbip-city-lite.mmdb", "asn": "dbip-asn-lite.mmdb"}


def _months_to_try():
    today = date.today()
    y, m = today.year, today.month
    out = []
    for _ in range(3):  # this month, then the previous two (new month's file may not be out yet)
        out.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return out


def _download(kind: str, dest: str):
    for month in _months_to_try():
        url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
        try:
            r = requests.get(url, stream=True, timeout=60)
            if r.status_code != 200:
                continue
            tmp = dest + ".tmp"
            with gzip.GzipFile(fileobj=r.raw) as gz, open(tmp, "wb") as out:
                shutil.copyfileobj(gz, out)
            os.replace(tmp, dest)
            log.info("downloaded %s", url)
            return True
        except Exception as e:  # network errors, bad gzip...
            log.warning("geoip download %s failed: %s", url, e)
    return False


def init():
    """Load (and if needed download) the databases. Safe to call again to reload."""
    global _city, _asn
    st = status.status["geoip"]
    st["enabled"] = True
    if maxminddb is None:
        status.fail("geoip", "python package 'maxminddb' not installed")
        return
    os.makedirs(settings.geoip_dir, exist_ok=True)
    for kind, fname in FILES.items():
        path = os.path.join(settings.geoip_dir, fname)
        stale = not os.path.exists(path) or (time.time() - os.path.getmtime(path)) > 35 * 86400
        if stale and settings.geoip_auto_download:
            _download(kind, path)
    try:
        cpath = os.path.join(settings.geoip_dir, FILES["city"])
        apath = os.path.join(settings.geoip_dir, FILES["asn"])
        _city = maxminddb.open_database(cpath) if os.path.exists(cpath) else None
        _asn = maxminddb.open_database(apath) if os.path.exists(apath) else None
        lookup.cache_clear()
        if _city:
            status.ok("geoip", city_db=cpath, asn_db=apath if _asn else None)
        else:
            status.fail("geoip", f"no city database in {settings.geoip_dir}")
    except Exception as e:
        status.fail("geoip", e)


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in n for n in _private)


@lru_cache(maxsize=50_000)
def lookup(ip: str) -> dict:
    """Return {'country','city','lat','lon','asn','as_name'} (values may be None)."""
    empty = {"country": None, "city": None, "lat": None, "lon": None, "asn": None, "as_name": None}
    if not ip or is_private(ip):
        return empty
    out = dict(empty)
    try:
        if _city:
            rec = _city.get(ip) or {}
            out["country"] = (rec.get("country") or {}).get("iso_code")
            out["city"] = ((rec.get("city") or {}).get("names") or {}).get("en")
            loc = rec.get("location") or {}
            out["lat"], out["lon"] = loc.get("latitude"), loc.get("longitude")
        if _asn:
            rec = _asn.get(ip) or {}
            out["asn"] = rec.get("autonomous_system_number")
            out["as_name"] = rec.get("autonomous_system_organization")
    except Exception:
        pass
    return out
