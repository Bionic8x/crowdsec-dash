"""
Nginx Proxy Manager access-log tailer.

NPM writes one log per proxy host: /data/logs/proxy-host-<N>_access.log
Each line looks like this (a failed Jellyfin login):

  [10/Oct/2026:14:20:04 -0400] - 401 401 - POST https jellyfin.example.com "/Users/authenticatebyname"
  [Client 203.0.113.50] [Length 25] [Gzip -] [Sent-to 192.168.1.10] "Mozilla/5.0 (...)" "-"

i.e. NPM's nginx log_format "proxy":
  [$time_local] $upstream_cache_status $upstream_status $status - $request_method $scheme $host
  "$request_uri" [Client $remote_addr] [Length $body_bytes_sent] [Gzip $gzip_ratio]
  [Sent-to $server] "$http_user_agent" "$http_referer"

We remember how far we've read in each file (inode + byte offset) so a restart
doesn't re-import everything, and we notice log rotation (new inode / file shrank).
"""
import asyncio
import glob
import logging
import os
import re

from .. import geoip, status
from ..config import settings
from ..db import db
from ..timeutil import parse_nginx_time
from . import cloudflare

log = logging.getLogger("npm")

LINE = re.compile(
    r'^\[(?P<time>[^\]]+)\]\s+'
    r'(?:(?P<cache>\S+)\s+(?P<upstream>\S+)\s+)?'          # missing in the fallback/default-host format
    r'(?P<status>\d{3})\s+-\s+'
    r'(?P<method>\S+)\s+(?P<scheme>\S+)\s+(?P<host>\S+)\s+'
    r'"(?P<uri>(?:[^"\\]|\\.)*)"\s+'
    r'\[Client\s+(?P<client>[^\]]+)\]\s+'
    r'\[Length\s+(?P<length>[^\]]+)\]\s+'
    r'\[Gzip\s+(?P<gzip>[^\]]+)\]\s+'
    r'(?:\[Sent-to\s+(?P<sentto>[^\]]+)\]\s+)?'
    r'"(?P<ua>(?:[^"\\]|\\.)*)"\s+"(?P<referer>(?:[^"\\]|\\.)*)"'
)
HOST_ID = re.compile(r"proxy-host-(\d+)_")


def parse_line(line: str, proxy_host_id=None):
    m = LINE.match(line.strip())
    if not m:
        return None
    g = m.groupdict()
    client = g["client"].strip()
    host = g["host"].lower()
    geo = geoip.lookup(client)
    try:
        length = int(g["length"])
    except ValueError:
        length = 0
    return (
        parse_nginx_time(g["time"]), host, g["method"], g["scheme"], g["uri"][:2000], int(g["status"]),
        g["upstream"], client, length, g["ua"][:500], g["referer"][:500], g["sentto"],
        int(cloudflare.is_cloudflare_ip(client)), proxy_host_id, geo["country"], geo["lat"], geo["lon"],
    )


INSERT = (
    "INSERT INTO npm_requests(ts,host,method,scheme,path,status,upstream_status,client_ip,bytes,ua,referer,"
    "sent_to,via_cf,proxy_host_id,country,lat,lon) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
)


def read_new(path: str) -> tuple[int, int]:
    """Read whatever was appended to `path` since last time. Returns (parsed, unparsed)."""
    st = os.stat(path)
    key = f"npm_offset:{path}"
    saved = db.get_kv(key)
    inode, offset = (None, None)
    if saved:
        inode, offset = saved.split(":")
        inode, offset = int(inode), int(offset)
    skip_partial = False
    if inode is None:
        # first time we see this file: only backfill the last NPM_BACKFILL_BYTES
        offset = max(0, st.st_size - settings.npm_backfill_bytes)
        skip_partial = offset > 0
    elif inode != st.st_ino or offset > st.st_size:
        offset = 0  # log was rotated (new inode) or truncated: start from the top
    if offset == st.st_size:
        return 0, 0
    m = HOST_ID.search(os.path.basename(path))
    host_id = int(m.group(1)) if m else None
    rows, bad = [], 0
    with open(path, "rb") as f:
        f.seek(offset)
        if skip_partial:
            f.readline()  # we jumped into the middle of a line - skip the partial one
        start = f.tell()
        chunk = f.read(8_000_000)
        last_nl = chunk.rfind(b"\n")
        if last_nl < 0:
            return 0, 0  # no complete line yet
        complete = chunk[: last_nl + 1]
        for raw in complete.decode("utf-8", "replace").splitlines():
            if not raw.strip():
                continue
            row = parse_line(raw, host_id)
            if row is None:
                bad += 1
                continue
            if row[1] in settings.npm_ignore_hosts:
                continue
            rows.append(row)
        new_offset = start + len(complete)
    db.executemany(INSERT, rows)
    db.set_kv(key, f"{st.st_ino}:{new_offset}")
    return len(rows), bad


async def run():
    status.status["npm"]["enabled"] = True
    pattern = os.path.join(settings.npm_log_dir, settings.npm_log_glob)
    total, total_bad = 0, 0
    while True:
        try:
            files = sorted(glob.glob(pattern))
            if not files:
                status.fail("npm", f"no files match {pattern}")
            else:
                for path in files:
                    n, bad = await asyncio.to_thread(read_new, path)
                    total += n
                    total_bad += bad
                status.ok("npm", files=len(files), pattern=pattern, lines_imported=total, lines_unparsed=total_bad)
        except Exception as e:
            log.warning("npm tail error: %s", e)
            status.fail("npm", e)
        await asyncio.sleep(2)
