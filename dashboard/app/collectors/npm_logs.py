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

We remember how far we've read in each file (inode + byte offset + a fingerprint of
the first bytes) so a restart doesn't re-import everything, and we notice log rotation
(file shrank, or a new inode whose first bytes differ). The fingerprint matters on
Unraid: /mnt/user (shfs) can hand out new inode numbers after a reboot, and trusting
the inode alone would re-import - and double count - whole log files.

Query-string values that look like credentials (api_key=, token=, ...) are replaced
with REDACTED before storing, so the dashboard doesn't become a store of session tokens.
"""
import asyncio
import glob
import hashlib
import logging
import os
import re
from urllib.parse import unquote_plus

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
_REDACT = set(settings.npm_redact_params)


def redact_uri(uri: str) -> str:
    """'/Videos/1/stream?api_key=abc&Static=true' -> '/Videos/1/stream?api_key=REDACTED&Static=true'"""
    path, sep, query = uri.partition("?")
    if not sep or not _REDACT:
        return uri
    parts = []
    for item in query.split("&"):
        k, eq, _ = item.partition("=")
        parts.append(f"{k}=REDACTED" if eq and unquote_plus(k).lower() in _REDACT else item)
    return f"{path}?{'&'.join(parts)}"


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
        parse_nginx_time(g["time"]), host, g["method"], g["scheme"], redact_uri(g["uri"])[:2000], int(g["status"]),
        g["upstream"], client, length, g["ua"][:500], g["referer"][:500], g["sentto"],
        int(cloudflare.is_cloudflare_ip(client)), proxy_host_id, geo["country"], geo["lat"], geo["lon"],
    )


INSERT = (
    "INSERT INTO npm_requests(ts,host,method,scheme,path,status,upstream_status,client_ip,bytes,ua,referer,"
    "sent_to,via_cf,proxy_host_id,country,lat,lon) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
)


FP_BYTES = 256


def _fingerprint(path: str, size: int) -> str:
    """'<n>-<sha1 of the first n bytes>' - identifies a log file independently of its inode."""
    n = min(FP_BYTES, size)
    with open(path, "rb") as f:
        return f"{n}-{hashlib.sha1(f.read(n)).hexdigest()}"


def _same_file(path: str, fp: str | None, size: int) -> bool:
    """Does the file at `path` still start with the bytes we fingerprinted?"""
    if not fp:
        return False  # state saved by an older version: no fingerprint, trust the inode
    n_str, _, digest = fp.partition("-")
    n = int(n_str)
    if n == 0 or size < n:
        return False
    with open(path, "rb") as f:
        return hashlib.sha1(f.read(n)).hexdigest() == digest


def read_new(path: str) -> tuple[int, int]:
    """Read whatever was appended to `path` since last time. Returns (parsed, unparsed)."""
    st = os.stat(path)
    key = f"npm_offset:{path}"
    saved = db.get_kv(key)
    inode, offset, fp = None, None, None
    if saved:
        parts = saved.split(":", 2)  # "inode:offset" (old) or "inode:offset:fingerprint"
        inode, offset = int(parts[0]), int(parts[1])
        fp = parts[2] if len(parts) > 2 else None
    skip_partial = False
    if inode is None:
        # first time we see this file: only backfill the last NPM_BACKFILL_BYTES
        offset = max(0, st.st_size - settings.npm_backfill_bytes)
        skip_partial = offset > 0
    elif offset > st.st_size:
        offset = 0  # truncated (copytruncate rotation): start from the top
    elif inode != st.st_ino and not _same_file(path, fp, st.st_size):
        offset = 0  # rotated: a different file now has this name
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
    db.set_kv(key, f"{st.st_ino}:{new_offset}:{_fingerprint(path, st.st_size)}")
    return len(rows), bad


async def run():
    status.status["npm"]["enabled"] = True
    pattern = os.path.join(settings.npm_log_dir, settings.npm_log_glob)
    total, total_bad = 0, 0
    last_errors: list[str] = []
    while True:
        try:
            files = sorted(glob.glob(pattern))
            if not files:
                status.fail("npm", f"no files match {pattern}")
            else:
                errors = []
                for path in files:  # one unreadable file mustn't stop the others
                    try:
                        n, bad = await asyncio.to_thread(read_new, path)
                    except Exception as e:
                        errors.append(f"{os.path.basename(path)}: {e}")
                        continue
                    total += n
                    total_bad += bad
                status.ok("npm", files=len(files), pattern=pattern, lines_imported=total, lines_unparsed=total_bad)
                if errors:
                    status.fail("npm", "; ".join(errors[:3]) + (f" (+{len(errors) - 3} more)" if len(errors) > 3 else ""))
                    if errors != last_errors:  # don't repeat the same warning every 2 seconds
                        log.warning("npm tail errors: %s", errors)
                last_errors = errors
        except Exception as e:
            log.warning("npm tail error: %s", e)
            status.fail("npm", e)
        await asyncio.sleep(2)
