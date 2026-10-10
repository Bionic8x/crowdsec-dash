"""
SQLite storage.

One database file holds everything the collectors gather. Every timestamp is
stored as an ISO-8601 UTC string ("2026-10-10T18:16:09Z") so that string
comparison == time comparison, and SQLite's strftime('%s', ts) can bucket them.

We use one shared connection guarded by a lock. The collectors write small
batches and the API reads, so this is plenty fast for a home lab.
"""
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from .config import settings

SCHEMA = """
-- CrowdSec alerts (one per scenario overflow), mirrored from LAPI
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY,      -- LAPI alert id
    created_at    TEXT,
    start_at      TEXT,
    stop_at       TEXT,
    scenario      TEXT,
    message       TEXT,
    events_count  INTEGER,
    machine_id    TEXT,
    simulated     INTEGER,
    kind          TEXT,
    scope         TEXT,
    value         TEXT,
    ip            TEXT,
    country       TEXT,
    as_number     TEXT,
    as_name       TEXT,
    lat           REAL,
    lon           REAL,
    target_host   TEXT,                     -- target_fqdn from the events (which site was hit)
    meta          TEXT                      -- raw JSON of meta + a few event metas
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip);

-- CrowdSec decisions (bans). Each belongs to an alert.
CREATE TABLE IF NOT EXISTS decisions (
    id          INTEGER PRIMARY KEY,        -- LAPI decision id
    alert_id    INTEGER,
    origin      TEXT,
    type        TEXT,
    scope       TEXT,
    value       TEXT,
    scenario    TEXT,
    duration    TEXT,
    until       TEXT,                       -- when it expires (UTC ISO)
    created_at  TEXT,
    simulated   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_decisions_value ON decisions(value);
CREATE INDEX IF NOT EXISTS idx_decisions_until ON decisions(until);

-- One row per NPM access-log line
CREATE TABLE IF NOT EXISTS npm_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT,
    host            TEXT,
    method          TEXT,
    scheme          TEXT,
    path            TEXT,
    status          INTEGER,
    upstream_status TEXT,
    client_ip       TEXT,
    bytes           INTEGER,
    ua              TEXT,
    referer         TEXT,
    sent_to         TEXT,
    via_cf          INTEGER,                -- client_ip is a Cloudflare edge IP (real IP not restored)
    proxy_host_id   INTEGER,
    country         TEXT,
    lat             REAL,
    lon             REAL
);
CREATE INDEX IF NOT EXISTS idx_npm_ts ON npm_requests(ts);
CREATE INDEX IF NOT EXISTS idx_npm_ip ON npm_requests(client_ip);
CREATE INDEX IF NOT EXISTS idx_npm_host ON npm_requests(host, ts);

-- One row per OPNsense filterlog line we kept
CREATE TABLE IF NOT EXISTS fw_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT,
    action    TEXT,
    iface     TEXT,
    dir       TEXT,
    proto     TEXT,
    src_ip    TEXT,
    src_port  INTEGER,
    dst_ip    TEXT,
    dst_port  INTEGER,
    label     TEXT,                         -- rule label / hash from filterlog
    crowdsec  INTEGER,                      -- 1 if src had an active CrowdSec decision or rule label matched
    country   TEXT,
    lat       REAL,
    lon       REAL
);
CREATE INDEX IF NOT EXISTS idx_fw_ts ON fw_events(ts);
CREATE INDEX IF NOT EXISTS idx_fw_src ON fw_events(src_ip);

-- DNS records from Cloudflare: is a hostname proxied (orange cloud) or DNS-only?
CREATE TABLE IF NOT EXISTS cf_hosts (
    name        TEXT PRIMARY KEY,
    zone        TEXT,
    record_type TEXT,
    content     TEXT,
    proxied     INTEGER,
    updated_at  TEXT
);

-- Cloudflare security events (optional)
CREATE TABLE IF NOT EXISTS cf_events (
    ray      TEXT PRIMARY KEY,
    ts       TEXT,
    action   TEXT,
    source   TEXT,
    ip       TEXT,
    country  TEXT,
    host     TEXT,
    path     TEXT,
    method   TEXT,
    ua       TEXT,
    rule_id  TEXT
);
CREATE INDEX IF NOT EXISTS idx_cf_ts ON cf_events(ts);
CREATE INDEX IF NOT EXISTS idx_cf_ip ON cf_events(ip);

-- Small key/value store for collector state (file offsets, last poll time...)
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """datetime -> '2026-10-10T18:16:09Z' (always UTC)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return iso(utcnow())


def ago_iso(**kwargs) -> str:
    return iso(utcnow() - timedelta(**kwargs))


class DB:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.lock = threading.Lock()

    # -- reads ------------------------------------------------------------
    def all(self, sql: str, params=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params=()) -> dict | None:
        with self.lock:
            row = self.conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def scalar(self, sql: str, params=()):
        with self.lock:
            row = self.conn.execute(sql, params).fetchone()
            return row[0] if row else None

    # -- writes -----------------------------------------------------------
    def execute(self, sql: str, params=()):
        with self.lock:
            return self.conn.execute(sql, params)

    def executemany(self, sql: str, rows):
        rows = list(rows)
        if not rows:
            return
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.executemany(sql, rows)
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    # -- kv helpers ---------------------------------------------------------
    def get_kv(self, k: str, default=None):
        v = self.scalar("SELECT v FROM kv WHERE k=?", (k,))
        return v if v is not None else default

    def set_kv(self, k: str, v: str):
        self.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

    # -- housekeeping -------------------------------------------------------
    def prune(self, days: int):
        cutoff = ago_iso(days=days)
        with self.lock:
            self.conn.execute("DELETE FROM npm_requests WHERE ts < ?", (cutoff,))
            self.conn.execute("DELETE FROM fw_events WHERE ts < ?", (cutoff,))
            self.conn.execute("DELETE FROM cf_events WHERE ts < ?", (cutoff,))
            # keep alerts/decisions a bit longer - they're small and useful history
            long_cutoff = ago_iso(days=days * 4)
            self.conn.execute("DELETE FROM decisions WHERE until < ? ", (long_cutoff,))
            self.conn.execute("DELETE FROM alerts WHERE created_at < ?", (long_cutoff,))


db = DB(settings.db_path)
