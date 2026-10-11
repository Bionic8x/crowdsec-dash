"""
All the SQL behind the dashboard's API, kept apart from the web layer so it's
easy to read (and to try in `sqlite3 /data/dash.db` yourself).
"""
from . import geoip
from .collectors import cloudflare
from .db import ago_iso, db, now_iso

RANGES = {  # range -> (timedelta kwargs, bucket seconds)
    "1h": ({"hours": 1}, 300),
    "6h": ({"hours": 6}, 900),
    "24h": ({"hours": 24}, 3600),
    "7d": ({"days": 7}, 6 * 3600),
    "30d": ({"days": 30}, 24 * 3600),
}


def window(rng: str):
    kw, bucket = RANGES.get(rng, RANGES["24h"])
    return ago_iso(**kw), bucket


def _bucket_expr(col: str, bucket: int) -> str:
    return f"(CAST(strftime('%s', {col}) AS INTEGER) / {bucket}) * {bucket}"


# ---------------------------------------------------------------------------
def overview(rng: str) -> dict:
    since, bucket = window(rng)
    now = now_iso()
    k = {}
    k["active_decisions"] = db.scalar(
        "SELECT COUNT(DISTINCT value) FROM decisions WHERE until > ? AND simulated = 0", (now,))
    k["alerts"] = db.scalar("SELECT COUNT(*) FROM alerts WHERE created_at >= ?", (since,))
    r = db.one(
        """SELECT COUNT(*) n,
                  SUM(status BETWEEN 400 AND 499) e4, SUM(status >= 500) e5,
                  SUM(status IN (401,403)) auth, COUNT(DISTINCT client_ip) ips,
                  SUM(via_cf) via_cf
           FROM npm_requests WHERE ts >= ?""", (since,))
    k.update(requests=r["n"] or 0, req_4xx=r["e4"] or 0, req_5xx=r["e5"] or 0,
             auth_fail=r["auth"] or 0, unique_ips=r["ips"] or 0, via_cf=r["via_cf"] or 0)
    r = db.one("SELECT COUNT(*) n, SUM(crowdsec) cs, COUNT(DISTINCT src_ip) ips FROM fw_events WHERE ts >= ?", (since,))
    k.update(fw_drops=r["n"] or 0, fw_crowdsec=r["cs"] or 0, fw_ips=r["ips"] or 0)
    k["cf_events"] = db.scalar("SELECT COUNT(*) FROM cf_events WHERE ts >= ?", (since,))

    traffic = db.all(
        f"""SELECT {_bucket_expr('ts', bucket)} t,
                   SUM(status < 400) ok, SUM(status BETWEEN 400 AND 499) e4, SUM(status >= 500) e5
            FROM npm_requests WHERE ts >= ? GROUP BY t ORDER BY t""", (since,))
    drops = db.all(
        f"""SELECT {_bucket_expr('ts', bucket)} t, SUM(crowdsec) cs, SUM(1 - crowdsec) other
            FROM fw_events WHERE ts >= ? GROUP BY t ORDER BY t""", (since,))
    alerts_tl = db.all(
        f"""SELECT {_bucket_expr('created_at', bucket)} t, COUNT(*) n
            FROM alerts WHERE created_at >= ? GROUP BY t ORDER BY t""", (since,))

    top_scenarios = db.all(
        """SELECT scenario, COUNT(*) n FROM alerts WHERE created_at >= ?
           GROUP BY scenario ORDER BY n DESC LIMIT 8""", (since,))
    top_hosts = db.all(
        """SELECT host, COUNT(*) n, SUM(status >= 400) err FROM npm_requests WHERE ts >= ?
           GROUP BY host ORDER BY n DESC LIMIT 8""", (since,))
    for h in top_hosts:
        h["cf_proxied"] = cloudflare.host_proxied(h["host"])
    return {
        "range": rng, "since": since, "bucket": bucket, "kpis": k,
        "timeline": {"traffic": traffic, "drops": drops, "alerts": alerts_tl},
        "top_scenarios": top_scenarios, "top_hosts": top_hosts,
        "top_sources": top_sources(since),
    }


def top_sources(since: str, limit: int = 10) -> list[dict]:
    """IPs that look most hostile: alerts, firewall drops and failed requests combined."""
    rows = db.all(
        """
        WITH a AS (SELECT ip, COUNT(*) alerts FROM alerts WHERE created_at >= :s AND ip IS NOT NULL GROUP BY ip),
             f AS (SELECT src_ip ip, COUNT(*) drops FROM fw_events WHERE ts >= :s GROUP BY src_ip),
             n AS (SELECT client_ip ip, SUM(status >= 400) errs, COUNT(*) reqs
                   FROM npm_requests WHERE ts >= :s GROUP BY client_ip),
             ips AS (SELECT ip FROM a UNION SELECT ip FROM f UNION SELECT ip FROM n WHERE errs > 0)
        SELECT ips.ip, COALESCE(a.alerts,0) alerts, COALESCE(f.drops,0) drops,
               COALESCE(n.errs,0) errs, COALESCE(n.reqs,0) reqs,
               COALESCE(a.alerts,0) * 50 + COALESCE(f.drops,0) + COALESCE(n.errs,0) * 2 score
        FROM ips LEFT JOIN a ON a.ip = ips.ip LEFT JOIN f ON f.ip = ips.ip LEFT JOIN n ON n.ip = ips.ip
        ORDER BY score DESC LIMIT :lim
        """, {"s": since, "lim": limit})
    now = now_iso()
    banned = {r["value"] for r in db.all("SELECT value FROM decisions WHERE until > ?", (now,))}
    for r in rows:
        g = geoip.lookup(r["ip"])
        r["country"], r["as_name"] = g["country"], g["as_name"]
        r["banned"] = r["ip"] in banned
        r["cloudflare_edge"] = cloudflare.is_cloudflare_ip(r["ip"])
    return rows


def geo_points(rng: str, layer: str) -> dict:
    """Points for the world map. layer = 'traffic' (NPM clients) or 'threats' (alerts + firewall drops)."""
    since, _ = window(rng)
    if layer == "traffic":
        pts = db.all(
            """SELECT ROUND(lat,1) lat, ROUND(lon,1) lon, country, COUNT(*) n, COUNT(DISTINCT client_ip) ips,
                      SUM(status >= 400) err
               FROM npm_requests WHERE ts >= ? AND lat IS NOT NULL AND via_cf = 0
               GROUP BY ROUND(lat,1), ROUND(lon,1) ORDER BY n DESC LIMIT 2000""", (since,))
        countries = db.all(
            """SELECT country, COUNT(*) n FROM npm_requests WHERE ts >= ? AND country IS NOT NULL AND via_cf = 0
               GROUP BY country ORDER BY n DESC""", (since,))
    else:
        pts = db.all(
            """SELECT ROUND(lat,1) lat, ROUND(lon,1) lon, country, COUNT(*) n, COUNT(DISTINCT ip) ips, 0 err FROM (
                   SELECT lat, lon, country, src_ip ip FROM fw_events WHERE ts >= :s AND lat IS NOT NULL
                   UNION ALL
                   SELECT lat, lon, country, ip FROM alerts WHERE created_at >= :s AND lat IS NOT NULL
               ) GROUP BY ROUND(lat,1), ROUND(lon,1) ORDER BY n DESC LIMIT 2000""", {"s": since})
        countries = db.all(
            """SELECT country, COUNT(*) n FROM (
                   SELECT country FROM fw_events WHERE ts >= :s AND country IS NOT NULL
                   UNION ALL SELECT country FROM alerts WHERE created_at >= :s AND country IS NOT NULL
               ) GROUP BY country ORDER BY n DESC""", {"s": since})
    return {"layer": layer, "points": pts, "countries": countries}


# A 403 that NPM produced itself (no upstream answered): the npm-bouncer (or an NPM access list)
# stopped the request before it reached the app.
_BLOCKED_AT_NPM = "(n.status = 403 AND COALESCE(n.upstream_status, '-') = '-')"


# ---------------------------------------------------------------------------
def decisions(state: str, q: str, limit: int) -> list[dict]:
    now = now_iso()
    where, params = [], {"now": now, "lim": limit}
    if state == "active":
        where.append("d.until > :now")
    elif state == "expired":
        where.append("d.until <= :now")
    if q:
        where.append("(d.value LIKE :q OR d.scenario LIKE :q OR a.country LIKE :q OR a.as_name LIKE :q OR d.origin LIKE :q)")
        params["q"] = f"%{q}%"
    sql = f"""
        SELECT d.*, a.country, a.as_name, a.target_host, a.machine_id,
               (d.until > :now) active,
               (SELECT COUNT(*) FROM fw_events f WHERE f.src_ip = d.value AND f.ts >= d.created_at
                    AND (d.until > :now OR f.ts <= d.until)) fw_hits,
               (SELECT COUNT(*) FROM npm_requests n WHERE n.client_ip = d.value AND n.ts > d.created_at
                    AND (d.until > :now OR n.ts <= d.until) AND NOT {_BLOCKED_AT_NPM}) npm_after,
               (SELECT COUNT(*) FROM npm_requests n WHERE n.client_ip = d.value AND n.ts > d.created_at
                    AND (d.until > :now OR n.ts <= d.until) AND {_BLOCKED_AT_NPM}) npm_blocked
        FROM decisions d LEFT JOIN alerts a ON a.id = d.alert_id
        {'WHERE ' + ' AND '.join(where) if where else ''}
        ORDER BY d.created_at DESC LIMIT :lim"""
    rows = db.all(sql, params)
    for r in rows:
        if not r["country"]:
            r["country"] = geoip.lookup(r["value"])["country"]
        r["host_proxied"] = cloudflare.host_proxied(r["target_host"])
    return rows


def alerts(q: str, limit: int) -> list[dict]:
    params = {"lim": limit}
    where = ""
    if q:
        where = "WHERE ip LIKE :q OR scenario LIKE :q OR country LIKE :q OR as_name LIKE :q OR target_host LIKE :q OR machine_id LIKE :q"
        params["q"] = f"%{q}%"
    rows = db.all(
        f"""SELECT id, created_at, scenario, message, events_count, machine_id, simulated, kind, scope, value, ip,
                   country, as_name, target_host,
                   (SELECT COUNT(*) FROM decisions d WHERE d.alert_id = alerts.id) n_decisions
            FROM alerts {where} ORDER BY created_at DESC LIMIT :lim""", params)
    return rows


def requests(host, status_f, ip, q, limit, before_id) -> list[dict]:
    where, params = [], []
    if host:
        where.append("host = ?"); params.append(host)
    if ip:
        where.append("client_ip = ?"); params.append(ip)
    if status_f:
        if len(status_f) == 3 and status_f.endswith("xx") and status_f[0] in "12345":
            lo = int(status_f[0]) * 100
            where.append("status BETWEEN ? AND ?"); params += [lo, lo + 99]
        elif status_f == "auth":
            where.append("status IN (401,403)")
        elif status_f.isdigit():
            where.append("status = ?"); params.append(int(status_f))
    if q:
        where.append("(path LIKE ? OR ua LIKE ?)"); params += [f"%{q}%", f"%{q}%"]
    if before_id:
        where.append("id < ?"); params.append(before_id)
    params.append(limit)
    return db.all(
        f"""SELECT id, ts, host, method, path, status, client_ip, bytes, ua, via_cf, country, sent_to
            FROM npm_requests {'WHERE ' + ' AND '.join(where) if where else ''}
            ORDER BY id DESC LIMIT ?""", params)


def firewall(ip, crowdsec_only, port, limit, before_id) -> list[dict]:
    where, params = [], []
    if ip:
        where.append("src_ip = ?"); params.append(ip)
    if crowdsec_only:
        where.append("crowdsec = 1")
    if port is not None:
        where.append("dst_port = ?"); params.append(port)
    if before_id:
        where.append("id < ?"); params.append(before_id)
    params.append(limit)
    return db.all(
        f"""SELECT * FROM fw_events {'WHERE ' + ' AND '.join(where) if where else ''}
            ORDER BY id DESC LIMIT ?""", params)


def firewall_summary(rng: str) -> dict:
    since, _ = window(rng)
    ports = db.all(
        """SELECT dst_port port, proto, COUNT(*) n, COUNT(DISTINCT src_ip) ips FROM fw_events
           WHERE ts >= ? GROUP BY dst_port, proto ORDER BY n DESC LIMIT 10""", (since,))
    srcs = db.all(
        """SELECT src_ip ip, country, COUNT(*) n, MAX(crowdsec) crowdsec FROM fw_events
           WHERE ts >= ? GROUP BY src_ip ORDER BY n DESC LIMIT 10""", (since,))
    return {"ports": ports, "sources": srcs}


def hosts(rng: str) -> list[dict]:
    since, _ = window(rng)
    rows = db.all(
        """SELECT host, COUNT(*) n, SUM(status BETWEEN 400 AND 499) e4, SUM(status >= 500) e5,
                  SUM(status IN (401,403)) auth, COUNT(DISTINCT client_ip) ips, SUM(via_cf) via_cf,
                  MAX(ts) last_seen, MAX(sent_to) upstream
           FROM npm_requests WHERE ts >= ? GROUP BY host ORDER BY n DESC""", (since,))
    alert_counts = {r["target_host"]: r["n"] for r in db.all(
        "SELECT target_host, COUNT(*) n FROM alerts WHERE created_at >= ? GROUP BY target_host", (since,))}
    seen = set()
    for r in rows:
        seen.add(r["host"])
        r["cf_proxied"] = cloudflare.host_proxied(r["host"])
        r["alerts"] = alert_counts.get(r["host"], 0)
    # Cloudflare records with no traffic yet still deserve a row
    for c in db.all("SELECT name, proxied FROM cf_hosts ORDER BY name"):
        if c["name"] not in seen and not c["name"].startswith("*"):
            rows.append({"host": c["name"], "n": 0, "e4": 0, "e5": 0, "auth": 0, "ips": 0, "via_cf": 0,
                         "last_seen": None, "upstream": None, "cf_proxied": bool(c["proxied"]), "alerts": 0})
    return rows


def ip_detail(ip: str) -> dict:
    now = now_iso()
    g = geoip.lookup(ip)
    out = {
        "ip": ip, "geo": g, "private": geoip.is_private(ip), "cloudflare_edge": cloudflare.is_cloudflare_ip(ip),
        "decisions": db.all(
            """SELECT d.*, (d.until > ?) active FROM decisions d WHERE d.value = ? ORDER BY d.created_at DESC""",
            (now, ip)),
        "alerts": db.all("SELECT * FROM alerts WHERE ip = ? ORDER BY created_at DESC LIMIT 100", (ip,)),
        "requests": db.all(
            """SELECT id, ts, host, method, path, status, ua FROM npm_requests WHERE client_ip = ?
               ORDER BY id DESC LIMIT 300""", (ip,)),
        "firewall": db.all("SELECT * FROM fw_events WHERE src_ip = ? ORDER BY id DESC LIMIT 300", (ip,)),
        "cloudflare": db.all("SELECT * FROM cf_events WHERE ip = ? ORDER BY ts DESC LIMIT 100", (ip,)),
        "counts": {
            "requests": db.scalar("SELECT COUNT(*) FROM npm_requests WHERE client_ip = ?", (ip,)),
            "errors": db.scalar("SELECT COUNT(*) FROM npm_requests WHERE client_ip = ? AND status >= 400", (ip,)),
            "drops": db.scalar("SELECT COUNT(*) FROM fw_events WHERE src_ip = ?", (ip,)),
            "first_seen": db.scalar(
                "SELECT MIN(t) FROM (SELECT MIN(ts) t FROM npm_requests WHERE client_ip=:ip "
                "UNION SELECT MIN(ts) FROM fw_events WHERE src_ip=:ip UNION SELECT MIN(created_at) FROM alerts WHERE ip=:ip)",
                {"ip": ip}),
        },
        "hosts": db.all(
            """SELECT host, COUNT(*) n, SUM(status >= 400) err FROM npm_requests WHERE client_ip = ?
               GROUP BY host ORDER BY n DESC""", (ip,)),
    }
    # Stitch everything into one chronological story
    tl = []
    for d in out["decisions"]:
        tl.append({"ts": d["created_at"], "kind": "decision", "text": f"{d['type']} for {d['duration']} — {d['scenario']}"})
    for a in out["alerts"]:
        tl.append({"ts": a["created_at"], "kind": "alert", "text": a["scenario"] + (f" → {a['target_host']}" if a["target_host"] else "")})
    for r in out["requests"][:150]:
        tl.append({"ts": r["ts"], "kind": "request", "status": r["status"], "text": f"{r['method']} {r['host']}{r['path']}"})
    for f in out["firewall"][:150]:
        tl.append({"ts": f["ts"], "kind": "drop", "crowdsec": f["crowdsec"], "text": f"{f['proto']} → :{f['dst_port'] or '-'} on {f['iface']}"})
    for c in out["cloudflare"]:
        tl.append({"ts": c["ts"], "kind": "cloudflare", "text": f"{c['action']} by {c['source']} — {c['host']}{c['path']}"})
    tl.sort(key=lambda e: e["ts"] or "", reverse=True)
    out["timeline"] = tl[:400]
    return out


def counts() -> dict:
    return {t: db.scalar(f"SELECT COUNT(*) FROM {t}") for t in
            ("alerts", "decisions", "npm_requests", "fw_events", "cf_hosts", "cf_events")}
