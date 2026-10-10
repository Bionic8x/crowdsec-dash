# How it works: a walkthrough

This is the "read me while you read the code" guide. Start at the top. Each section
names the file to open alongside it.

## The big picture

```
             Internet
                │
   ┌────────────▼─────────────┐
   │ OPNsense                 │
   │  CrowdSec LAPI   ◄───────┼─── alerts from the Unraid agent
   │  firewall bouncer (pf)   │    (bans become pf table entries)
   │  filterlog ──────────────┼─── syslog udp/5514 ───────┐
   └────────────┬─────────────┘                           │
                │ LAN                                     │
   ┌────────────▼─────────────────────────────────────────▼─┐
   │ Unraid                                                 │
   │  NPM ──► proxy-host-*_access.log ──► crowdsec-agent ───┼──► LAPI
   │                                 └──► crowdsec-dash ◄───┼─── LAPI (read alerts/decisions)
   │                                      SQLite + web UI   │
   └────────────────────────────────────────────────────────┘
```

CrowdSec splits into three jobs, and your setup spreads them across two boxes:

| Job | CrowdSec name | Where it runs for you |
|---|---|---|
| Read logs, spot attacks | **Log processor** (agent / "machine") | OPNsense (its own logs) + `crowdsec-agent` on Unraid (NPM logs) |
| Store alerts, turn them into bans | **LAPI** (Local API) | OPNsense |
| Enforce bans | **Remediation component** (bouncer) | OPNsense firewall bouncer → pf tables |

The dashboard is a fourth *machine*. It logs in like an agent but only reads.

## 1. Detection: from a log line to a ban (the agent)

Files: `crowdsec/acquis.d/npm.yaml`, `crowdsec/scenarios/jellyfin-npm-bf.yaml`

1. **Acquisition** tails `/var/log/npm/proxy-host-*_access.log` and labels each line `type: nginx-proxy-manager`.
2. **Parsers** pick the line apart. The NPM parser fills fields like `evt.Meta.source_ip`, `http_status`, `http_path`, and `target_fqdn`. Enrichers add GeoIP data. Whitelists (private IPs, and our Cloudflare list) drop events that must never cause a ban.
3. **Scenarios** are leaky buckets keyed by IP. When one overflows, the agent sends an **alert** to the LAPI.
4. The LAPI's profile says "alert from an IP → `ban` decision for 4h". The OPNsense bouncer polls LAPI, sees the new decision, and adds the IP to a pf table that the plugin's rules block.

Open `jellyfin-npm-bf.yaml` next to a failed-login line in an NPM log. One 401 puts one drop in a 5-drop bucket that leaks once a minute, so it's nowhere near a ban. A script trying passwords overflows it in seconds.

## 2. The dashboard's collectors

All in `dashboard/app/collectors/`. Each is an `async def run()` loop started from `main.py`. Blocking work (HTTP calls, SQLite) goes to a thread with `asyncio.to_thread`.

### `lapi.py`: talking to CrowdSec
- `POST /v1/watchers/login` with machine id and password returns a JWT, sent as `Authorization: Bearer …` from then on. On a 401 it logs in again.
- Every 30s, `GET /v1/alerts?since=<seconds since last poll>` fetches new alerts. Each alert carries its decisions.
- Then `GET /v1/alerts?has_active_decision=true` gets everything banned *right now*. Decisions in our DB that aren't in that set get marked expired. That's how a `cscli decisions delete` on OPNsense shows up here.
- `ActiveIndex` keeps the set of banned IPs in memory so the firewall collector can check each packet quickly.
- `add_ban()` shows how `cscli decisions add` works under the hood: it pushes an *alert* that carries a decision. There's no "create decision" endpoint.

### `npm_logs.py`: tailing files without losing your place
- One regex (`LINE`) matches NPM's log format. The comment above it maps each part back to the nginx `log_format`.
- For each file it stores `inode:offset` in the `kv` table. A new inode means the log was rotated, and a file smaller than the offset means it was truncated; either way it starts over from the top.
- It only reads up to the last complete newline, so a half-written line is picked up on the next pass.
- `via_cf` is set when the client IP is a Cloudflare edge address. That's the "real IP not restored" warning.

### `syslog_fw.py`: a UDP syslog server in ~100 lines
- `asyncio.DatagramProtocol` calls `datagram_received` once per packet.
- `extract_csv` finds the `filterlog` CSV, and `parse_filterlog` maps the fields (the layout is in the docstring; IPv4 and IPv6 differ).
- Rows are buffered and written once a second, which matters because a WAN under scan can send hundreds of packets a second.
- `crowdsec = 1` when the source has an active decision. Those are drops caused by the bouncer.

### `cloudflare.py`: why "proxied" changes everything
- With the orange cloud on, the TCP connection to your WAN comes **from Cloudflare**. OPNsense never sees the attacker's IP, so a pf ban can't apply.
- With a token, it syncs DNS records and stores `proxied` per hostname. The UI uses that to tell you which hosts your firewall can actually protect.
- The Decisions page's **Requests after ban** column is that idea turned into data: a banned IP still reaching NPM.

### `../geoip.py`
- Downloads the free DB-IP Lite `.mmdb` files monthly and looks up IPs (with an LRU cache). Lookups happen at insert time, so country, lat, and lon are stored on each row and the map is a plain `GROUP BY`.

## 3. Storage: `dashboard/app/db.py`

One SQLite file, `data/dash.db`. Every timestamp is a UTC string `YYYY-MM-DDTHH:MM:SSZ`, so `ts >= '2026-10-10T00:00:00Z'` is a valid time comparison and `strftime('%s', ts)` buckets for charts. Poke at it yourself:

```sh
docker exec -it crowdsec-dash python -c "import sqlite3;c=sqlite3.connect('/data/dash.db');print(c.execute('select host,count(*) from npm_requests group by host').fetchall())"
```

Old rows are pruned hourly (`RETENTION_DAYS`).

## 4. The API: `dashboard/app/main.py` + `queries.py`

`main.py` is routing only. Every endpoint calls one function in `queries.py`, which is just SQL. Interesting ones:

- `top_sources()` combines three tables with `UNION` plus `LEFT JOIN`s into one "hostility score": `alerts×50 + drops + errors×2`. Tweak the weights.
- `decisions()` uses correlated subqueries to count firewall hits and NPM requests *during* each ban.
- `ip_detail()` stitches every source into one sorted timeline.

Try them in a browser: `/api/overview?range=24h`, `/api/ip/1.2.3.4`, `/api/status`.

## 5. The UI: `dashboard/static/app.js`

No framework and no build step. `render()` reads `location.hash` (`#/decisions?state=active`), calls `pages[name]()`, which fetches JSON and writes HTML. It re-renders every 30s.

- `stackedBars()` draws the time charts with d3 scales and `d3.stack()`, plus a hover layer.
- `worldMap()` uses d3-geo's Natural Earth projection. `topoFeatures()` is a hand-written ~20-line TopoJSON decoder, which shows how TopoJSON shares borders as delta-encoded "arcs".

## Ideas for what to build next

1. **Cloudflare enforcement**: the CrowdSec Cloudflare Worker bouncer, then watch "Requests after ban" drop to 0 for proxied hosts.
2. **Notifications**: a `notify.py` collector that posts to ntfy or Discord when a ban targets a host you care about.
3. **Your own scenario**: e.g. "more than 30 404s on one host in a minute". Write it, run `cscli explain`, then watch it fire here.
4. **AppSec / WAF**: CrowdSec's AppSec component can inspect requests inline. NPM would need the OpenResty bouncer for that.
5. **Hairpin traffic**: LAN clients using your public hostnames show up as the router IP (NAT reflection). Split DNS on OPNsense (Unbound host overrides) would send LAN clients straight to NPM.
