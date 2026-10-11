"""
A tiny stand-in for the Cloudflare API, for the demo stack: one zone (example.com), its DNS
records, and a few hours of security events (GraphQL firewallEventsAdaptive). Point the
dashboard at it with CF_API_URL=http://mock-cloudflare:8000.
"""
import json
import os
import random
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import demo  # same generated attackers as the rest of the demo data

ZONE = {"id": "0123456789abcdef0123456789abcdef", "name": "example.com"}
RECORDS = [  # proxied = orange cloud. jellyfin + listen are DNS-only, like demo.DNS_ONLY
    ("example.com", "A", demo.WAN, True), ("www.example.com", "CNAME", "example.com", True),
    ("requests.example.com", "CNAME", "example.com", True), ("books.example.com", "CNAME", "example.com", True),
    ("wiki.example.com", "CNAME", "example.com", True), ("cloud.example.com", "CNAME", "example.com", True),
    ("jellyfin.example.com", "CNAME", "example.com", False), ("listen.example.com", "CNAME", "example.com", False),
]
R = random.Random(7)
EVENTS = []
FEATURED = next(ip for ip, (_, _, web) in demo.BANNED if web)  # the README's IP-page screenshot: every source
for ip in [FEATURED] + R.sample(demo.ATTACKERS[len(demo.BANS):], 40):
    host = R.choice(["example.com", "example.com", "wiki.example.com", "requests.example.com", "cloud.example.com"])
    source, action = R.choice([("firewallCustom", "block")] * 5 + [("firewallManaged", "block")] * 2
                              + [("botFight", "managed_challenge"), ("securitylevel", "managed_challenge"), ("linkMaze", "link_maze_injected")])
    start = demo.NOW - timedelta(seconds=R.uniform(120, 5.5 * 3600))
    for i in range(R.randint(1, 6)):
        EVENTS.append({
            "datetime": (start + timedelta(seconds=i * 3)).strftime("%Y-%m-%dT%H:%M:%SZ"), "action": action,
            "source": source, "clientIP": ip, "clientCountryName": "", "clientRequestHTTPHost": host,
            "clientRequestPath": R.choice(demo.PROBES), "clientRequestHTTPMethodName": R.choice(["GET", "GET", "POST"]),
            "userAgent": R.choice(demo.BOT_UAS), "ruleId": f"{R.getrandbits(128):032x}", "rayName": f"{R.getrandbits(64):016x}",
        })
EVENTS.sort(key=lambda e: e["datetime"])


def country(ip, _cache={}):
    """Cloudflare reports the visitor's country; we look it up in the dashboard's GeoIP file."""
    if ip not in _cache:
        try:
            import maxminddb
            with maxminddb.open_database(os.path.join(os.environ.get("GEOIP_DIR", "/geoip"), "dbip-city-lite.mmdb")) as db:
                _cache[ip] = ((db.get(ip) or {}).get("country") or {}).get("iso_code") or ""
        except Exception:
            return ""
    return _cache[ip]


class Handler(BaseHTTPRequestHandler):
    def reply(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        page = {"page": 1, "total_pages": 1}
        if path == "/zones":
            self.reply({"success": True, "result": [ZONE], "result_info": page})
        elif path == f"/zones/{ZONE['id']}/dns_records":
            recs = [{"name": n, "type": t, "content": c, "proxied": p} for n, t, c, p in RECORDS]
            self.reply({"success": True, "result": recs, "result_info": page})
        else:  # /ips and anything else: let the dashboard fall back to its built-in list
            self.send_error(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        since = (body.get("variables") or {}).get("since", "")
        events = [dict(e, clientCountryName=country(e["clientIP"])) for e in EVENTS if e["datetime"] >= since][:1000]
        self.reply({"data": {"viewer": {"zones": [{"firewallEventsAdaptive": events}]}}, "errors": None})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
