"""
Demo data for screenshots: a believable day at the edge with nothing real in it. Hosts are
example.com names, your own addresses are documentation ranges, and every visitor/attacker IP
is generated from a fixed seed (so the same "attackers" show up in every source).

  demo.py npm <dir>                 a day of NPM access logs, backdated over the last 24 h
  demo.py syslog [host]             a day of firewall drops, backdated, sent like OPNsense does
  demo.py alerts                    CrowdSec alerts + bans from two machines, pushed to the LAPI
  demo.py after-ban <dir> [host]    banned IPs coming back: tagged firewall drops, NPM 403s

`alerts` logs in with LAPI_URL plus OPNSENSE_ID/OPNSENSE_PASSWORD and AGENT_ID/AGENT_PASSWORD.
"""
import ipaddress
import json
import math
import os
import random
import socket
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone

R = random.Random(20261011)
NOW = datetime.now(timezone.utc)
WAN = "203.0.113.10"          # documentation range: "your" public IP
UPSTREAM = "192.168.1.20"

# First octets by registry, so geolocation spreads the way real internet noise does.
REGIONS = {
    "arin": [23, 24, 50, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 107, 174, 184, 199, 205, 206, 207, 208, 209],
    "ripe": [2, 5, 31, 37, 46, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 176, 178, 185, 193, 194, 195, 212, 213, 217],
    "apnic": [1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 175, 180, 182, 183, 210, 211, 218, 219, 220, 221, 222, 223],
    "lacnic": [177, 179, 181, 186, 187, 189, 191, 200, 201],
    "afrinic": [41, 102, 105, 154, 196],
}
CF = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22")]


def public_ip(regions, weights):
    while True:
        first = R.choice(REGIONS[R.choices(regions, weights)[0]])
        ip = ipaddress.ip_address(f"{first}.{R.randint(0, 255)}.{R.randint(0, 255)}.{R.randint(1, 254)}")
        if ip.is_global and not any(ip in n for n in CF):
            return str(ip)


# Attackers come from hosting/cloud networks (where scanners actually run), not home ISPs:
# random addresses in these /16s, so no real household ends up pictured as an attacker.
HOSTING = [
    "104.248", "138.68", "159.65", "165.227", "167.99", "128.199", "139.59", "188.166", "46.101", "206.189",  # DigitalOcean
    "5.9", "78.46", "88.99", "88.198", "95.216", "116.202", "135.181", "65.108", "49.12",                    # Hetzner
    "51.38", "51.68", "51.75", "51.77", "51.91", "54.36", "137.74", "145.239", "147.135", "178.32",          # OVH
    "45.33", "45.56", "45.79", "139.162", "172.105",                                                         # Linode
    "45.32", "45.63", "45.76", "45.77", "95.179", "108.61", "136.244", "144.202", "149.28",       # Vultr
    "3.88", "13.58", "18.144", "52.79", "54.183", "34.105", "35.198", "35.240", "20.51", "40.83",            # AWS, GCP, Azure
    "43.153", "49.51", "101.33", "119.28", "129.211", "150.109", "47.74", "47.88", "8.209", "121.40",        # Tencent, Alibaba
]


def hosting_ip():
    while True:
        ip = ipaddress.ip_address(f"{R.choice(HOSTING)}.{R.randint(0, 255)}.{R.randint(1, 254)}")
        if ip.is_global and not any(ip in n for n in CF):
            return str(ip)


ATTACKERS = [hosting_ip() for _ in range(140)]
VISITORS = [public_ip(["arin", "ripe"], [9, 1]) for _ in range(14)]
# The ones CrowdSec catches. (scenario, machine, "web" = also seen in NPM logs)
BANS = [
    ("firewallservices/pf-scan-multi_ports", "opnsense", False),
    ("firewallservices/pf-scan-multi_ports", "opnsense", False),
    ("firewallservices/pf-scan-multi_ports", "opnsense", False),
    ("firewallservices/pf-scan-multi_ports", "opnsense", False),
    ("firewallservices/pf-scan-multi_ports", "opnsense", False),
    ("firewallservices/pf-scan-multi_ports", "opnsense", False),
    ("firewallservices/pf-scan-multi_ports", "opnsense", False),
    ("crowdsecurity/http-probing", "agent", True),
    ("crowdsecurity/http-probing", "agent", True),
    ("crowdsecurity/http-probing", "agent", True),
    ("crowdsecurity/http-sensitive-files", "agent", True),
    ("crowdsecurity/http-sensitive-files", "agent", True),
    ("crowdsecurity/http-bad-user-agent", "agent", True),
    ("crowdsecurity/http-cve-2021-41773", "agent", True),
    ("crowdsecurity/http-crawl-non_statics", "agent", True),
    ("local/jellyfin-npm-bf", "agent", True),
    ("local/jellyfin-npm-bf", "agent", True),
    ("local/seerr-npm-bf", "agent", True),
    ("local/komga-npm-bf", "agent", True),
]
BANNED = list(zip(ATTACKERS[:len(BANS)], BANS))
WEB_ATTACKERS = [ip for ip, (_, _, web) in BANNED if web] + ATTACKERS[len(BANS):len(BANS) + 45]

HOSTS = {1: "jellyfin.example.com", 2: "requests.example.com", 3: "books.example.com", 4: "listen.example.com",
         5: "wiki.example.com", 6: "cloud.example.com", 7: "example.com"}
DNS_ONLY = {1, 4}  # must match mock_cloudflare.py
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
       "Jellyfin-Android/2.6.3", "Infuse-Direct/8.2", "Kodi/21.2 (Linux; Android 14)"]
BOT_UAS = ["Mozilla/5.0 zgrab/0.x", "python-requests/2.32.3", "curl/8.10.1", "Go-http-client/1.1",
           "Mozilla/5.0 (compatible; Odin; https://docs.getodin.com/)", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"]
# (host id, method, path, status, typical bytes)
NORMAL = [
    (1, "GET", "/web/index.html", 200, 9000), (1, "GET", "/System/Info/Public", 200, 400),
    (1, "GET", "/Users/5f1c/Items/Resume?Limit=12&Fields=PrimaryImageAspectRatio", 200, 6000),
    (1, "GET", "/Videos/a91e/stream.mkv?Static=true&api_key=0123456789abcdef", 206, 8_000_000),
    (1, "POST", "/Sessions/Playing/Progress", 204, 0), (1, "GET", "/Items/a91e/Images/Primary?maxHeight=300", 200, 40000),
    (2, "GET", "/", 200, 54000), (2, "GET", "/api/v1/auth/me", 200, 900), (2, "GET", "/api/v1/discover/movies?page=1", 200, 22000),
    (2, "POST", "/api/v1/request", 201, 600), (2, "GET", "/_next/static/chunks/main.js", 304, 0),
    (3, "GET", "/api/v1/series?page=0&size=20", 200, 15000), (3, "GET", "/api/v1/books/0b7d/pages/3", 200, 350000),
    (3, "GET", "/opds/v1.2/catalog", 200, 3000),
    (4, "GET", "/api/me/progress/li_8f2k", 200, 500), (4, "POST", "/api/items/li_8f2k/play", 200, 2400),
    (4, "GET", "/api/items/li_8f2k/file/3", 206, 4_000_000),
    (5, "GET", "/", 200, 30000), (5, "POST", "/graphql", 200, 4000), (5, "GET", "/_assets/js/app.js", 304, 0),
    (6, "GET", "/index.php/apps/files/", 200, 60000), (6, "PROPFIND", "/remote.php/dav/files/alex/Photos", 207, 9000),
    (7, "GET", "/", 200, 12000), (7, "GET", "/favicon.ico", 200, 4000),
]
PROBES = ["/.env", "/.git/config", "/wp-login.php", "/xmlrpc.php", "/wp-admin/setup-config.php", "/phpmyadmin/",
          "/admin.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/luci/;stok=/locale",
          "/owa/auth/logon.aspx", "/boaform/admin/formLogin", "/.aws/credentials", "/config.json", "/actuator/env",
          "/server-status", "/.DS_Store", "/api/v1/pods", "/cgi-bin/.%2e/.%2e/.%2e/bin/sh"]
LOGIN_FAIL = {"local/jellyfin-npm-bf": (1, "POST", "/Users/authenticatebyname", 401),
              "local/seerr-npm-bf": (2, "POST", "/api/v1/auth/local", 403),
              "local/komga-npm-bf": (3, "GET", "/api/v2/users/me?remember-me=true", 401)}


def evening_weight(t):
    """More traffic in the (US) evening, never zero."""
    h = (t.hour - 1) % 24
    return 0.25 + max(0.0, math.cos((h - 1) / 24 * 2 * math.pi)) ** 2


def random_time(weighted=False, within=timedelta(hours=24)):
    while True:
        t = NOW - timedelta(seconds=R.uniform(60, within.total_seconds()))
        if not weighted or R.random() < evening_weight(t) / 1.25:
            return t


def npm_line(t, status, upstream, method, host, uri, client, length, ua):
    ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (f'[{ts}] - {upstream} {status} - {method} https {host} "{uri}" [Client {client}] '
            f'[Length {length}] [Gzip -] [Sent-to {UPSTREAM}] "{ua}" "-"\n')


def write_npm(d, rows):
    by_host = {}
    for t, hid, line in rows:
        by_host.setdefault(hid, []).append((t, line))
    for hid in HOSTS:
        with open(os.path.join(d, f"proxy-host-{hid}_access.log"), "a") as f:
            f.writelines(line for _, line in sorted(by_host.get(hid, [])))
    open(os.path.join(d, "fallback_access.log"), "a").close()
    return len(rows)


def cmd_npm(d):
    rows = []
    people = [(ip, R.choice(UAS)) for ip in VISITORS]
    for _ in range(3200):  # people using their apps
        t = random_time(weighted=True)
        ip, ua = R.choice(people)
        hid, method, path, status, size = R.choice(NORMAL)
        rows.append((t, hid, npm_line(t, status, status, method, HOSTS[hid], path, ip, int(size * R.uniform(.6, 1.4)), ua)))
    for _ in range(40):  # people mistyping passwords now and then
        t = random_time(weighted=True)
        ip, ua = R.choice(people)
        hid, method, path, status = LOGIN_FAIL[R.choice(list(LOGIN_FAIL))]
        rows.append((t, hid, npm_line(t, status, status, method, HOSTS[hid], path, ip, 40, ua)))
    banned_web = {ip: sc for ip, (sc, _, web) in BANNED if web}
    for ip in WEB_ATTACKERS:  # scanners: mostly the DNS-only hosts, Cloudflare stops a lot on the others
        start, ua = random_time(), R.choice(BOT_UAS)
        hits = R.randint(2, 6) if ip not in banned_web else R.randint(14, 30)
        for i in range(hits):
            t = start + timedelta(seconds=i * R.uniform(1, 8))
            hid = R.choice([1, 1, 4, 4, 2, 5, 7])
            if banned_web.get(ip) in LOGIN_FAIL:
                hid, method, path, status = LOGIN_FAIL[banned_web[ip]]
                rows.append((t, hid, npm_line(t, status, status, method, HOSTS[hid], path, ip, 40, R.choice(UAS))))
            else:
                status = R.choice([404, 404, 404, 403, 400])
                rows.append((t, hid, npm_line(t, status, status, "GET", HOSTS[hid], R.choice(PROBES), ip, R.randint(150, 600), ua)))
    print(f"wrote {write_npm(d, rows)} NPM log lines")


def filterlog(t, src, dport, seq):
    ts = t.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    csv = (f"96,,,02f4bab031b57d1e30553ce08e0c5e6a,igb0,match,block,in,4,0x0,,242,{R.randint(1, 65535)},0,none,6,tcp,40,"
           f"{src},{WAN},{R.randint(1024, 65535)},{dport},0,S,{R.randint(1, 2**31)},,1024,,")
    return f'<134>1 {ts} OPNsense.lan filterlog {seq} - [meta sequenceId="{seq}"] {csv}'


PORTS = {22: 18, 23: 10, 3389: 12, 445: 8, 8080: 8, 5900: 5, 1433: 5, 3306: 5, 6379: 4, 8443: 5, 2222: 4,
         81: 3, 8888: 3, 9200: 2, 25: 3, 21: 3, 37215: 2, 5555: 2, 7547: 2, 8291: 2}


def send(packets, host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i, msg in enumerate(packets):
        s.sendto(msg.encode(), (host, 5514))
        if i % 200 == 199:
            time.sleep(0.05)  # don't overrun the receiver's socket buffer
    return len(packets)


def cmd_syslog(host):
    packets, seq = [], 0
    ports, weights = list(PORTS), list(PORTS.values())
    for i, ip in enumerate(ATTACKERS):
        heavy = i < len(BANS) and BANS[i][1] == "opnsense"
        n = R.randint(40, 120) if heavy else int(R.paretovariate(1.3) * 6)
        start = random_time()
        for _ in range(min(n, 400)):
            seq += 1
            t = min(NOW, start + timedelta(seconds=R.uniform(0, 3600 if not heavy else 900)))
            packets.append(filterlog(t, ip, R.choices(ports, weights)[0], seq))
    print(f"sent {send(packets, host)} filterlog packets to {host}:5514")


def lapi(method, path, body=None, token=None):
    req = urllib.request.Request(os.environ["LAPI_URL"].rstrip("/") + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 # the LAPI refuses logins whose User-Agent isn't "name/version"
                                 headers={"Content-Type": "application/json", "User-Agent": "crowdsec-dash-demo/1.0"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read() or b"null")


def cmd_alerts():
    tokens = {}
    for name, (mid, pw) in {"opnsense": ("OPNSENSE_ID", "OPNSENSE_PASSWORD"), "agent": ("AGENT_ID", "AGENT_PASSWORD")}.items():
        tokens[name] = lapi("POST", "/v1/watchers/login",
                            {"machine_id": os.environ[mid], "password": os.environ[pw], "scenarios": []})["token"]
    # The LAPI stamps alerts with the time it receives them, so spread the pushes out a little
    # (ALERT_GAP seconds apart) instead of 19 bans "30s ago".
    gap = float(os.environ.get("ALERT_GAP", "12"))
    order = BANNED[:]
    R.shuffle(order)
    n = 0
    for ip, (scenario, machine, _) in order:
        if n:
            time.sleep(gap)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        duration = R.choice(["4h", "4h", "4h", "24h"])
        events = []
        if machine == "agent":  # web alerts say which site was attacked (the Target column)
            hid = LOGIN_FAIL[scenario][0] if scenario in LOGIN_FAIL else R.choice([1, 4, 2, 5, 7])
            events = [{"timestamp": stamp, "meta": [{"key": "target_fqdn", "value": HOSTS[hid]},
                                                    {"key": "source_ip", "value": ip}, {"key": "service", "value": "http"}]}]
        alert = {
            "scenario": scenario, "scenario_hash": "", "scenario_version": "", "message": f"Ip {ip} performed '{scenario}'",
            "events_count": R.randint(6, 40), "start_at": stamp, "stop_at": stamp, "created_at": stamp,
            "capacity": 5, "leakspeed": "10s", "simulated": False, "events": events,
            "source": {"scope": "Ip", "value": ip, "ip": ip},
            "decisions": [{"duration": duration, "origin": "crowdsec", "scenario": scenario,
                           "scope": "Ip", "type": "ban", "value": ip}],
        }
        lapi("POST", "/v1/alerts", [alert], tokens[machine])
        n += 1
    print(f"pushed {n} alerts with bans")


def cmd_after_ban(d, host):
    """Banned IPs keep knocking: the firewall drops them (tagged CrowdSec), and on Cloudflare-proxied
    hosts the NPM bouncer answers 403 (no upstream). One gets through before the bouncer caught up."""
    packets, rows = [], []
    for i, (ip, (_, _, web)) in enumerate(BANNED):
        for k in range(R.randint(3, 25)):
            t = NOW - timedelta(seconds=R.uniform(0, 8))  # after the ban was created
            packets.append(filterlog(t, ip, R.choice(list(PORTS)), 900000 + i * 100 + k))
        if web:
            for _ in range(R.randint(2, 12)):
                t = NOW - timedelta(seconds=R.uniform(0, 8))  # after the ban was created
                hid = R.choice([2, 3, 5, 7])
                rows.append((t, hid, npm_line(t, 403, "-", "GET", HOSTS[hid], R.choice(PROBES), ip, 146, R.choice(BOT_UAS))))
    ip = next(ip for ip, (_, _, web) in BANNED if web)
    t = NOW - timedelta(seconds=2)
    rows.append((t, 5, npm_line(t, 404, 404, "GET", HOSTS[5], "/.env.production", ip, 310, BOT_UAS[1])))
    print(f"sent {send(packets, host)} drops from banned IPs; wrote {write_npm(d, rows)} NPM lines")


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "npm":
        cmd_npm(args[0])
    elif cmd == "syslog":
        cmd_syslog(args[0] if args else "crowdsec-dash")
    elif cmd == "alerts":
        cmd_alerts()
    elif cmd == "after-ban":
        cmd_after_ban(args[0], args[1] if len(args) > 1 else "crowdsec-dash")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
