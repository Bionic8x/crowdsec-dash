"""
Write Nginx Proxy Manager style access-log lines (NPM's "proxy" log_format) for testing.

  npm_logs.py <dir> seed               create proxy-host-{1,2}_access.log with normal traffic
  npm_logs.py <dir> traffic [N]        append N normal requests
  npm_logs.py <dir> bruteforce IP [N]  append N failed Jellyfin logins from IP (default 10)
  npm_logs.py <dir> raw HOST_ID        append stdin as-is (e.g. real lines from a test NPM)
"""
import os
import random
import sys
import time

HOSTS = {1: "jellyfin.example.com", 2: "cloud.example.com"}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
VISITORS = ["81.2.69.142", "89.160.20.112", "2.125.160.216", "175.16.199.5", "216.160.83.56"]
CF_EDGE = "172.70.120.15"  # a Cloudflare edge address: the dashboard should flag "real IP not restored"


def line(status, method, host, uri, client, length=512, ua=UA):
    ts = time.strftime("%d/%b/%Y:%H:%M:%S %z")
    return (f'[{ts}] - {status} {status} - {method} https {host} "{uri}" [Client {client}] '
            f'[Length {length}] [Gzip -] [Sent-to 192.168.1.10] "{ua}" "-"\n')


def append(d, host_id, lines):
    with open(os.path.join(d, f"proxy-host-{host_id}_access.log"), "a") as f:
        f.writelines(lines)


def normal(n):
    out = []
    for _ in range(n):
        hid = random.choice(list(HOSTS))
        uri = random.choice(["/", "/web/index.html", "/System/Info/Public", "/index.php/apps/files",
                             "/Videos/abc/stream?api_key=SECRET-KEY-123&Static=true"])
        out.append((hid, line(random.choice([200, 200, 200, 304, 404]), "GET", HOSTS[hid], uri,
                              random.choice(VISITORS + [CF_EDGE]))))
    return out


def main():
    d, cmd, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    os.makedirs(d, exist_ok=True)
    if cmd == "seed":
        for hid in HOSTS:
            open(os.path.join(d, f"proxy-host-{hid}_access.log"), "a").close()
        open(os.path.join(d, "fallback_access.log"), "a").close()
        cmd, args = "traffic", ["40"]
    if cmd == "traffic":
        rows = normal(int(args[0]) if args else 20)
        for hid in HOSTS:
            append(d, hid, [ln for h, ln in rows if h == hid])
        print(f"appended {len(rows)} normal requests")
    elif cmd == "bruteforce":
        ip, n = args[0], int(args[1]) if len(args) > 1 else 10
        lines = []
        for _ in range(n):
            lines.append(line(401, "POST", HOSTS[1], "/Users/authenticatebyname", ip, 25))
        append(d, 1, lines)
        print(f"appended {n} failed Jellyfin logins from {ip}")
    elif cmd == "raw":
        lines = [ln if ln.endswith("\n") else ln + "\n" for ln in sys.stdin if ln.strip()]
        append(d, int(args[0]), lines)
        print(f"appended {len(lines)} raw lines to proxy-host-{args[0]}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
