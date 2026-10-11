"""
Request a page through NPM as a given visitor, the way Cloudflare would deliver it.

  probe.py IP [IP ...] [--npm nginx-proxy-manager] [--host app.test] [--path /api/health]

Prints one line per IP: the HTTP status NPM returned (403 = blocked by the npm-bouncer).
NPM trusts CF-Connecting-IP from Docker's address range once the proxy host has
`real_ip_header CF-Connecting-IP;` (SETUP.md step 6), so the header stands in for Cloudflare.
"""
import argparse
import urllib.error
import urllib.request


def main():
    p = argparse.ArgumentParser()
    p.add_argument("ips", nargs="+")
    p.add_argument("--npm", default="nginx-proxy-manager")
    p.add_argument("--host", default="app.test")
    p.add_argument("--path", default="/api/health")
    a = p.parse_args()
    for ip in a.ips:
        req = urllib.request.Request(f"http://{a.npm}{a.path}", headers={"Host": a.host, "CF-Connecting-IP": ip})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        except OSError as e:
            code = f"error: {e}"
        print(f"{ip:<18} -> {code}")


if __name__ == "__main__":
    main()
