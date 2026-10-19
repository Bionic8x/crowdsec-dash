"""
CrowdSec bouncer for stock Nginx Proxy Manager (jc21/nginx-proxy-manager).

Why: OPNsense can only block IPs that connect to you directly. For Cloudflare-proxied
hosts the connection comes from Cloudflare, so the firewall ban never applies. NPM does
see the real visitor (once `real_ip_header CF-Connecting-IP;` is set), so this blocks
banned IPs there, with a 403, before the request reaches the app.

How, using only features stock NPM already has:
  * NPM includes optional files from /data/nginx/custom/ (its "Custom Nginx Configurations").
    We add two tiny hooks:
        http.conf          geo $crowdsec_banned { default 0; include .../crowdsec-bans*.map; }
        server_proxy.conf  if ($crowdsec_banned) { return 403; }
    nginx's geo module matches the *restored* client IP, so it works for proxied and
    DNS-only hosts alike. Existing hook files are never modified (we log what to add).
  * Every POLL_SECONDS we pull decisions from the LAPI with a bouncer API key (read-only)
    and rewrite crowdsec-bans.map when the set changes.
  * nginx only reads config on reload, so we send its master process SIGHUP (graceful:
    open connections like a video stream carry on). The container shares NPM's PID
    namespace for that (compose `pid: container:<npm>`), which avoids the Docker socket.

Fail-safe: if this container stops, the last ban list stays in place; nothing ever blocks
everyone. Private/LAN and Cloudflare addresses are never written to the list.
To uninstall: stop the container and delete crowdsec-bans.map, plus our http.conf and
server_proxy.conf if we created them (they start with "# crowdsec-npm-bouncer").
"""
import ipaddress
import json
import logging
import os
import signal
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlencode

log = logging.getLogger("npm-bouncer")


def _list(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


LAPI_URL = os.environ.get("LAPI_URL", "").rstrip("/")
API_KEY = os.environ.get("BOUNCER_API_KEY", "")
VERIFY_TLS = os.environ.get("LAPI_VERIFY_TLS", "true").lower() in ("1", "true", "yes", "on")
CUSTOM_DIR = os.environ.get("NPM_CUSTOM_DIR", "/npm-custom")            # NPM's nginx/custom, as mounted here
NGINX_CUSTOM_PATH = os.environ.get("NGINX_CUSTOM_PATH", "/data/nginx/custom")  # the same folder, as NPM sees it
MAP_NAME = "crowdsec-bans.map"
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "10"))
RELOAD_MIN_SECONDS = int(os.environ.get("RELOAD_MIN_SECONDS", "30"))  # at most one nginx reload per this
RESYNC_MINUTES = int(os.environ.get("RESYNC_MINUTES", "60"))          # full re-pull, corrects any drift
# "all" = also blocklists. The LAPI's origins filter is case-sensitive and the community list is
# "CAPI" (every other origin is lowercase), so normalise rather than lowercase everything.
ORIGINS = [{"capi": "CAPI"}.get(o.lower(), o.lower()) for o in _list("INCLUDE_ORIGINS", "crowdsec,cscli")]
_ORIGINS_LC = {o.lower() for o in ORIGINS}
TYPES = [t.lower() for t in _list("DECISION_TYPES", "ban")]
STATUS_FILE = os.environ.get("STATUS_FILE", "/status/npm-bouncer.json")
LAN_CIDRS = _list("LAN_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,100.64.0.0/10,"
                               "fc00::/7,fe80::/10,::1/128")
CF_RANGES = _list("CLOUDFLARE_RANGES",  # https://www.cloudflare.com/ips/
                  "173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,"
                  "108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,"
                  "162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,"
                  "2400:cb00::/32,2606:4700::/32,2803:f800::/32,2405:b500::/32,2405:8100::/32,"
                  "2a06:98c0::/29,2c0f:f248::/32")

MARKER = "# crowdsec-npm-bouncer"
HOOKS = {
    # file name: (content we create, text that shows the hook is already there)
    "http.conf": (
        f"{MARKER}: managed file. Defines $crowdsec_banned from the ban list.\n"
        "geo $crowdsec_banned {\n"
        "    default 0;\n"
        f"    include {NGINX_CUSTOM_PATH}/crowdsec-bans*.map;  # wildcard: a missing file is not an error\n"
        "}\n",
        "$crowdsec_banned {",
    ),
    "server_proxy.conf": (
        f"{MARKER}: managed file. Included in every NPM proxy host.\n"
        "if ($crowdsec_banned) {\n"
        "    return 403;\n"
        "}\n",
        "if ($crowdsec_banned)",
    ),
}

_never = [ipaddress.ip_network(c) for c in LAN_CIDRS + CF_RANGES]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# decisions -> validated networks
# ---------------------------------------------------------------------------
def to_network(scope: str, value: str):
    """Decision -> ip_network, or None if it's malformed or must never be blocked."""
    try:
        if scope == "ip":
            addr = ipaddress.ip_address(value)
            if addr.version == 6 and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            net = ipaddress.ip_network(addr)
        elif scope == "range":
            net = ipaddress.ip_network(value, strict=False)
        else:
            return None
    except ValueError:
        return None
    a = net.network_address
    if a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local or a.is_reserved:
        return None
    if any(net.overlaps(n) for n in _never if n.version == net.version):
        return None  # LAN, or a Cloudflare edge (blocking that would cut off every proxied visitor)
    return net


class Bans:
    """value -> decision ids. A value stays banned while any of its decisions is active."""

    def __init__(self):
        self.ids: dict[str, set[int]] = {}
        self.skipped = 0

    def reset(self):
        self.ids, self.skipped = {}, 0

    def wanted(self, d: dict) -> str | None:
        if (d.get("type") or "").lower() not in TYPES:
            return None
        if "all" not in ORIGINS and (d.get("origin") or "").lower() not in _ORIGINS_LC:
            return None
        net = to_network((d.get("scope") or "").lower(), d.get("value") or "")
        if net is None:
            self.skipped += 1
            return None
        return str(net.network_address) if net.num_addresses == 1 else str(net)

    def apply(self, data: dict):
        for d in data.get("new") or []:
            key = self.wanted(d)
            if key:
                self.ids.setdefault(key, set()).add(d.get("id"))
        for d in data.get("deleted") or []:
            key = self.wanted(d)
            if key and key in self.ids:
                self.ids[key].discard(d.get("id"))
                if not self.ids[key]:
                    del self.ids[key]

    def map_text(self) -> str:
        lines = [f"{MARKER}: generated ban list, rewritten automatically. {len(self.ids)} entries.\n"]
        lines += [f"{k} 1;\n" for k in sorted(self.ids)]
        return "".join(lines)


# ---------------------------------------------------------------------------
# LAPI
# ---------------------------------------------------------------------------
_ctx = ssl.create_default_context() if VERIFY_TLS else ssl._create_unverified_context()


def fetch(startup: bool) -> dict:
    q = {"startup": "true" if startup else "false"}
    if "all" not in ORIGINS:
        q["origins"] = ",".join(ORIGINS)
    req = urllib.request.Request(f"{LAPI_URL}/v1/decisions/stream?{urlencode(q)}",
                                 headers={"X-Api-Key": API_KEY, "User-Agent": "crowdsec-npm-bouncer/1.0"})
    with urllib.request.urlopen(req, timeout=30, context=_ctx) as r:
        return json.load(r) or {}


# ---------------------------------------------------------------------------
# NPM side: files and reload
# ---------------------------------------------------------------------------
def write_atomic(path: str, text: str) -> bool:
    """Write only if the content changed. Returns True if the file changed."""
    try:
        with open(path) as f:
            if f.read() == text:
                return False
    except FileNotFoundError:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return True


def ensure_hooks() -> tuple[bool, list[str]]:
    """Create our hook files if absent. Returns (created_any, manual_steps)."""
    created, manual = False, []
    for name, (content, needle) in HOOKS.items():
        path = os.path.join(CUSTOM_DIR, name)
        try:
            with open(path) as f:
                existing = f.read()
        except FileNotFoundError:
            write_atomic(path, content)
            log.info("created %s", path)
            created = True
            continue
        if needle not in existing:
            body = "".join(ln for ln in content.splitlines(keepends=True) if not ln.startswith(MARKER))
            manual.append(f"{name} already exists and isn't ours: add this to it:\n{body}")
    return created, manual


def nginx_master() -> int | None:
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    if f.read().startswith(b"nginx: master process"):
                        return int(pid)
            except OSError:
                continue
    return None


def reload_nginx() -> str | None:
    """Graceful reload. Returns an error message, or None on success."""
    pid = nginx_master()
    if pid is None:
        return ("can't see NPM's nginx: is `pid: container:<npm container name>` set and is NPM running? "
                "The ban list is still written and applies on NPM's next reload or restart.")
    try:
        os.kill(pid, signal.SIGHUP)
    except OSError as e:
        return f"could not signal nginx (pid {pid}): {e}"
    log.info("reloaded nginx (pid %s)", pid)
    return None


# ---------------------------------------------------------------------------
def write_status(**st):
    try:
        os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
        write_atomic(STATUS_FILE, json.dumps({"updated": now_iso(), **st}, indent=1))
    except OSError as e:
        log.debug("status file: %s", e)


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if not LAPI_URL or not API_KEY:
        log.error("LAPI_URL and BOUNCER_API_KEY are required (cscli bouncers add npm-bouncer on OPNsense)")
        write_status(ok=False, error="LAPI_URL or BOUNCER_API_KEY not set")
        sys.exit(1)
    os.makedirs(CUSTOM_DIR, exist_ok=True)
    map_path = os.path.join(CUSTOM_DIR, MAP_NAME)
    bans = Bans()
    need_full, last_full = True, 0.0
    pending_reload, last_reload, last_reload_iso = False, 0.0, None
    error, manual, reload_error = None, [], None
    log.info("starting: LAPI %s, origins %s, types %s, writing %s", LAPI_URL, ORIGINS, TYPES, map_path)
    while True:
        try:
            if need_full or time.monotonic() - last_full > RESYNC_MINUTES * 60:
                data = fetch(startup=True)
                bans.reset()
                need_full, last_full = False, time.monotonic()
            else:
                data = fetch(startup=False)
            bans.apply(data)
            # map first, so the hooks never reference a list that isn't there yet
            if write_atomic(map_path, bans.map_text()):
                log.info("ban list now has %d entries", len(bans.ids))
                pending_reload = True
            created, manual = ensure_hooks()
            for m in manual:
                log.warning(m)
            pending_reload |= created
            error = None
        except Exception as e:  # LAPI down, bad key, disk full...: keep the last list, retry with a full sync
            if str(e) != error:
                log.warning("sync failed: %s", e)
            error, need_full = str(e), True
        if pending_reload and time.monotonic() - last_reload >= RELOAD_MIN_SECONDS:
            reload_error = reload_nginx()
            if reload_error:
                log.warning(reload_error)
            else:
                pending_reload, last_reload, last_reload_iso = False, time.monotonic(), now_iso()
        write_status(
            ok=error is None and reload_error is None and not manual,
            error=error or reload_error or ("; ".join(manual) if manual else None),
            banned=len(bans.ids), skipped=bans.skipped, origins=ORIGINS, types=TYPES,
            last_reload=last_reload_iso, reload_pending=pending_reload, nginx_master=nginx_master(),
            map_path=map_path,
        )
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
