"""
All settings come from environment variables (set them in docker-compose.yml / .env).

Keeping config in one place means every other module just does
`from .config import settings` and never touches os.environ directly.
"""
import os


def _bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _list(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


class Settings:
    # --- storage -----------------------------------------------------------
    data_dir = os.environ.get("DATA_DIR", "/data")
    db_path = os.environ.get("DB_PATH", os.path.join(data_dir, "dash.db"))
    retention_days = _int("RETENTION_DAYS", 14)

    # --- CrowdSec LAPI (on OPNsense) ----------------------------------------
    # The dashboard logs in as a "machine" (watcher), the same way cscli does.
    lapi_url = os.environ.get("LAPI_URL", "").rstrip("/")
    lapi_machine_id = os.environ.get("LAPI_MACHINE_ID", "crowdsec-dash")
    lapi_password = os.environ.get("LAPI_PASSWORD", "")
    lapi_poll_seconds = _int("LAPI_POLL_SECONDS", 30)
    lapi_lookback = os.environ.get("LAPI_LOOKBACK", "168h")  # first sync window
    lapi_include_capi = _bool("LAPI_INCLUDE_CAPI", False)  # community blocklist is huge
    lapi_verify_tls = _bool("LAPI_VERIFY_TLS", True)

    # --- Nginx Proxy Manager logs -----------------------------------------
    npm_log_dir = os.environ.get("NPM_LOG_DIR", "/npm-logs")
    npm_log_glob = os.environ.get("NPM_LOG_GLOB", "proxy-host-*_access.log")
    npm_backfill_bytes = _int("NPM_BACKFILL_BYTES", 2_000_000)  # read this much history on first start
    npm_ignore_hosts = _list("NPM_IGNORE_HOSTS")
    # query-string parameters whose values are replaced with "REDACTED" before storing (case-insensitive)
    npm_redact_params = [p.lower() for p in _list(
        "NPM_REDACT_PARAMS",
        "api_key,apikey,x-emby-token,x-mediabrowser-token,token,access_token,refresh_token,id_token,auth,"
        "authorization,password,passwd,pwd,pass,secret,key,sig,signature,session,sessionid,sid,code,ticket,otp",
    )]

    # --- OPNsense firewall log (syslog) ------------------------------------
    syslog_enabled = _bool("SYSLOG_ENABLED", True)
    syslog_port = _int("SYSLOG_PORT", 5514)
    syslog_allowed_sources = _list("SYSLOG_ALLOWED_SOURCES")  # IPs/CIDRs allowed to send syslog. empty = anyone
    fw_actions = _list("FW_ACTIONS", "block")          # which filterlog actions to keep
    fw_interfaces = _list("FW_INTERFACES")             # e.g. "igb0" (WAN). empty = all
    fw_ignore_private_src = _bool("FW_IGNORE_PRIVATE_SRC", True)
    fw_crowdsec_labels = _list("FW_CROWDSEC_LABELS")   # rule label/hash(es) of the CrowdSec block rules

    # --- GeoIP -------------------------------------------------------------
    geoip_dir = os.environ.get("GEOIP_DIR", os.path.join(data_dir, "geoip"))
    geoip_auto_download = _bool("GEOIP_AUTO_DOWNLOAD", True)

    # --- Cloudflare (optional) ---------------------------------------------
    cf_api_token = os.environ.get("CF_API_TOKEN", "")
    cf_sync_minutes = _int("CF_SYNC_MINUTES", 60)
    cf_fetch_events = _bool("CF_FETCH_EVENTS", False)  # needs Zone > Analytics > Read
    cf_events_poll_minutes = _int("CF_EVENTS_POLL_MINUTES", 5)

    # --- Dashboard ---------------------------------------------------------
    port = _int("PORT", 8088)
    dash_user = os.environ.get("DASH_USER", "")
    dash_password = os.environ.get("DASH_PASSWORD", "")
    allow_no_auth = _bool("ALLOW_NO_AUTH", False)  # must be set to run without DASH_PASSWORD
    # Host names the dashboard answers to (besides IP addresses and localhost). Blocks DNS rebinding.
    # Comma separated, "*.example.com" wildcards allowed, "*" disables the check.
    allowed_hosts = _list("ALLOWED_HOSTS")
    allow_write = _bool("ALLOW_WRITE", False)  # enables Ban / Unban buttons
    ban_durations = _list("BAN_DURATIONS", "1h,4h,24h,168h")  # what the Ban form may ask for
    lan_cidrs = _list(
        "LAN_CIDRS",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,100.64.0.0/10,fc00::/7,fe80::/10,::1/128",
    )


settings = Settings()
