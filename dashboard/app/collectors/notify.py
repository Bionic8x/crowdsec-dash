"""
Discord notifications for new bans, sent through Notifiarr's Passthrough integration.

Why here and not in CrowdSec's own notification plugins: those run where the LAPI's
profiles are (OPNsense), know nothing about your sites, and send one message per alert.
The dashboard already has every decision in its DB, plus what it learned on the side:
which site was attacked, whether that site sits behind Cloudflare, country and network.

How it avoids flooding Discord:
  * It reads the decisions table (filled by the LAPI collector) and remembers the highest
    decision id it has handled (`notify_last_decision_id` in kv). On the very first run it
    records the current highest id and sends nothing, and the mark survives restarts.
  * Decisions created more than MAX_AGE ago (the dashboard was down) are only counted.
  * One message per IP per poll: an IP that trips 7 scenarios at once is one message.
  * At most NOTIFY_MAX_PER_HOUR messages an hour. The rest are counted and summed up in
    one message when the hour is over ("+812 more bans, mostly <network>").

Notifiarr wants the API key in the URL path, and requests puts URLs in its error messages,
so every error passes through _scrub() before it's logged or shown on the Status page.
"""
import asyncio
import fnmatch
import json
import logging
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import requests

from .. import status
from ..config import settings
from ..db import db, iso, now_iso, utcnow
from . import cloudflare

log = logging.getLogger("notify")
# urllib3 logs request paths at DEBUG (LOG_LEVEL=DEBUG), and our path holds the API key
logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)

MAX_AGE = timedelta(minutes=15)
WINDOW = timedelta(hours=1)
COLORS = {"web": "E5534B", "firewall": "F0883E", "manual": "4C8BF5", "summary": "8B949E", "test": "3FB950"}

session = requests.Session()
session.headers["User-Agent"] = "crowdsec-dash/1.0"
totals = {"sent": 0, "held": 0, "muted": 0}  # since the dashboard started, for the Status page


def enabled() -> bool:
    return bool(settings.notifiarr_api_key and settings.notifiarr_channel_id)


def _scrub(text) -> str:
    text = str(text)
    return text.replace(settings.notifiarr_api_key, "<api key>") if settings.notifiarr_api_key else text


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------
def send(text: dict, color: str, event: str):
    """POST one Passthrough message. Raises RuntimeError with a scrubbed message on failure."""
    payload = {
        "notification": {"name": "CrowdSec", "event": event},
        "discord": {"color": color, "text": {**text, "footer": "crowdsec-dash"},
                    "ids": {"channel": int(settings.notifiarr_channel_id)}},
    }
    url = f"{settings.notifiarr_url}/{settings.notifiarr_api_key}"
    err = None
    for attempt in range(2):
        if attempt:
            time.sleep(3)
        try:
            r = session.post(url, json=payload, timeout=20)
        except requests.RequestException as e:
            err = f"Notifiarr unreachable: {_scrub(e)}"
            continue
        if r.status_code >= 500:
            err = f"Notifiarr answered {r.status_code}: {_scrub(r.text[:200])}"
            continue
        try:
            result = r.json().get("result")
        except (ValueError, AttributeError):
            result = None
        if r.status_code >= 400 or result not in (None, "success"):
            raise RuntimeError(f"Notifiarr refused the message ({r.status_code}): {_scrub(r.text[:200])}")
        return
    raise RuntimeError(err)


def send_test():
    send({"title": "Test from crowdsec-dash",
          "description": "Ban notifications from crowdsec-dash will arrive in this channel."},
         COLORS["test"], f"test-{int(time.time())}")


# ---------------------------------------------------------------------------
# Building messages
# ---------------------------------------------------------------------------
def _flag(cc) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper()) + " "


def _unix(ts: str) -> int:
    return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())


def _is_manual(origin) -> bool:
    return (origin or "").lower().startswith("cscli") or (origin or "").lower() == "console"


def _ban_message(ip: str, rows: list[dict]) -> tuple[dict, str]:
    first = rows[0]
    manual = _is_manual(first["origin"])
    sites = sorted({r["target_host"] for r in rows if r["target_host"]})
    kind = "manual" if manual else "web" if sites else "firewall"
    scenarios = sorted({r["scenario"] or "?" for r in rows})
    title = f"Banned {ip}" + (f" ({', '.join(sorted({r['type'] for r in rows if r['type'] != 'ban'}))})"
                              if any(r["type"] != "ban" for r in rows) else "")
    fields = [{"title": "Reason (manual ban)" if manual else "Scenario" + ("s" if len(scenarios) > 1 else ""),
               "text": "\n".join(scenarios)[:1000], "inline": False}]
    for host in sites[:3]:
        proxied = cloudflare.host_proxied(host)
        note = ("\nBehind Cloudflare: the firewall ban can't stop it, only the NPM bouncer can." if proxied
                else "\nDNS-only: the firewall blocks it." if proxied is False else "")
        fields.append({"title": "Site", "text": host + note, "inline": False})
    network = first["as_name"] and first["as_name"] + (f" (AS{first['as_number']})" if first["as_number"] else "")
    origin = " · ".join(x for x in (first["country"] and _flag(first["country"]) + first["country"], network) if x)
    if origin:
        fields.append({"title": "From", "text": origin, "inline": True})
    machines = sorted({r["machine_id"] for r in rows if r["machine_id"]})
    if machines and not manual:
        events = sum(r["events_count"] or 0 for r in {r["alert_id"]: r for r in rows}.values())
        fields.append({"title": "Detected by", "text": ", ".join(machines) + (f"\n{events} events" if events else ""),
                       "inline": True})
    until = max(r["until"] for r in rows)
    fields.append({"title": "Ban", "text": f"{first['duration'] or '?'}, ends <t:{_unix(until)}:R>", "inline": True})
    text = {"title": title, "fields": fields}
    if settings.notify_dash_url:
        text["description"] = f"[Open in the dashboard]({settings.notify_dash_url}/#/ip/{ip})"
    return text, COLORS[kind]


def _summary_message(win: dict) -> dict:
    top = lambda c: "\n".join(f"{n} × {k}" for k, n in Counter(c).most_common(5))[:1000] or "?"
    start = datetime.fromisoformat(win["start"].replace("Z", "+00:00"))
    return {
        "title": f"{win['held']} more banned IP{'s' if win['held'] != 1 else ''} not sent one by one",
        "description": (f"Between <t:{int(start.timestamp())}:t> and <t:{int((start + WINDOW).timestamp())}:t>. "
                        f"Messages are limited to {settings.notify_max_per_hour} an hour (NOTIFY_MAX_PER_HOUR)."
                        + (f"\n{win['failed']} of them because Notifiarr could not be reached." if win.get("failed") else "")),
        "fields": [{"title": "Scenarios", "text": top(win["scenarios"]), "inline": False},
                   {"title": "Networks", "text": top(win["networks"]), "inline": False}],
    }


# ---------------------------------------------------------------------------
# The poll
# ---------------------------------------------------------------------------
def _new_window() -> dict:
    return {"start": now_iso(), "sent": 0, "held": 0, "failed": 0, "scenarios": {}, "networks": {}}


def _hold(win: dict, rows: list[dict], failed=False):
    win["held"] += 1
    win["failed"] += int(failed)
    for r in rows:
        win["scenarios"][r["scenario"] or "?"] = win["scenarios"].get(r["scenario"] or "?", 0) + 1
    net = rows[0]["as_name"] or rows[0]["country"] or "unknown"
    win["networks"][net] = win["networks"].get(net, 0) + 1
    totals["held"] += 1


def notify_once() -> str:
    last = db.get_kv("notify_last_decision_id")
    top_id = db.scalar("SELECT MAX(id) FROM decisions") or 0
    if last is None or int(last) > top_id:  # first run, or the LAPI's database was reset
        db.set_kv("notify_last_decision_id", str(top_id))
        return "started: bans from now on will be sent"
    last = int(last)

    try:
        win = json.loads(db.get_kv("notify_window") or "null") or _new_window()
    except ValueError:
        win = _new_window()
    if utcnow() - datetime.fromisoformat(win["start"].replace("Z", "+00:00")) >= WINDOW:
        if win["held"]:
            send(_summary_message(win), COLORS["summary"], f"summary-{win['start']}")  # on failure: retried next poll
        win = _new_window()

    rows = db.all(
        """SELECT d.id, d.alert_id, d.origin, d.type, d.scope, d.value, d.scenario, d.duration, d.until,
                  d.created_at, d.simulated, a.machine_id, a.country, a.as_number, a.as_name, a.target_host,
                  a.events_count
           FROM decisions d LEFT JOIN alerts a ON a.id = d.alert_id
           WHERE d.id > ? ORDER BY d.id""", (last,))
    by_ip = defaultdict(list)
    old = iso(utcnow() - MAX_AGE)
    for r in rows:
        origin = (r["origin"] or "").lower()
        if r["simulated"] or not (origin == "crowdsec" or (_is_manual(origin) and settings.notify_manual_bans)):
            continue  # simulation mode, blocklists, community list
        if any(fnmatch.fnmatch(r["scenario"] or "", p) for p in settings.notify_exclude_scenarios):
            totals["muted"] += 1
            continue
        by_ip[r["value"]].append(r)

    error = None
    # attacks on your sites first, so a firewall scan burst can't use up the hour's messages
    for ip, ip_rows in sorted(by_ip.items(), key=lambda kv: not any(r["target_host"] for r in kv[1])):
        if error or win["sent"] >= settings.notify_max_per_hour or min(r["created_at"] for r in ip_rows) < old:
            _hold(win, ip_rows, failed=bool(error))
            continue
        try:
            send(*_ban_message(ip, ip_rows), f"ban-{ip}-{ip_rows[0]['id']}")
            win["sent"] += 1
            totals["sent"] += 1
        except Exception as e:  # everything not sent yet goes into the hourly summary instead
            error = e
            _hold(win, ip_rows, failed=True)

    if rows:
        db.set_kv("notify_last_decision_id", str(rows[-1]["id"]))
    db.set_kv("notify_window", json.dumps(win))
    if error:
        raise error
    return ""


async def run():
    if not enabled():
        status.status["notify"]["info"]["note"] = "off (set NOTIFIARR_API_KEY and NOTIFIARR_CHANNEL_ID)"
        return
    status.status["notify"]["enabled"] = True
    while True:
        try:
            note = await asyncio.to_thread(notify_once)
            status.status["notify"]["info"].pop("note", None)
            status.ok("notify", sent=totals["sent"], held_for_summary=totals["held"], muted=totals["muted"],
                      limit_per_hour=settings.notify_max_per_hour,
                      **({"note": note} if note else {}))
        except Exception as e:
            log.warning("notification failed: %s", _scrub(e))
            status.fail("notify", _scrub(e))
        await asyncio.sleep(settings.lapi_poll_seconds)
