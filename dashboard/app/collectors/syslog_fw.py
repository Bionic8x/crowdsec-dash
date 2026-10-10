"""
OPNsense firewall log receiver (UDP syslog).

OPNsense's packet filter logs every packet that hits a rule with "log" enabled
via a program called `filterlog`. With remote logging pointed here, we receive
lines like (RFC 5424 shown; the older BSD format works too):

  <134>1 2026-10-10T14:16:09-04:00 OPNsense.lan filterlog 3243 - [meta sequenceId="7"]
  96,,,02f4bab031b57d1e30553ce08e0c5e6a,igb0,match,block,in,4,0x0,,242,54321,0,none,6,tcp,40,
  185.220.101.4,203.0.113.10,49152,22,0,S,1234567,,1024,,

The CSV part is what matters. Field order (shared by pfSense and OPNsense):
  0 rule number, 1 sub-rule, 2 anchor, 3 rule label (a hash on OPNsense),
  4 interface, 5 reason, 6 action (pass/block), 7 direction (in/out), 8 IP version
  IPv4 then: 9 tos, 10 ecn, 11 ttl, 12 id, 13 offset, 14 flags, 15 proto id,
             16 proto name, 17 length, 18 src, 19 dst, then ports for tcp/udp
  IPv6 then: 9 class, 10 flow label, 11 hop limit, 12 proto name, 13 proto id,
             14 length, 15 src, 16 dst, then ports for tcp/udp

A drop is tagged "crowdsec" when the source IP currently has a CrowdSec decision
(or the rule label matches FW_CROWDSEC_LABELS) - that's how we show
"the firewall actually blocked this banned IP N times".
"""
import asyncio
import logging
import re
from datetime import datetime, timedelta

from .. import geoip, status
from ..config import settings
from ..db import db, iso, now_iso
from ..timeutil import norm_ts
from .lapi import active_index

log = logging.getLogger("syslog")


def extract_csv(msg: str) -> str | None:
    """Find the filterlog CSV payload inside a syslog message."""
    i = msg.find("filterlog")
    if i < 0:
        return None
    # the CSV is the longest comma-heavy token after the program name
    for token in reversed(msg[i:].split()):
        if token.count(",") >= 8:
            return token
    return None


def parse_filterlog(csv: str) -> dict | None:
    f = csv.split(",")
    if len(f) < 9:
        return None
    rec = {"label": f[3], "iface": f[4], "action": f[6], "dir": f[7], "ipver": f[8]}
    try:
        if f[8] == "4":
            proto, src, dst, rest = f[16], f[18], f[19], f[20:]
        elif f[8] == "6":
            proto, src, dst, rest = f[12], f[15], f[16], f[17:]
        else:
            return None
    except IndexError:
        return None
    rec.update(proto=proto.lower(), src=src, dst=dst, sport=None, dport=None)
    if rec["proto"] in ("tcp", "udp") and len(rest) >= 2:
        rec["sport"] = int(rest[0]) if rest[0].isdigit() else None
        rec["dport"] = int(rest[1]) if rest[1].isdigit() else None
    return rec


_BSD = re.compile(r"^<\d+>([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})")


def syslog_time(msg: str) -> str:
    """RFC5424 messages carry a full ISO timestamp with offset. BSD/RFC3164 ones ('Oct 10 14:16:09')
    have no year or zone: we assume this year and the container's local time zone (set TZ!)."""
    head = msg[:60]
    ts = norm_ts(head)
    if ts:
        return ts
    m = _BSD.match(head)
    if m:
        try:
            now = datetime.now().astimezone()
            dt = datetime.strptime(f"{now.year} {m[1]} {m[2]} {m[3]}", "%Y %b %d %H:%M:%S").replace(tzinfo=now.tzinfo)
            if dt > now + timedelta(days=1):  # 'Dec 31' received on Jan 1st
                dt = dt.replace(year=now.year - 1)
            return iso(dt)
        except ValueError:
            pass
    return now_iso()


class Receiver(asyncio.DatagramProtocol):
    def __init__(self):
        self.buffer: list[tuple] = []
        self.packets = 0
        self.kept = 0
        self.unparsed = 0

    def datagram_received(self, data: bytes, addr):
        self.packets += 1
        msg = data.decode("utf-8", "replace")
        csv = extract_csv(msg)
        if not csv:
            return
        rec = parse_filterlog(csv)
        if not rec:
            self.unparsed += 1
            return
        if settings.fw_actions and rec["action"] not in settings.fw_actions:
            return
        if settings.fw_interfaces and rec["iface"] not in settings.fw_interfaces:
            return
        if settings.fw_ignore_private_src and geoip.is_private(rec["src"]):
            return
        cs = int(active_index.contains(rec["src"]) or (rec["label"] in settings.fw_crowdsec_labels))
        geo = geoip.lookup(rec["src"])
        self.buffer.append((
            syslog_time(msg), rec["action"], rec["iface"], rec["dir"], rec["proto"], rec["src"], rec["sport"],
            rec["dst"], rec["dport"], rec["label"], cs, geo["country"], geo["lat"], geo["lon"],
        ))
        self.kept += 1

    def flush(self):
        rows, self.buffer = self.buffer, []
        db.executemany(
            "INSERT INTO fw_events(ts,action,iface,dir,proto,src_ip,src_port,dst_ip,dst_port,label,crowdsec,country,lat,lon) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows,
        )


async def run():
    if not settings.syslog_enabled:
        return
    status.status["syslog"]["enabled"] = True
    loop = asyncio.get_running_loop()
    receiver = Receiver()
    try:
        await loop.create_datagram_endpoint(lambda: receiver, local_addr=("0.0.0.0", settings.syslog_port))
    except OSError as e:
        status.fail("syslog", f"cannot listen on udp/{settings.syslog_port}: {e}")
        return
    status.ok("syslog", listening=f"udp/{settings.syslog_port}")
    while True:
        await asyncio.sleep(1)
        try:
            await asyncio.to_thread(receiver.flush)
            if receiver.packets:
                status.ok("syslog", packets=receiver.packets, kept=receiver.kept, unparsed=receiver.unparsed)
        except Exception as e:
            status.fail("syslog", e)
