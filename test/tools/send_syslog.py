"""
Send OPNsense filterlog lines over UDP syslog (RFC 5424), like OPNsense remote logging does.

  send_syslog.py [--host crowdsec-dash] [--port 5514] [--count 20] [--src IP]

Without --src, sources are random public IPs knocking on common ports. With --src, every
packet comes from that IP (e.g. a banned one, to see drops tagged "CrowdSec").
"""
import argparse
import random
import socket
import time

SCANNERS = ["185.220.101.4", "45.155.205.233", "193.32.162.157", "89.248.165.52", "162.142.125.10"]
PORTS = [22, 23, 445, 3389, 8080, 5900, 1433]


def filterlog(src, dport, seq):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    ts = ts[:-2] + ":" + ts[-2:]  # +0000 -> +00:00
    csv = (f"96,,,02f4bab031b57d1e30553ce08e0c5e6a,igb0,match,block,in,4,0x0,,242,54321,0,none,6,tcp,40,"
           f"{src},203.0.113.10,{random.randint(1024, 65535)},{dport},0,S,1234567,,1024,,")
    return f'<134>1 {ts} OPNsense.lan filterlog {seq} - [meta sequenceId="{seq}"] {csv}'


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="crowdsec-dash")
    p.add_argument("--port", type=int, default=5514)
    p.add_argument("--count", type=int, default=20)
    p.add_argument("--src")
    a = p.parse_args()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(a.count):
        msg = filterlog(a.src or random.choice(SCANNERS), random.choice(PORTS), i + 1)
        s.sendto(msg.encode(), (a.host, a.port))
    print(f"sent {a.count} filterlog packets to {a.host}:{a.port}")


if __name__ == "__main__":
    main()
