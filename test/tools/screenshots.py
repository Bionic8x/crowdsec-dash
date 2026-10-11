"""
README screenshots, taken from the demo stack (test/README.md, "Demo data") with Playwright's
Chromium, which has color-emoji fonts for the country flags. Writes docs/screenshots/*.png.
"""
import os
import sys

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(__file__))
import demo  # noqa: E402  same seed as the demo data, so we know which IP to feature

BASE = os.environ.get("DASH_URL", "http://172.31.99.20:8088")  # by IP: host names other than ALLOWED_HOSTS get 421
OUT = os.environ.get("OUT", "/out")
FEATURED = next(ip for ip, (_, _, web) in demo.BANNED if web)
SHOTS = [  # (file, route, viewport width, height)
    ("overview", "#/overview?range=24h", 1440, 1250),
    ("decisions", "#/decisions?state=active", 1640, 860),
    ("ip", f"#/ip/{FEATURED}", 1440, 1000),
    ("hosts", "#/hosts?range=24h", 1440, 1080),
    ("firewall", "#/firewall?range=24h", 1440, 1000),
]

with sync_playwright() as p:
    browser = p.chromium.launch()
    for name, route, width, height in SHOTS:
        ctx = browser.new_context(viewport={"width": width, "height": height}, color_scheme="dark", device_scale_factor=1)
        page = ctx.new_page()
        page.goto(f"{BASE}/{route}")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1500)  # chart transitions
        page.screenshot(path=os.path.join(OUT, f"{name}.png"))
        ctx.close()
        print("saved", name)
    browser.close()
