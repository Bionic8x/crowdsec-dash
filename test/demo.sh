#!/bin/sh
# Demo stack for README screenshots: throwaway LAPI, fake Cloudflare API, a day of made-up data
# (example.com hosts, generated IPs). Run from the repo root; needs test/.env.test (test/README.md).
#
#   sh test/demo.sh           start fresh, load the data, take docs/screenshots/*.png
#   sh test/demo.sh down      remove it all again
set -e
export MSYS_NO_PATHCONV=1   # Git Bash on Windows: keep /dev/null and /logs as they are
[ -f test/demo-opnsense.env ] || echo "DEMO_OPNSENSE_PASSWORD=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')" > test/demo-opnsense.env
C="docker compose --env-file test/.env.test --env-file test/demo-opnsense.env -f docker-compose.yml -f test/docker-compose.test.yml -f test/docker-compose.demo.yml"

$C --profile tools down -v
rm -rf test/demo-data
[ "$1" = down ] && exit 0

set -a; . test/.env.test; . test/demo-opnsense.env; set +a
D="$C --profile tools run --rm -T demo"
# machines and logs first, so the dashboard starts without login/"no files" errors
$C build crowdsec-dash mock-cloudflare
$C up -d lapi mock-cloudflare
sleep 10
$C exec -T lapi cscli machines add "$DASH_MACHINE_ID" --password "$DASH_MACHINE_PASSWORD" -f /dev/null
$C exec -T lapi cscli machines add "$AGENT_MACHINE_ID" --password "$AGENT_MACHINE_PASSWORD" -f /dev/null
$C exec -T lapi cscli machines add opnsense --password "$DEMO_OPNSENSE_PASSWORD" -f /dev/null
$D npm /logs
$C up -d crowdsec-dash

# the syslog listener starts after the GeoIP download; packets sent before that are lost
until curl -s http://127.0.0.1:8088/api/status | grep -q '"listening"'; do sleep 2; done

$D syslog              # before the bans, so the day's drops aren't tagged CrowdSec
$D alerts              # ~4 minutes: bans arrive 12 s apart
sleep 15               # dashboard picks up the last bans (LAPI_POLL_SECONDS=10)
$D after-ban /logs     # banned IPs coming back: tagged drops, NPM bouncer 403s
sleep 5
$C --profile tools run --rm -T shots
echo "open http://127.0.0.1:8088 (no password); screenshots in docs/screenshots/"
