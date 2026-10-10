# Local test stack

Runs the real `docker-compose.yml` on any Docker host (e.g. Docker Desktop) against a
**throwaway** CrowdSec LAPI instead of OPNsense, with fake NPM logs and a fake OPNsense
syslog sender. Nothing touches your real firewall.

Run everything from the repo root. In Git Bash, `export MSYS_NO_PATHCONV=1` first so paths like
`/dev/null` reach the containers unchanged.

```sh
C="docker compose --env-file test/.env.test -f docker-compose.yml -f test/docker-compose.test.yml"
```

## 1. Test settings

Create `test/.env.test` (git-ignored) from `.env.example` with these differences:

```
BIND_IP=127.0.0.1
LAPI_URL=http://lapi:8080
NPM_LOGS=npmlogs                      # the shared log volume from the test compose file
SYSLOG_ALLOWED_SOURCES=172.31.99.10   # the fake OPNsense container
ALLOW_WRITE=true
```

Set random values for `DASH_MACHINE_PASSWORD`, `AGENT_MACHINE_PASSWORD` and `DASH_PASSWORD`
(`openssl rand -hex 24`).

## 2. Start

```sh
$C build crowdsec-dash
$C up -d lapi
set -a; . test/.env.test; set +a
$C exec -T lapi cscli machines add "$DASH_MACHINE_ID"  --password "$DASH_MACHINE_PASSWORD"  -f /dev/null
$C exec -T lapi cscli machines add "$AGENT_MACHINE_ID" --password "$AGENT_MACHINE_PASSWORD" -f /dev/null
$C run --rm npm seed                       # NPM log files with some normal traffic
$C up -d crowdsec-dash crowdsec-agent
```

Open http://127.0.0.1:8088 (user `admin`, password `DASH_PASSWORD`).

## 3. Make things happen

```sh
$C run --rm npm bruteforce 203.0.113.50 10        # agent bans it (local/jellyfin-npm-bf)
$C run --rm npm traffic 50                        # normal requests
$C run --rm opnsense --count 30                   # firewall drops, kept
$C run --rm rogue --count 25                      # same packets from a non-allowed sender, rejected
$C run --rm opnsense --count 7 --src 203.0.113.50 # drops from the banned IP, tagged "CrowdSec"
$C exec -T lapi cscli decisions list              # what the LAPI thinks is banned
```

## 4. Clean up

```sh
$C --profile tools down -v      # containers, network and volumes
rm -rf test/data
```
