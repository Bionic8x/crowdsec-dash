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

# login scenarios (APP: komga | seerr-local | seerr-jellyfin | abs)
$C run --rm npm login-fail komga 198.51.100.11 8 15   # slow attack: 8 guesses, 15 s apart -> banned
$C run --rm npm login-noise komga 198.51.100.21       # normal use with harmless 401s -> no ban
$C exec -T lapi cscli alerts list
```

## 4. Optional: the NPM bouncer against a real, stock NPM

Add `NPM_BOUNCER_API_KEY` and `NPM_TEST_ADMIN_PASSWORD` (random values) to `test/.env.test`, and add
`--profile npm-bouncer` to `$C`.

```sh
$C up -d nginx-proxy-manager
$C exec -T lapi cscli bouncers add npm-bouncer --key "$NPM_BOUNCER_API_KEY"
# NPM 2.13+ has no default login: create the first admin, then a proxy host app.test -> the dashboard,
# with the real-IP line from SETUP.md step 6 as its advanced config
api() { $C exec -T nginx-proxy-manager curl -s -X "$1" "http://127.0.0.1:81/api$2" \
          -H 'Content-Type: application/json' ${TOKEN:+-H "Authorization: Bearer $TOKEN"} ${3:+-d "$3"}; }
api POST /users "{\"name\":\"Test Admin\",\"nickname\":\"admin\",\"email\":\"admin@example.test\",\"roles\":[\"admin\"],\"is_disabled\":false,\"auth\":{\"type\":\"password\",\"secret\":\"$NPM_TEST_ADMIN_PASSWORD\"}}"
TOKEN=$(api POST /tokens "{\"identity\":\"admin@example.test\",\"secret\":\"$NPM_TEST_ADMIN_PASSWORD\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
api POST /nginx/proxy-hosts '{"domain_names":["app.test"],"forward_scheme":"http","forward_host":"crowdsec-dash","forward_port":8088,"access_list_id":0,"certificate_id":0,"ssl_forced":false,"caching_enabled":false,"block_exploits":false,"advanced_config":"real_ip_header CF-Connecting-IP;","meta":{},"allow_websocket_upgrade":false,"http2_support":false,"hsts_enabled":false,"hsts_subdomains":false,"locations":[]}'
$C up -d --build npm-bouncer

$C run --rm npm bruteforce 203.0.113.50 10        # get it banned
$C run --rm probe 203.0.113.50 81.2.69.142        # through NPM "via Cloudflare": expect 403, then 200
$C exec -T nginx-proxy-manager cat /data/nginx/custom/crowdsec-bans.map
```

## 5. Clean up

```sh
$C --profile tools --profile npm-bouncer down -v      # containers, network and volumes
rm -rf test/data
```
