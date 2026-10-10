# Setup

About 30–45 minutes, most of it on OPNsense. Do the steps in order. Each one has a
**check** so you know it worked before moving on.

Assumed addresses (swap in yours):

| Thing | Address |
|---|---|
| OPNsense LAN | `192.168.1.1` |
| Unraid | `192.168.1.20` |

---

## 1. Let other machines reach the LAPI on OPNsense

The CrowdSec plugin's LAPI listens on `127.0.0.1:8080` by default, so only OPNsense itself can reach it.

1. **Services › CrowdSec › Settings**: set the **LAPI listen address** to `192.168.1.1` (keep port `8080`). Click **Apply**.
2. **Firewall › Rules › LAN**: add a *pass* rule, protocol TCP, source `192.168.1.20` (Unraid), destination **This Firewall**, port `8080`.

**Check.** From the Unraid terminal:
```sh
curl -s http://192.168.1.1:8080/v1/heartbeat
```
You should get a small JSON error (401, something like "token is empty"). That's good: the LAPI answered. A timeout means the rule or the listen address is wrong.

## 2. Create two machine accounts on OPNsense

SSH into OPNsense (or use **Diagnostics › Command Prompt**). Generate two passwords and register them:

```sh
openssl rand -hex 24          # run twice, keep both outputs
cscli machines add unraid-npm    --password 'PASSWORD-1' -f /dev/null
cscli machines add crowdsec-dash --password 'PASSWORD-2' -f /dev/null
```

> Keep `-f /dev/null`. Without it, `cscli` overwrites OPNsense's own agent credentials file and the plugin's agent stops working.

- `unraid-npm` is the CrowdSec agent on Unraid that reads NPM's logs.
- `crowdsec-dash` is the dashboard. It reads alerts and decisions. It can only add or remove bans if you set `ALLOW_WRITE=true`.

**Check.** `cscli machines list` shows both, plus OPNsense's own machine.

## 3. Send the firewall log to Unraid

**System › Settings › Logging › Remote › +**

| Field | Value |
|---|---|
| Transport | UDP(4) |
| Applications | **filter (filterlog)** |
| Levels | info, notice, warning, … (all of them is fine) |
| Hostname | `192.168.1.20` |
| Port | `5514` |
| rfc5424 | ✔ (gives full timestamps with time zones) |

Make sure blocked packets are actually logged:

- WAN noise: enable **"Log packets matched from the default block rules"** (System › Settings › Logging, or Firewall › Settings › Advanced on some versions).
- The CrowdSec plugin's own block rules: if your plugin version has an option to **log** its firewall rules, turn it on. If it doesn't, drops from banned IPs are still tagged *CrowdSec*, because the dashboard matches the source IP against active decisions.

## 4. Find NPM's log folder on Unraid

On the Unraid terminal:
```sh
find /mnt/user/appdata -name 'proxy-host-*_access.log' 2>/dev/null | head
```
The folder that prints is your `NPM_LOGS`. Typical values are `/mnt/user/appdata/NginxProxyManager/log` (jlesage image) or `/mnt/user/appdata/<npm>/data/logs` (official image).

## 5. Start the stack on Unraid

Copy this folder to Unraid, for example to `/mnt/user/appdata/crowdsec-dash`. Then:

```sh
cd /mnt/user/appdata/crowdsec-dash
cp .env.example .env
nano .env            # LAPI_URL, the two passwords, NPM_LOGS, FW_INTERFACES
docker compose up -d --build
```

With the **Compose Manager** plugin, create a new stack, point it at this folder, and click **Compose Up**.

**Check.**
```sh
docker logs crowdsec-agent 2>&1 | tail -20       # look for "Starting processing data"
docker exec crowdsec-agent cscli metrics          # Acquisition table lists /var/log/npm/... with lines read
```
On OPNsense, `cscli machines list` should now show `unraid-npm` with a recent heartbeat.

Open **http://192.168.1.20:8088** and go to the **Status** page. Each collector should say *working*. The syslog card shows a packet count once OPNsense blocks something; the internet will oblige within a minute.

## 6. Real visitor IPs for Cloudflare-proxied hosts

For an orange-cloud host, NPM's log shows **Cloudflare's** IP as the client unless NPM is told to trust Cloudflare's header. The dashboard flags this in red on the Overview and Hosts pages ("Real IP: not restored").

NPM already loads Cloudflare's IP ranges as trusted proxies (`set_real_ip_from`). It just reads the wrong header. For each proxied host, open **Edit Proxy Host › Advanced** and add:

```nginx
real_ip_header CF-Connecting-IP;
```

**Check.** New rows on **Proxy traffic** for that host show real visitor IPs instead of a `CF edge` badge, and the host's "Real IP" column turns *ok*.

The `cloudflare-whitelist.yaml` parser in this stack is a safety net, so the agent never bans a Cloudflare edge IP even if this step is missed.

> **Important: bans vs. proxied hosts.** Once real IPs flow, CrowdSec detects attackers on proxied hosts correctly. But OPNsense still can't *block* them, because those connections arrive from Cloudflare. You'll see this on the Decisions page as **Requests after ban**. To enforce bans there, add Cloudflare-side remediation. The official [CrowdSec Cloudflare Worker bouncer](https://docs.crowdsec.net/u/bouncers/cloudflare-workers) is a natural next project.

## 7. Optional: Cloudflare API

Create a token at **Cloudflare › My Profile › API Tokens › Create Token › Custom**:

| Permission | Why |
|---|---|
| Zone › Zone › Read | list your domains |
| Zone › DNS › Read | which hostnames are proxied vs. DNS-only |
| Zone › Analytics › Read | *(only with `CF_FETCH_EVENTS=true`)* what Cloudflare's WAF blocked |

Put it in `.env` as `CF_API_TOKEN`, then run `docker compose up -d`. The **Hosts & Cloudflare** page fills in the Protection column.

## 8. Optional: lock it down

- Set `DASH_PASSWORD` in `.env` to require a login.
- Don't expose port 8088 to the internet. If you want it in NPM, make an internal-only proxy host with an Access List restricted to your LAN.
- `ALLOW_WRITE=true` enables the Ban/Unban buttons. Leave it off until you're comfortable.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Status › LAPI: `login failed (403)` | Wrong machine name or password in `.env`, or the machine was added without `--password`. Re-run step 2. |
| Status › LAPI: connection refused / timeout | LAPI still on 127.0.0.1, or the LAN rule is missing (step 1). |
| Status › NPM: `no files match` | Wrong `NPM_LOGS` path (step 4). |
| `lines_unparsed` keeps growing | Your NPM writes a custom log format. Paste a line into `LINE` in `dashboard/app/collectors/npm_logs.py` and adjust the regex. |
| Syslog packets = 0 | Remote logging target (step 3), Unraid firewall, or port mapping `5514/udp`. |
| Map has dots but no countries | The image was built without internet access. Rebuild with `docker compose build --no-cache crowdsec-dash`. |
| No country / AS info | GeoIP download failed (Status › GeoIP). The container needs outbound access to `download.db-ip.com`. |
| Agent can't connect | `docker logs crowdsec-agent`. Usually `LAPI_URL` or the `unraid-npm` password. |
| Test a scenario | `docker exec crowdsec-agent cscli explain --file /var/log/npm/proxy-host-1_access.log --type nginx-proxy-manager` shows each parser and scenario step for those lines. |
