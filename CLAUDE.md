# crowdsec-dash

A dashboard plus CrowdSec agent plus optional NPM bouncer, for a CrowdSec LAPI running on OPNsense. README.md, SETUP.md and HOW-IT-WORKS.md describe the design; read the relevant one before changing behaviour.

## Rules
- This repo is PUBLIC. Never commit real domains, LAN IPs, hostnames, tokens or log excerpts.
  - Use `example.com` and documentation or demo address ranges.
  - Screenshots must come from the demo stack (`sh test/demo.sh`), never from a real deployment.
- Test changes on the local stack in `test/` (see test/README.md) against its throwaway LAPI before calling them done. In Git Bash, run `export MSYS_NO_PATHCONV=1` first.
- Keep `.env.example`, `docker-compose.yml` and SETUP.md in step. A new setting needs all three.
- `crowdsecurity/crowdsec:latest` is intentional. If a release breaks the agent, pin the last good version and note it in the compose comment.
- The bouncer's security model depends on its compose settings: `cap_drop: [ALL]`, `cap_add: [KILL, DAC_OVERRIDE]`, `read_only` and `no-new-privileges`. Don't widen them without explaining why.
- Personal deployment details (addresses, paths, how the real server is updated) go in `CLAUDE.local.md`, which is never committed.
