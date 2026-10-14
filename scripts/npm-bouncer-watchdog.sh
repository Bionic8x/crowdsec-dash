#!/bin/bash
# npm-bouncer watchdog: bring crowdsec-npm-bouncer back after NPM restarts or updates.
#
# Why this is needed: the bouncer shares NPM's process list (`pid: container:<npm>`) so it
# can reload nginx without the Docker socket. When NPM stops (Appdata Backup, Auto Update
# Applications, a manual restart), Docker kills the bouncer too, and its restart policy
# can't bring it back: the restart is attempted while NPM is still down, or it points at
# the old NPM container that an update replaced. Recreating the bouncer fixes it.
#
# What it does, every run:
#   NPM not running           -> nothing (a backup or update is in progress; try next run)
#   bouncer running and attached to the current NPM -> nothing
#   otherwise                 -> recreate the bouncer with the same compose project it came from
#
# Install on Unraid: Settings > User Scripts > Add New Script ("npm-bouncer-watchdog"),
# paste this file in, set the schedule to Custom: */5 * * * *
# Run it once by hand ("Run Script") to check the output.

BOUNCER="${BOUNCER:-crowdsec-npm-bouncer}"
# NPM's container name. Empty = read NPM_CONTAINER from the stack's .env (or the compose default).
NPM_CONTAINER="${NPM_CONTAINER:-}"

log() { echo "$(date '+%F %T') npm-bouncer-watchdog: $*"; logger -t npm-bouncer-watchdog "$*" 2>/dev/null || true; }
label() { docker inspect -f "{{index .Config.Labels \"$2\"}}" "$1" 2>/dev/null; }

# One run at a time (a slow recreate must not overlap the next cron tick).
exec 9>/tmp/npm-bouncer-watchdog.lock
flock -n 9 || exit 0

if ! docker inspect "$BOUNCER" >/dev/null 2>&1; then
    log "no container named $BOUNCER (npm-bouncer not enabled?), nothing to do"
    exit 0
fi

# The compose project the bouncer belongs to (works for Compose Manager stacks too).
project=$(label "$BOUNCER" com.docker.compose.project)
workdir=$(label "$BOUNCER" com.docker.compose.project.working_dir)
files=$(label "$BOUNCER" com.docker.compose.project.config_files)
envfile=$(label "$BOUNCER" com.docker.compose.project.environment_file)
service=$(label "$BOUNCER" com.docker.compose.service)
if [ -z "$project" ] || [ -z "$workdir" ]; then
    log "$BOUNCER wasn't created by docker compose; recreate it by hand"
    exit 1
fi

if [ -z "$NPM_CONTAINER" ]; then
    for f in ${envfile//,/ } "$workdir/.env"; do
        [ -f "$f" ] && NPM_CONTAINER=$(sed -n 's/^[[:space:]]*NPM_CONTAINER=//p' "$f" | tail -n1 | tr -d "\"'\r")
        [ -n "$NPM_CONTAINER" ] && break
    done
    NPM_CONTAINER="${NPM_CONTAINER:-Nginx-Proxy-Manager-Official}"
fi

if [ "$(docker inspect -f '{{.State.Running}}' "$NPM_CONTAINER" 2>/dev/null)" != "true" ]; then
    log "NPM ($NPM_CONTAINER) isn't running; waiting for it"
    exit 0
fi

npm_id=$(docker inspect -f '{{.Id}}' "$NPM_CONTAINER")
running=$(docker inspect -f '{{.State.Running}}' "$BOUNCER")
target=$(docker inspect -f '{{.HostConfig.PidMode}}' "$BOUNCER"); target=${target#container:}
case "$target" in
    "$NPM_CONTAINER"|"/$NPM_CONTAINER"|"$npm_id"|"${npm_id:0:12}") attached=true ;;
    *) attached=false ;;
esac

if [ "$running" = "true" ] && [ "$attached" = "true" ]; then
    exit 0  # healthy: stay quiet
fi

if [ "$running" != "true" ]; then why="not running"; else why="attached to an old NPM container"; fi
log "$BOUNCER is $why; recreating it (project $project)"

args=(-p "$project" --project-directory "$workdir")
IFS=',' read -ra cfgs <<< "$files"
for c in "${cfgs[@]}"; do [ -n "$c" ] && args+=(-f "$c"); done
IFS=',' read -ra envs <<< "$envfile"
for e in "${envs[@]}"; do [ -f "$e" ] && args+=(--env-file "$e"); done

if docker compose "${args[@]}" up -d --force-recreate --no-deps "${service:-npm-bouncer}"; then
    log "recreated $BOUNCER"
else
    log "recreate failed; run: cd $workdir && docker compose up -d --force-recreate npm-bouncer"
    exit 1
fi
