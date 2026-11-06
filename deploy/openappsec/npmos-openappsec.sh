#!/bin/bash
# NPMOS: the processes of the openappsec container (deploy/openappsec/Dockerfile):
#   - the open-appsec agent (/npmos-entry.sh: the settings of WAF -> Agent, then the upstream entry.sh);
#   - its shared storage (decisions.data, learning state) and tuning (statistics, suggestions) services;
#   - npmos-control, the Docker API for the GUI (only when the Docker socket is mounted).
# Each is started again when it stops. npmos-control restarts the agent with a TERM to the pid in
# /run/npmos-agent.pid (its settings are read at its start). TERM to the container stops them all.
# The container owns the network namespace npmos joins: the services listen on ports nginx leaves free.
set -u

SHARED_STORAGE_PORT="${NPMOS_SHARED_STORAGE_PORT:-7811}"
TUNING_PORT="${NPMOS_TUNING_PORT:-7813}"
AGENT_PID_FILE=/run/npmos-agent.pid

log() { echo "npmos-openappsec: $*" >&2; }

stopping=0
stop() {
    stopping=1
    # ignored here (the TERM to the group below reaches this shell too); the subshells have their own trap
    trap '' TERM INT
    log "stopping"
    # the agent first (its entry.sh stops the watchdog and the nano services), then the rest
    [ -s "$AGENT_PID_FILE" ] && kill -TERM "$(cat "$AGENT_PID_FILE")" 2>/dev/null
    sleep 2
    kill -TERM 0 2>/dev/null
    wait
    exit 0
}
trap stop TERM INT

# keep NAME COMMAND...: runs COMMAND again 5 s after it stops
keep() {
    local name="$1"
    shift
    (
        trap 'exit 0' TERM
        while true; do
            "$@"
            log "$name stopped (exit $?), starting it again in 5 s"
            sleep 5
        done
    ) &
}

shared_storage() {
    cd /opt/appsec-shared-storage || return 1
    SERVER_PORT="$SHARED_STORAGE_PORT" SERVER_ALTERNATIVE_PORT="$((SHARED_STORAGE_PORT + 1))" exec ./app
}

tuning() {
    cd /opt/appsec-tuning || return 1
    # the database password from its file (npmos-init), not in the environment of the container
    local password=""
    [ -r "${QUERY_DB_PASSWORD_FILE:-}" ] && password=$(cat "$QUERY_DB_PASSWORD_FILE")
    SERVER_PORT="$TUNING_PORT" SHARED_STORAGE_HOST="127.0.0.1:$SHARED_STORAGE_PORT" QUERY_DB_PASSWORD="$password" \
        exec ./app
}

agent() {
    /npmos-entry.sh "$@" &
    echo $! > "$AGENT_PID_FILE"
    wait $!
}

keep shared-storage shared_storage
keep tuning tuning
if [ -S /var/run/docker.sock ]; then
    keep npmos-control node /opt/npmos-control/server.js
else
    log "no Docker socket: npmos-control (System -> Services) is off"
fi

# the agent in the foreground loop: a TERM from npmos-control restarts it, a TERM to the container ends here
while [ "$stopping" = 0 ]; do
    agent "$@"
    code=$?
    [ "$stopping" = 1 ] && break
    log "the agent stopped (exit $code), starting it again"
    sleep 2
done
wait
