#!/bin/bash
# NginxionS: agent settings made in the GUI (WAF -> Agent), applied at every start of the agent.
# NginxionS writes them to /ext/appsec/nginxions-agent.env (volume appsec-localconfig) and restarts the
# agent. Only the keys below are read; the file is not sourced.
SETTINGS=/ext/appsec/nginxions-agent.env
CROWDSEC_KEY=/run/secrets/nginxions/crowdsec_bouncer_key

CROWDSEC_ENABLED=false
CROWDSEC_MODE=prevent
NGINXIONS_FAIL_OPEN=true
NGINXIONS_FAIL_OPEN_TIMEOUT_MS=50
if [ -f "$SETTINGS" ]; then
    while IFS='=' read -r key value; do
        case "$key=$value" in
            CROWDSEC_ENABLED=true | CROWDSEC_ENABLED=false) CROWDSEC_ENABLED=$value ;;
            CROWDSEC_MODE=prevent | CROWDSEC_MODE=detect) CROWDSEC_MODE=$value ;;
            NGINXIONS_FAIL_OPEN=true | NGINXIONS_FAIL_OPEN=false) NGINXIONS_FAIL_OPEN=$value ;;
            NGINXIONS_FAIL_OPEN_TIMEOUT_MS=*)
                [[ "$value" =~ ^[0-9]{1,5}$ ]] && NGINXIONS_FAIL_OPEN_TIMEOUT_MS=$value ;;
        esac
    done < "$SETTINGS"
fi

# IP reputation from the local CrowdSec LAPI (bouncer key registered by nginxions-init)
if [ "$CROWDSEC_ENABLED" = true ] && [ -s "$CROWDSEC_KEY" ]; then
    export CROWDSEC_ENABLED=true CROWDSEC_MODE CROWDSEC_AUTH_METHOD=apikey
    export CROWDSEC_API_URL="${CROWDSEC_API_URL:-http://crowdsec:8080/v1/decisions/stream}"
    CROWDSEC_AUTH_DATA=$(cat "$CROWDSEC_KEY")
    export CROWDSEC_AUTH_DATA
else
    [ "$CROWDSEC_ENABLED" = true ] && echo "nginxions: no CrowdSec bouncer key at $CROWDSEC_KEY, CrowdSec stays off" >&2
    unset CROWDSEC_ENABLED
fi

# Fail-open of the nginx attachment: profile settings in settings.json. The agent gets settings only
# from the Check Point cloud, which NginxionS never uses, so the file is ours.
# Not agent.config.log.useBulkMode=false: without bulk mode every log goes to all streams at once on
# the request path, the HTTP transaction handler then neither logs nor blocks (checked in CI).
# orchestration.configTimeoutSeconds: the orchestration waits for the services to confirm a new policy up to 600 s by
# default and checks no update meanwhile; a confirmation lost while the services restart (an agent restart from the
# GUI) held every policy change of the GUI for 10 minutes. 60 s, then the policy is applied again.
mkdir -p /etc/cp/conf
printf '{"agentSettings": [%s, %s, %s]}\n' \
    "{\"key\": \"agent.failOpenState.nginxModule\", \"value\": \"$NGINXIONS_FAIL_OPEN\"}" \
    "{\"key\": \"agent.failOpenTimeout.nginxModule\", \"value\": \"$NGINXIONS_FAIL_OPEN_TIMEOUT_MS\"}" \
    '{"key": "orchestration.configTimeoutSeconds", "value": "60"}' \
    > /etc/cp/conf/settings.json

# a snapshot of what the agent learned, restored in the GUI (Agents -> open-appsec -> Learning -> Snapshots): staged by
# nginxions-control (control/learning.js), put in place of the learned files before the agent reads them
RESTORE=/etc/cp/conf/nginxions-learning-restore
LEARNED=/etc/cp/conf/waap
if [ -d "$RESTORE" ]; then
    mkdir -p "$LEARNED"
    find "$LEARNED" -type f \( -name 4.data -o -name 5.data -o -name 7.data -o -name 9.data -o -name 11.data \) -delete
    if cp -R "$RESTORE/." "$LEARNED/"; then
        echo "nginxions: the learned state of a snapshot is restored" >&2
    else
        echo "nginxions: the learned state of a snapshot could not be restored" >&2
    fi
    rm -rf "$RESTORE"
fi

# what this start applied, for "saved, restart the agent to apply" in the GUI
[ -f "$SETTINGS" ] && cp "$SETTINGS" /ext/appsec/nginxions-agent.applied

# the prometheus nano service of the agent: the metrics of its services on 127.0.0.1:7465/metrics, which NginxionS shows
# in WAF -> Agent (waf/metrics.js); local only, nothing is sent anywhere
export PROMETHEUS=true

exec /cp-nano-agent "$@"
