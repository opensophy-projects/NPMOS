#!/bin/bash
# NPMOS: agent settings made in the GUI (WAF -> Agent), applied at every start of the agent.
# NPMOS writes them to /ext/appsec/npmos-agent.env (volume appsec-localconfig) and restarts the
# agent. Only the keys below are read; the file is not sourced.
SETTINGS=/ext/appsec/npmos-agent.env
CROWDSEC_KEY=/run/secrets/npmos/crowdsec_bouncer_key

CROWDSEC_ENABLED=false
CROWDSEC_MODE=prevent
NPMOS_FAIL_OPEN=true
NPMOS_FAIL_OPEN_TIMEOUT_MS=50
if [ -f "$SETTINGS" ]; then
    while IFS='=' read -r key value; do
        case "$key=$value" in
            CROWDSEC_ENABLED=true | CROWDSEC_ENABLED=false) CROWDSEC_ENABLED=$value ;;
            CROWDSEC_MODE=prevent | CROWDSEC_MODE=detect) CROWDSEC_MODE=$value ;;
            NPMOS_FAIL_OPEN=true | NPMOS_FAIL_OPEN=false) NPMOS_FAIL_OPEN=$value ;;
            NPMOS_FAIL_OPEN_TIMEOUT_MS=*)
                [[ "$value" =~ ^[0-9]{1,5}$ ]] && NPMOS_FAIL_OPEN_TIMEOUT_MS=$value ;;
        esac
    done < "$SETTINGS"
fi

# IP reputation from the local CrowdSec LAPI (bouncer key registered by npmos-init)
if [ "$CROWDSEC_ENABLED" = true ] && [ -s "$CROWDSEC_KEY" ]; then
    export CROWDSEC_ENABLED=true CROWDSEC_MODE CROWDSEC_AUTH_METHOD=apikey
    export CROWDSEC_API_URL="${CROWDSEC_API_URL:-http://crowdsec:8080/v1/decisions/stream}"
    CROWDSEC_AUTH_DATA=$(cat "$CROWDSEC_KEY")
    export CROWDSEC_AUTH_DATA
else
    [ "$CROWDSEC_ENABLED" = true ] && echo "npmos: no CrowdSec bouncer key at $CROWDSEC_KEY, CrowdSec stays off" >&2
    unset CROWDSEC_ENABLED
fi

# Fail-open of the nginx attachment: profile settings in settings.json. The agent gets settings only
# from the Check Point cloud, which NPMOS never uses, so the file is ours.
mkdir -p /etc/cp/conf
printf '{"agentSettings": [%s, %s]}\n' \
    "{\"key\": \"agent.failOpenState.nginxModule\", \"value\": \"$NPMOS_FAIL_OPEN\"}" \
    "{\"key\": \"agent.failOpenTimeout.nginxModule\", \"value\": \"$NPMOS_FAIL_OPEN_TIMEOUT_MS\"}" \
    > /etc/cp/conf/settings.json

# what this start applied, for "saved, restart the agent to apply" in the GUI
[ -f "$SETTINGS" ] && cp "$SETTINGS" /ext/appsec/npmos-agent.applied

exec /cp-nano-agent "$@"
