#!/usr/bin/env sh

export ENABLE_PRERUN="${ENABLE_PRERUN:-false}"
if ! echo "$ENABLE_PRERUN" | grep -q "^true$\|^false$"; then
    echo "ENABLE_PRERUN needs to be true or false."
    sleep inf
fi

if [ -n "$(ls -A /data/prerun 2> /dev/null)" ] && [ "$ENABLE_PRERUN" = "true" ]; then
    for script in /data/prerun/*.sh; do
        echo "Exexcuting prerun script: $script"
        chmod +x "$script"
        "$script"
    done
fi

# NginxionS: data of the time the project was called NPMOS (/data/npmos) moves to /data/nginxions once; the
# configs of hosts written then name its paths and Lua modules, they get the new names in the same step.
if [ -d /data/npmos ] && [ ! -e /data/nginxions ]; then
    echo "Moving /data/npmos to /data/nginxions (the project is now called NginxionS)"
    mv /data/npmos /data/nginxions
    find /data/nginx -type f -name '*.conf' -exec sed -i 's/npmos/nginxions/g' {} + 2> /dev/null || true
fi

exec envs.sh
