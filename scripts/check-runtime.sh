#!/usr/bin/env bash
# Runtime checks of the containers of a running stack (the extended DAST, scripts/test-dast.sh): what the compose
# files ask for is checked on what Docker really runs. One JSON finding per weakness:
#   high     privileged, the host's PID, IPC or network namespace, the Docker socket outside nginxions-control
#   medium   added capabilities, no no-new-privileges, cap_drop without ALL
#   low      root user, writable root filesystem
#   info     the Docker socket of nginxions-control (openappsec, CLAUDE.md), ports published on every address
#
#   scripts/check-runtime.sh <compose project> <out.json>
set -euo pipefail

project=$1
out=$2

ids=$(docker ps -q --filter "label=com.docker.compose.project=$project")
[ -n "$ids" ] || { echo "no container of $project is running" >&2; exit 1; }

# shellcheck disable=SC2086
docker inspect $ids | jq '
  [ .[] as $c
    | ($c.Config.Labels["com.docker.compose.service"] // ($c.Name | ltrimstr("/"))) as $svc
    | def finding($rule; $severity; $title): {rule: $rule, severity: $severity, container: $svc, title: $title};
      ( if $c.HostConfig.Privileged then finding("privileged"; "high"; "privileged: true") else empty end ),
      ( ["PidMode", "IpcMode", "NetworkMode"][] as $ns
        | select($c.HostConfig[$ns] == "host")
        | finding("host-namespace"; "high"; "\($ns): host") ),
      ( $c.Mounts[]? | select(.Source == "/var/run/docker.sock" or .Source == "/run/docker.sock")
        | if $svc == "openappsec"
          then finding("docker-socket"; "info"; "Docker socket (nginxions-control, белый список операций)")
          else finding("docker-socket"; "high"; "Docker socket в контейнере \($svc)") end ),
      ( ($c.HostConfig.CapAdd // []) | select(length > 0)
        | finding("cap-add"; "medium"; "cap_add: \(join(", "))") ),
      ( if (($c.HostConfig.CapDrop // []) | map(ascii_upcase) | any(. == "ALL" or . == "CAP_ALL")) | not
        then finding("cap-drop"; "medium"; "cap_drop без ALL") else empty end ),
      ( if (($c.HostConfig.SecurityOpt // []) | map(select(startswith("no-new-privileges"))) | length) == 0
        then finding("no-new-privileges"; "medium"; "нет security_opt no-new-privileges") else empty end ),
      ( if (($c.Config.User // "") | IN("", "0", "root", "0:0", "root:root"))
        then finding("root-user"; "low"; "процессы работают от root") else empty end ),
      ( if $c.HostConfig.ReadonlyRootfs | not
        then finding("writable-rootfs"; "low"; "корневая файловая система доступна на запись") else empty end ),
      ( ($c.HostConfig.PortBindings // {}) | to_entries[] | .key as $port | .value[]?
        | select((.HostIp // "") | IN("", "0.0.0.0", "::"))
        | finding("port-all-addresses"; "info"; "порт \($port) опубликован на всех адресах (:\(.HostPort))") )
  ]' > "$out"

echo "runtime: $(jq length "$out") findings in $(echo "$ids" | wc -l) containers"
