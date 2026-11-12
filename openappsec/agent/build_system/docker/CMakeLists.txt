# NginxionS: no prebuilt installers of Check Point (intelligence service, CrowdSec auxiliary service): binaries with
# no sources; NginxionS runs CrowdSec with its own bouncer
# NginxionS: no Dockerfile of upstream and no "docker" target: the image is deploy/openappsec/Dockerfile
install(FILES entry.sh self_managed_openappsec_manifest.json DESTINATION .)
