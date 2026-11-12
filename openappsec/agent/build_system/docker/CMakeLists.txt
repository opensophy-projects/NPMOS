# NginxionS: no prebuilt installers of Check Point (intelligence service, CrowdSec auxiliary service): binaries with
# no sources; NginxionS runs CrowdSec with its own bouncer
install(FILES Dockerfile entry.sh self_managed_openappsec_manifest.json DESTINATION .)

add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/agent-docker.img
    COMMAND docker build -t agent-docker ${CMAKE_INSTALL_PREFIX}
    COMMAND docker image save agent-docker -o ${CMAKE_INSTALL_PREFIX}/agent-docker.img
)

add_custom_target(docker DEPENDS ${CMAKE_INSTALL_PREFIX}/agent-docker.img)
