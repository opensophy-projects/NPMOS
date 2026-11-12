# NginxionS: from attachment.patch of NPMplus: the nginx module only (no docker, nodes, nano_attachment), zlib-ng
cmake_minimum_required(VERSION 3.5.0)
project(ngen)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wno-terminate")

set(CMAKE_CXX_STANDARD 11)

list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
)

find_package(PkgConfig REQUIRED)
find_package(Brotli REQUIRED MODULE)

include_directories(external)
include_directories(core/include/attachments)

add_subdirectory(core)
add_subdirectory(attachments)
#add_subdirectory(docker)
#add_subdirectory(nodes)
