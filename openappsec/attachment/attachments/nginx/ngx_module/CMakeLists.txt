add_library(
	ngx_module
	SHARED
	ngx_http_cp_attachment_module.c ngx_cp_thread.c ngx_cp_hook_threads.c ngx_cp_hooks.c ngx_cp_utils.c
	ngx_cp_initializer.c ngx_cp_io.c ngx_cp_static_content.c ngx_cp_custom_response.c ngx_modules.c
	ngx_cp_compression.c ngx_cp_http_parser.c ngx_cp_failing_state.c ngx_cp_metric.c
)

add_dependencies(ngx_module shmem_ipc_2 osrc_nginx_attachment_util osrc_compression_utils)

target_link_libraries(ngx_module shmem_ipc_2 osrc_nginx_attachment_util osrc_compression_utils)

file(GLOB_RECURSE NGINX_DIRS LIST_DIRECTORIES true "/src/nginx/*")
set(NGX_INCLUDES "/src/nginx")
foreach(dir ${NGINX_DIRS})
    if(IS_DIRECTORY ${dir})
        list(APPEND NGX_INCLUDES ${dir})
    endif()
endforeach()
target_include_directories(ngx_module PRIVATE ${NGX_INCLUDES})

install(TARGETS ngx_module DESTINATION lib)
install(TARGETS ngx_module DESTINATION nginx_attachment/lib)
