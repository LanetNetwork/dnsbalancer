cmake_minimum_required(VERSION 2.8.11)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-scripts)
include(generic)

include(FindPkgConfig)
if (PKG_CONFIG_FOUND)
	pkg_check_modules(LIBINI_CONFIG REQUIRED ini_config)
	pkg_check_modules(LIBMICROHTTPD REQUIRED libmicrohttpd)
	pkg_check_modules(LIBBSD REQUIRED libbsd)
	pkg_check_modules(LIBUNWIND REQUIRED libunwind)
	if(NOT CMAKE_BUILD_TYPE MATCHES Debug)
		pkg_check_modules(LIBTCMALLOC_MINIMAL libtcmalloc_minimal)
		if(LIBTCMALLOC_MINIMAL_FOUND EQUAL 1)
			set(GB_LD_EXTRA "${LIBTCMALLOC_MINIMAL_LIBRARIES}")
		endif (LIBTCMALLOC_MINIMAL_FOUND EQUAL 1)
	endif(NOT CMAKE_BUILD_TYPE MATCHES Debug)
endif (PKG_CONFIG_FOUND)

find_package(LDNS REQUIRED)

add_subdirectory(contrib/pfcq)
add_subdirectory(contrib/pfpthq)
add_subdirectory(contrib/iniparser)
add_subdirectory(contrib/xxhash)

add_executable(dnsbalancer
	acl.c
	acl_local.c
	dnsbalancer.c
	global_context.c
	local_context.c
	request.c
	stats.c
	utils.c
	watchdog.c
	worker.c)

target_link_libraries(dnsbalancer
	pthread
	rt
	ln_pfcq
	ln_pfpthq
	ln_iniparser
	ln_xxhash
	${LIBINI_CONFIG_LIBRARIES}
	${LDNS_LIBRARIES}
	${LIBBSD_LIBRARIES}
	${LIBUNWIND_LIBRARIES}
	${LIBMICROHTTPD_LIBRARIES}
	${GB_LD_EXTRA})

install(TARGETS dnsbalancer
	RUNTIME DESTINATION bin)

