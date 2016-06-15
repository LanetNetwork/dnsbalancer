cmake_minimum_required(VERSION 2.8.11)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Setting build type to 'Release' as none was specified.")
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)

if (CMAKE_BUILD_TYPE MATCHES Debug)
	message("This is DEBUG build")
endif (CMAKE_BUILD_TYPE MATCHES Debug)

include(FindPkgConfig)
if (PKG_CONFIG_FOUND)
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

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-scripts)
find_package(LDNS)

set(CMAKE_C_FLAGS
	"-std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -W -Wall -Wextra -pedantic -Wwrite-strings -Winit-self -Wcast-qual -Wpointer-arith -Wstrict-aliasing -Wformat=2 -Wmissing-declarations -Wmissing-include-dirs -Wno-unused-parameter -Wuninitialized -Wold-style-definition -Wstrict-prototypes -Wmissing-prototypes")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g -ggdb -pg -DMODE_DEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -DMODE_NORMAL")

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
	${LDNS_LIBRARIES}
	${LIBBSD_LIBRARIES}
	${LIBUNWIND_LIBRARIES}
	${LIBMICROHTTPD_LIBRARIES}
	${GB_LD_EXTRA})

install(TARGETS dnsbalancer
	RUNTIME DESTINATION bin)

