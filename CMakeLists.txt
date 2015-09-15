cmake_minimum_required(VERSION 2.6.4)

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
	pkg_check_modules(LIBMICROHTTPD libmicrohttpd)
	pkg_check_modules(LIBBSD libbsd)
	if(NOT CMAKE_BUILD_TYPE MATCHES Debug)
		pkg_check_modules(LIBTCMALLOC_MINIMAL libtcmalloc_minimal)
		if(LIBTCMALLOC_MINIMAL_FOUND EQUAL 1)
			set(GB_LD_EXTRA "${LIBTCMALLOC_MINIMAL_LIBRARIES}")
		endif (LIBTCMALLOC_MINIMAL_FOUND EQUAL 1)
	endif(NOT CMAKE_BUILD_TYPE MATCHES Debug)
endif (PKG_CONFIG_FOUND)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-scripts)
find_package(IniParser)
find_package(LDNS)

set(CMAKE_C_FLAGS
	"-std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -W -Wall -Wextra -pedantic -Wwrite-strings -Winit-self -Wcast-qual -Wpointer-arith -Wstrict-aliasing -Wformat=2 -Wmissing-declarations -Wmissing-include-dirs -Wno-unused-parameter -Wuninitialized -Wold-style-definition -Wstrict-prototypes -Wmissing-prototypes")
if (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Intel")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpadded")
endif (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Intel")

set(CMAKE_C_FLAGS_DEBUG "-O0 -g -ggdb -DMODE_DEBUG")
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Intel")
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -w3")
endif ("${CMAKE_C_COMPILER_ID}" STREQUAL "Intel")

set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -DMODE_NORMAL")

if (DB_INIPARSER4)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDB_INIPARSER4")
endif (DB_INIPARSER4)

add_subdirectory(pfcquirks)
add_subdirectory(pfpthquirks)

include_directories(.
	pfcquirks
	pfpthquirks)

add_executable(dnsbalancer
	acl.c
	acl_local.c
	crcspeed.c
	crc64speed.c
	dnsbalancer.c
	global_context.c
	hash.c
	hashitems.c
	local_context.c
	stats.c)

target_link_libraries(dnsbalancer
	pthread
	rt
	ln_pfcquirks
	ln_pfpthquirks
	${LDNS_LIBRARIES}
	${INIPARSER_LIBRARIES}
	${LIBBSD_LIBRARIES}
	${LIBMICROHTTPD_LIBRARIES}
	${GB_LD_EXTRA})

install(TARGETS dnsbalancer
	RUNTIME DESTINATION bin)

