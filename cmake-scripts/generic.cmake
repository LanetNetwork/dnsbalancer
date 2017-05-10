if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Setting build type to 'Release' as none was specified.")
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)

message(STATUS "This is ${CMAKE_BUILD_TYPE} build")

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Intel")
	set(DS_CONFIG_FLAGS "${DS_CONFIG_FLAGS} -w3 -wd2102 -wd2552 -wd11074 -wd11076")
else ("${CMAKE_C_COMPILER_ID}" STREQUAL "Intel")
	set(DS_CONFIG_FLAGS "${DS_CONFIG_FLAGS} -fdiagnostics-color=always")
endif ("${CMAKE_C_COMPILER_ID}" STREQUAL "Intel")

set(CMAKE_C_FLAGS
	"${DS_CONFIG_FLAGS} -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -pipe -W -Wall -Wextra -pedantic -Wwrite-strings -Winit-self -Wcast-qual -Wpointer-arith -Wstrict-aliasing -Wformat=2 -Wmissing-declarations -Wmissing-include-dirs -Wno-unused-parameter -Wuninitialized -Wold-style-definition -Wstrict-prototypes -Wmissing-prototypes")
set(CMAKE_C_FLAGS_DEBUG "${DS_CONFIG_FLAGS} -O1 -g -ggdb -pg -mtune=generic -D_FORTIFY_SOURCE=2 -fstack-protector-all -DMODE_DEBUG")
set(CMAKE_C_FLAGS_RELEASE "${DS_CONFIG_FLAGS} -O3 -march=native -mtune=native -D_FORTIFY_SOURCE=1 -fstack-protector-strong -DMODE_NORMAL")

