cmake_minimum_required(VERSION 2.8.11)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Setting build type to 'Release' as none was specified.")
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)

if (CMAKE_BUILD_TYPE MATCHES Debug)
	message("This is DEBUG build")
endif (CMAKE_BUILD_TYPE MATCHES Debug)

set(CMAKE_C_FLAGS
	"-std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -W -Wall -Wextra -pedantic -Wwrite-strings -Winit-self -Wcast-qual -Wpointer-arith -Wstrict-aliasing -Wformat=2 -Wmissing-declarations -Wmissing-include-dirs -Wno-unused-parameter -Wuninitialized -Wold-style-definition -Wstrict-prototypes -Wmissing-prototypes")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g -ggdb -DMODE_DEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -DMODE_NORMAL")

add_library(ln_iniparser
	STATIC
	dictionary.c
	iniparser.c)
