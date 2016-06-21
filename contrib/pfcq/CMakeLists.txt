cmake_minimum_required(VERSION 2.8.11)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-scripts)
include(generic)

add_library(ln_pfcq
	STATIC
	pfcq.c)
