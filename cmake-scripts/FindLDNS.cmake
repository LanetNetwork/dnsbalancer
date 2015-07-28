# - Try to find ldns
# Once done this will define
#
#  LDNS_FOUND - system has LDNS
#  LDNS_INCLUDE_DIRS - the LDNS include directory
#  LDNS_LIBRARIES - Link these to use LDNS
#  LDNS_DEFINITIONS - Compiler switches required for using LDNS
#
#  Copyright (c) 2011 Lee Hambley <lee.hambley@gmail.com>
#  Modified by Oleksandr Natalenko aka post-factum <oleksandr@natalenko.name>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#

if (LDNS_LIBRARIES AND LDNS_INCLUDE_DIRS)
  # in cache already
  set(LDNS_FOUND TRUE)
else (LDNS_LIBRARIES AND LDNS_INCLUDE_DIRS)

  find_path(LDNS_INCLUDE_DIR
    NAMES
      ldns.h
    PATHS
      /usr/include
      /usr/local/include
	  /usr/include/ldns
	  /usr/local/include/ldns
  )

  find_library(LDNS_LIBRARY
    NAMES
      libldns.so
    PATHS
      /usr/lib
      /usr/local/lib
      /usr/lib64
      /usr/local/lib64
  )

  set(LDNS_INCLUDE_DIRS
    ${LDNS_INCLUDE_DIR}
  )

  if (LDNS_LIBRARY)
    set(LDNS_LIBRARIES
        ${LDNS_LIBRARIES}
        ${LDNS_LIBRARY}
    )
  endif (LDNS_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(LDNS DEFAULT_MSG LDNS_LIBRARIES LDNS_INCLUDE_DIRS)

  mark_as_advanced(LDNS_INCLUDE_DIRS LDNS_LIBRARIES)

endif (LDNS_LIBRARIES AND LDNS_INCLUDE_DIRS)

