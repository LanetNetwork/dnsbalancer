# - Try to find IniParser
# Once done this will define
#
#  INIPARSER_FOUND - system has INIPARSER
#  INIPARSER_INCLUDE_DIRS - the INIPARSER include directory
#  INIPARSER_LIBRARIES - Link these to use INIPARSER
#  INIPARSER_DEFINITIONS - Compiler switches required for using INIPARSER
#
#  Copyright (c) 2011 Lee Hambley <lee.hambley@gmail.com>
#  Modified by Oleksandr Natalenko aka post-factum <oleksandr@natalenko.name>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#

if (INIPARSER_LIBRARIES AND INIPARSER_INCLUDE_DIRS)
  # in cache already
  set(INIPARSER_FOUND TRUE)
else (INIPARSER_LIBRARIES AND INIPARSER_INCLUDE_DIRS)

  find_path(INIPARSER_INCLUDE_DIR
    NAMES
      iniparser.h
    PATHS
      /usr/include
      /usr/local/include
  )

  find_library(INIPARSER_LIBRARY
    NAMES
      libiniparser.so
    PATHS
      /usr/lib
      /usr/local/lib
      /usr/lib64
      /usr/local/lib64
  )

  set(INIPARSER_INCLUDE_DIRS
    ${INIPARSER_INCLUDE_DIR}
  )

  if (INIPARSER_LIBRARY)
    set(INIPARSER_LIBRARIES
        ${INIPARSER_LIBRARIES}
        ${INIPARSER_LIBRARY}
    )
  endif (INIPARSER_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(INIPARSER DEFAULT_MSG INIPARSER_LIBRARIES INIPARSER_INCLUDE_DIRS)

  mark_as_advanced(INIPARSER_INCLUDE_DIRS INIPARSER_LIBRARIES)

endif (INIPARSER_LIBRARIES AND INIPARSER_INCLUDE_DIRS)

