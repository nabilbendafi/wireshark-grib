#
# Try to find the wireshark library and its includes
#
# This snippet sets the following variables:
#  WIRESHARK_FOUND             True if wireshark library got found
#  WIRESHARK_INCLUDE_DIRS      Location of the wireshark headers 
#  WIRESHARK_LIBRARIES         List of libraries to use wireshark
#
#  Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

# wireshark does not install its library with pkg-config information,
# so we need to manually find the libraries and headers

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(GRIB_API grib_api)

IF (GRIB_API_FOUND) 
  MESSAGE (STATUS "Found wireshark libs at ${GRIB_API_INCLUDE_DIRS}")
ELSE()
  MESSAGE (STATUS "Wireshark libs not found!")
ENDIF()
