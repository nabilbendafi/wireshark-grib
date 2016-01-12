# GRIB dissector plugin for Wireshark
#
# Copyright (c) 2016 Nabil BENDAFI
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

project(grib C CXX)

cmake_minimum_required(VERSION 2.6)
set(CMAKE_BACKWARDS_COMPATIBILITY 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

IF ( NOT CMAKE_INSTALL_LIBDIR )
  set(CMAKE_INSTALL_LIBDIR ~/.wireshark)
ENDIF ( NOT CMAKE_INSTALL_LIBDIR )
MESSAGE (STATUS "Plugin will be installed in: ${CMAKE_INSTALL_LIBDIR}")

INCLUDE(UseMakeDissectorReg)

find_package(GLIB2 REQUIRED)
include_directories (${GLIB2_INCLUDE_DIRS})

find_package(Wireshark REQUIRED)
include_directories (${WIRESHARK_INCLUDE_DIRS})

find_package(GRIB_API REQUIRED)
include_directories (${GRIB_API_INCLUDE_DIRS})

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/src)

set(LINK_MODE_LIB SHARED)
set(LINK_MODE_MODULE MODULE)

set(DISSECTOR_SRC
	src/packet-grib.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_dissector_files(plugin.c
        plugin
        ${DISSECTOR_SRC}
)

add_library(grib ${LINK_MODE_MODULE}
        ${PLUGIN_FILES}
)
set_target_properties(grib PROPERTIES PREFIX "")
set_target_properties(grib PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

target_link_libraries(grib wireshark grib_api)

install(TARGETS grib
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/plugins NAMELINK_SKIP
)
