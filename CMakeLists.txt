project(pico C)
set(CMAKE_BUILD_TYPE Debug)

cmake_minimum_required(VERSION 3.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules/")
option(USE_LIBPICOBT "Build with libbpicot support" TRUE)

if(USE_LIBPICOBT)
	add_definitions(-DHAVE_LIBPICOBT)
	find_package(Libpicobt REQUIRED)
	include_directories(${PICOBT_INCLUDE_DIRS})
endif()

# only look in default directories
find_path(
	CURL_INCLUDE_DIR 
	NAMES curl/curl.h
	DOC "curl include dir"
)

find_library(
	CURL_LIBRARY
	# names from cmake's FindCURL
	NAMES curl curllib libcurl_imp curllib_static libcurl
	DOC "curl library"
)

set(CURL_INCLUDE_DIRS ${CURL_INCLUDE_DIR})
set(CURL_LIBRARIES ${CURL_LIBRARY})

# debug library on windows
# same naming convention as in qt (appending debug library with d)
# boost is using the same "hack" as us with "optimized" and "debug"
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	find_library(
		CURL_LIBRARY_DEBUG
		NAMES curld libcurld
		DOC "curl debug library"
	)
	
	set(CURL_LIBRARIES optimized ${CURL_LIBRARIES} debug ${CURL_LIBRARY_DEBUG})
endif()
message(STATUS "Curl include dir: " ${CURL_INCLUDE_DIRS})
include_directories(${CURL_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
if( OPENSSL_FOUND )
    message(STATUS "Openssl include dir: " ${OPENSSL_INCLUDE_DIR})
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
	file(GLOB SOURCES_LIBENCODE "libqrencode/*.c")
	list(REMOVE_ITEM SOURCES_LIBENCODE ${CMAKE_CURRENT_SOURCE_DIR}/libqrencode/qrenc.c)
	include_directories(libqrencode)
	add_definitions(-D__STATIC=static -DMAJOR_VERSION=3 -DMINOR_VERSION=4 -DMICRO_VERSION=4 -DVERSION="v3.4.4")
	add_library(qrencode STATIC ${SOURCES_LIBENCODE})
endif()

include_directories(include)
include_directories(tests)
 
file(GLOB SOURCES "src/*.c")

add_library(pico SHARED ${SOURCES})
target_link_libraries (pico ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES} ${PICOBT_LIBRARIES} qrencode)

install(TARGETS pico DESTINATION /usr/lib)
