# - Try to find the Pico libpicobt libraries
#  Once done this will define
#
#  PICOBT_FOUND 
#  PICOBT_INCLUDE_DIR 
#  PICOBT_LIBRARIES 
#

INCLUDE( FindPkgConfig )

# Try to use PkgConfig. On Linux this should work happily
# if the package is installed
PKG_SEARCH_MODULE( PICOBT libpicobt )

IF( NOT PICOBT_FOUND )
	IF ( PICOBT_INSTALL_DIR )
		MESSAGE ( STATUS "Using override PICOBT_INSTALL_DIR to find libpicobt" )
		SET ( PICOBT_INCLUDE_DIR  "${PICOBT_INSTALL_DIR}/include" )
		FIND_LIBRARY( PICOBT_LIBRARY NAMES picobt PATHS "${PICOBT_INSTALL_DIR}" )
	ENDIF ( PICOBT_INSTALL_DIR )
	
	IF ( PICOBT_INCLUDE_DIR AND PICOBT_LIBRARY )
		SET( PICOBT_FOUND 1 )
		if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
			SET ( PICOBT_LIBRARIES "${PICOBT_LIBRARY}" ws2_32 Bthprops )
		else()
			SET ( PICOBT_LIBRARIES "${PICOBT_LIBRARY}")
		endif()
		SET ( PICOBT_INCLUDE_DIRS "${PICOBT_INCLUDE_DIR}")
	ELSE()
		MESSAGE ( "Not possible to find libpicobt. Please set PICOBT_INCLUDE_DIR and PICOBT_LIBRARY variables" )
	ENDIF()

	IF ( PICOBT_INCLUDE_DIRS AND PICOBT_LIBRARIES )
		SET( PICOBT_FOUND 1 )
		IF ( NOT Libpicobt_FIND_QUIETLY )
			MESSAGE ( STATUS "Found PICOBT: ${PICOBT_LIBRARIES}" )
		ENDIF ( NOT Libpicobt_FIND_QUIETLY )
	ELSE()
		IF( Libpicobt_FIND_REQUIRED )
			MESSAGE( FATAL_ERROR "Could NOT find PICOBT" )
		ELSE()
			IF( NOT Libpicobt_FIND_QUIETLY )
				MESSAGE( STATUS "Could NOT find PICOBT" )	
			ENDIF()
		ENDIF()
	ENDIF()
ELSE()
	MESSAGE ( STATUS "Libpicobt Include Dir: ${PICOBT_INCLUDE_DIRS}" )
ENDIF()

# Hide advanced variables from CMake GUIs
MARK_AS_ADVANCED( PICOBT_INCLUDE_DIRS PICOBT_LIBRARIES )

