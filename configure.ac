#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([pico], [0.0.3], [Frank.Stajano@cl.cam.ac.uk, David.Llewellyn-Jones@cl.cam.ac.uk])
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([include/pico/config.h])
AC_CONFIG_MACRO_DIR([m4])
# PKG_INSTALLDIR isn't defined for pkg-config < 0.27 so we set the directory
# manually in Makefile.am
# See http://redmine.audacious-media-player.org/issues/248
#PKG_INSTALLDIR

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
#AM_PROG_AR
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT
AC_CHECK_PROG([DOXYGEN], [doxygen], [doxygen])

if test "$DOXYGEN" = doxygen; then
echo Use \"make doxygen\" to generate library documentation.
else
echo ===================================================================
echo Install doxygen to allow the library documentation to be generated.
echo ===================================================================
fi

# Checks for libraries.
PKG_CHECK_MODULES([PICOLIB], [libcrypto, libcurl, libqrencode])
PKG_CHECK_MODULES([PICOBT], [libpicobt, bluez], [HAVE_BLUETOOTH=1], [HAVE_BLUETOOTH=0])
AC_CHECK_LIB([picobt], [bt_init])
AC_CHECK_LIB([bluetooth], [hci_get_route])

# Checks for the Check libraries. See https://libcheck.github.io/check/
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h stdlib.h string.h stdbool.h])

# Checks for compiler characteristics
AC_C_BIGENDIAN

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tests/Makefile
                 libpico-1.pc
                 doxyfile])
AC_OUTPUT
