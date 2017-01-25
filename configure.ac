#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Needed for autoconf 2.68
m4_pattern_allow([AC_CHECK_HEADER_STDBOOL])

AC_PREREQ([2.68])
AC_INIT([libotr4], [0.0.1], [strike@thoughtworks.com])
AC_CONFIG_SRCDIR([src/otrv4.c])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AM_PROG_AR

LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_RANLIB
AC_PROG_LIBTOOL

# Checks for libraries.
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.2])
PKG_CHECK_MODULES([LIBDECAF], [libdecaf >= 0.0.1])
PKG_CHECK_MODULES([LIBSODIUM], [libsodium >= 1.0.0])
PKG_CHECK_MODULES([LIBCRAMERSHOUP], [libcramershoup])
AM_PATH_LIBGCRYPT(1:1.2.0,,AC_MSG_ERROR(libgcrypt 1.2.0 or newer is required.))


# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AX_CFLAGS_GCC_OPTION([-Wall])
AX_CFLAGS_GCC_OPTION([-Werror])
AX_CFLAGS_GCC_OPTION([-Wfatal-errors])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strstr])

AC_CACHE_SAVE

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile src/test/Makefile])
AC_OUTPUT

