dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.
#
#  This file is part of the Off-the-Record Next Generation Messaging
#  library (libotr-ng).
#
#  Copyright (C) 2016-2018, the libotr-ng contributors.
#
#  This library is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this library.  If not, see <http://www.gnu.org/licenses/>.
#

AC_PREREQ([2.68])
AC_INIT([libotr-ng], [0.0.1], [otrv4-dev@autonomia.digital])
AC_CONFIG_SRCDIR([src/otrng.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([.])
AM_SILENT_RULES([no])

dnl Debug
AX_CHECK_ENABLE_DEBUG([yes])

dnl Valgrind: make check-valgrind
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_CHECK

AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
#AM_INIT_AUTOMAKE([-Wall -W -Werror foreign subdir-objects]) # Use this to allow Wextra flag
AM_PROG_AR
LT_INIT

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
# libtoolize: 'AC_PROG_RANLIB' is rendered obsolete by 'LT_INIT'
#AC_PROG_RANLIB

dnl ISO Standard C (currently C99), with fall back to ANSI C89 (ISO C90)
AC_PROG_CC_STDC

dnl Check that our compiler can do const and inline
AC_C_CONST
AC_C_INLINE

AC_CANONICAL_HOST
# Identify which OS we are building and do specific things based on the host
case $host_os in
  *linux*)
    HOST_OS=linux
    ;;
esac

dnl Checks for libraries.
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.18])
PKG_CHECK_MODULES([LIBGOLDILOCKS], [libgoldilocks >= 0.0.1])
PKG_CHECK_MODULES([LIBSODIUM], [libsodium >= 1.0.0])
AM_PATH_LIBOTR(4.0.0,,AC_MSG_ERROR(libotr 4.x >= 4.0.0 is required.))
# TODO: this seems to be not correctly working on Darwin.
# We probably need the config script
AM_PATH_LIBGCRYPT(1:1.8.0,,
  [AC_DEFINE([HAVE_GCRYPT], [1], [Use GCRYPT])],
  [AM_PATH_LIBGCRYPT(1:1.6.0,, AC_MSG_ERROR(libgcrypt 1.6.0 or newer is required.))]
)

dnl Checks for header files.
AC_CHECK_HEADERS([stddef.h stdint.h stdlib.h string.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AX_CFLAGS_GCC_OPTION([-Wall])
# AX_CFLAGS_GCC_OPTION([-W]) Uncomment this to allow Wextra flag
AX_CFLAGS_GCC_OPTION([-Werror])
AX_CFLAGS_GCC_OPTION([-Wformat])
AX_CFLAGS_GCC_OPTION([-Wno-format-extra-args])
AX_CFLAGS_GCC_OPTION([-Wfatal-errors])
AX_CFLAGS_GCC_OPTION([-Wbad-function-cast])
AX_CFLAGS_GCC_OPTION([-Wdiv-by-zero])
AX_CFLAGS_GCC_OPTION([-Wfloat-equal])
AX_CFLAGS_GCC_OPTION([-Wnested-externs])
AX_CFLAGS_GCC_OPTION([-Wpointer-arith])
AX_CFLAGS_GCC_OPTION([-Wredundant-decls])
# AX_CFLAGS_GCC_OPTION([-Wstrict-prototypes])
AX_CFLAGS_GCC_OPTION([-Wlogical-op])
AX_CFLAGS_GCC_OPTION([-Wbad-cast-qual])
AX_CFLAGS_GCC_OPTION([-Wformat-nonliteral])
AX_CFLAGS_GCC_OPTION([-Wbuiltin-memcpy-chk-size])
AX_CFLAGS_GCC_OPTION([-Wfloat-equal])
AX_CFLAGS_GCC_OPTION([-Wundef])
AX_CFLAGS_GCC_OPTION([-Wshadow])
AX_CFLAGS_GCC_OPTION([-Wpointer-arith])
AX_CFLAGS_GCC_OPTION([-Wcast-align])
AX_CFLAGS_GCC_OPTION([-Wmaybe-uninitialized])
AX_CFLAGS_GCC_OPTION([-Wlogicalop])
AX_CFLAGS_GCC_OPTION([-Wno-type-limits])
AX_CFLAGS_GCC_OPTION([-Wnull-dereference])
AX_CFLAGS_GCC_OPTION([-Wwrite-strings])
dnl for undefined behavior
# AX_CFLAGS_GCC_OPTION([-fcatch-undefined-behavior])
# AX_CFLAGS_GCC_OPTION([-fno-delete-null-pointer-checks])
# AX_CFLAGS_GCC_OPTION([-fno-strict-overflow])
# AX_CFLAGS_GCC_OPTION([-fno-strict-aliasing])

dnl Code coverage
AX_CODE_COVERAGE

dnl Checks for library functions.
AC_CHECK_FUNCS([memchr memmove memset strstr])
AC_FUNC_MALLOC
AC_FUNC_REALLOC

dnl Switches
AC_ARG_WITH(ctgrind,
[AS_HELP_STRING(--with-ctgrind, Use only if you have ctgrind)],
[AS_IF([test "x$with_ctgrind" = "xyes"], [
    AC_CHECK_LIB(ctgrind, ct_poison)
  ])
])

# Enable gprof profiling
AC_ARG_ENABLE([gprof],
    [AS_HELP_STRING([--enable-gprof],
                    [use gprof profiling compiler flags (default is no)])],
    [enable_gprof=$enableval],
    [enable_gprof=no])
AC_CACHE_SAVE

# Enable different -fsanitize options
AC_ARG_WITH([sanitizers],
    [AS_HELP_STRING([--with-sanitizers],
                    [comma separated list of extra sanitizers to build with (default is none enabled)])],
    [use_sanitizers=$withval])

if test "x$enable_gprof" = xyes; then
    AX_CHECK_COMPILE_FLAG([-pg],[GPROF_CFLAGS="-pg"],
        AC_MSG_ERROR(gprof profiling requested but not available))

    AX_CHECK_LINK_FLAG([[-no-pie]], [GPROF_LDFLAGS="-no-pie"])
    AX_CHECK_LINK_FLAG([[-pg]],[GPROF_LDFLAGS="$GPROF_LDFLAGS -pg"],
        AC_MSG_ERROR(gprof profiling requested but not available))
fi

if test x$use_sanitizers != x; then
  # First check if the compiler accepts flags. If an incompatible pair like
  # -fsanitize=address,thread is used here, this check will fail. This will also
  # fail if a bad argument is passed, e.g. -fsanitize=undfeined
  AX_CHECK_COMPILE_FLAG(
    [[-fsanitize=$use_sanitizers]],
    [[SANITIZER_CFLAGS=-fsanitize=$use_sanitizers]],
    [AC_MSG_ERROR([compiler did not accept requested flags])])

  # Some compilers (e.g. GCC) require additional libraries like libasan,
  # libtsan, libubsan, etc. Make sure linking still works with the sanitize
  # flag. This is a separate check so we can give a better error message when
  # the sanitize flags are supported by the compiler but the actual sanitizer
  # libs are missing.
  AX_CHECK_LINK_FLAG(
    [[-fsanitize=$use_sanitizers]],
    [[SANITIZER_LDFLAGS=-fsanitize=$use_sanitizers]],
    [AC_MSG_ERROR([linker did not accept requested flags, you are missing required libraries])])
fi

AC_SUBST(GPROF_CFLAGS)
AC_SUBST(GPROF_LDFLAGS)
AC_SUBST(SANITIZER_CFLAGS)
AC_SUBST(SANITIZER_LDFLAGS)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile src/include/Makefile src/test/Makefile pkgconfig/Makefile pkgconfig/libotr-ng.pc])
AC_OUTPUT

echo \
"----------------------------------------------------------------------------
Thank you for installing libotr-ng version ${PACKAGE_VERSION}.
Installation completed in directory '${prefix}'.
----------------------------------------------------------------------------"

echo
echo "Options used to compile and link:"
echo "  sanitizers    = $use_sanitizers"
echo "  gprof enabled = $enable_gprof"
echo "  CC            = $CC"
echo "  CFLAGS        = $CFLAGS"
echo "  LDFLAGS       = $LDFLAGS"
echo
