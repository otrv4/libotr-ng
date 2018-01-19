dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([libotr4], [0.0.1], [otrv4-dev@autonomia.digital])
AC_CONFIG_SRCDIR([src/otrv4.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([.])
AM_SILENT_RULES([no])

dnl Debug
AX_CHECK_ENABLE_DEBUG([yes])
AX_CHECK_ENABLE_GPROF

dnl Valgrind: make check-valgrind
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_CHECK

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

dnl Check that our compiler can do const and inline
AC_C_CONST
AC_C_INLINE

dnl Checks for libraries.
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.18])
PKG_CHECK_MODULES([LIBDECAF], [libdecaf >= 0.0.1])
PKG_CHECK_MODULES([LIBSODIUM], [libsodium >= 1.0.0])
AM_PATH_LIBOTR(4.0.0,,AC_MSG_ERROR(libotr 4.x >= 4.0.0 is required.))
# TODO: this seems to be not correctly working on Darwin.
# We probably need the config script
AM_PATH_LIBGCRYPT(1:1.8.0,,
  [AC_DEFINE([HAVE_GCRYPT], [1], [Use GCRYPT])],
  [AM_PATH_LIBGCRYPT(1:1.6.0,, [AC_MSG_ERROR(libgcrypt 1.6.0 or newer is required.)])]
)

dnl Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_PROG_CC_STDC

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
dnl for undefined behavior
# AX_CFLAGS_GCC_OPTION([-fcatch-undefined-behavior])
# AX_CFLAGS_GCC_OPTION([-fno-delete-null-pointer-checks])
# AX_CFLAGS_GCC_OPTION([-fno-strict-overflow])
# AX_CFLAGS_GCC_OPTION([-fno-strict-aliasing])

dnl Code coverage
AX_CODE_COVERAGE

dnl Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memchr memmove memset stpcpy strchr strstr])

dnl Switches
AC_ARG_WITH(ctgrind,
[AS_HELP_STRING(--with-ctgrind, Use only if you have ctgrind)],
[AS_IF([test "x$with_ctgrind" = "xyes"], [
    AC_CHECK_LIB(ctgrind, ct_poison)
  ])
])

AC_CACHE_SAVE

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile src/test/Makefile pkgconfig/Makefile pkgconfig/libotr4.pc])
AC_OUTPUT
