AC_DEFUN([adl_ENABLE_GPROF],
 [AC_ARG_ENABLE([gprof],
  [AC_HELP_STRING([--enable-gprof],[enable gprof profiling])])
  if test "${enable_gprof}" = "yes" -a -n "$GCC"; then
   CFLAGS="$CFLAGS -pg"
  fi])
