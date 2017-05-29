# SOURCES =
#include src/include.am

SUBDIRS = src src/test pkgconfig
ACLOCAL_AMFLAGS = -I m4

@CODE_COVERAGE_RULES@

ci: test mem-check coverage-check

test: check
	$(top_builddir)/src/test/test

code-check:
	splint +trytorecover src/*.h src/**.c `pkg-config --cflags glib-2.0`

mem-check: check
	valgrind --error-exitcode=2 --track-origins=yes --trace-children=yes --leak-check=full --suppressions=valgrind.supp $(top_builddir)/src/test/test

coverage-check: test 
	@make check-code-coverage

