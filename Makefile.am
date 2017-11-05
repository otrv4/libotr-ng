# SOURCES =
#include src/include.am

SUBDIRS = src src/test pkgconfig
ACLOCAL_AMFLAGS = -I m4

@CODE_COVERAGE_RULES@

ci: test mem-check

test: check
	$(top_builddir)/src/test/test

code-check:
	splint +trytorecover src/*.h src/**.c `pkg-config --cflags glib-2.0`

VALGRIND_SUPPRESSIONS = \
	valgrind.supp

VALGRIND_ARGS = --track-origins=yes --quiet --error-exitcode=2 --leak-check=full \
	--suppressions=$(VALGRIND_SUPPRESSIONS)

mem-check: check
	valgrind $(VALGRIND_ARGS) $(top_builddir)/src/test/test

coverage-check: test
	@make check-code-coverage

code-style:
	clang-format -style=llvm -i config.h src/*.h src/*.c src/**/*.h src/**/*.c

code-style-doctor: code-style
	git diff --exit-code .

LOOPS = 10
test-loop:
	for ((i=1; i <= ${LOOPS}; ++i)) do make test && echo $$i || break; done
