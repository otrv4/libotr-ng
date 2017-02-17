# SOURCES =
#include src/include.am

SUBDIRS = src src/test
ACLOCAL_AMFLAGS = -I m4

#Compilation and linkage flags
#CFLAGS = -std=c99 -g -Wall `pkg-config --cflags glib-2.0`
#LDLIBS = `pkg-config --libs glib-2.0`
#CC = gcc

test: check
	$(top_builddir)/src/test/test

ci: test mem-check

code-check:
	splint +trytorecover src/*.h src/**.c `pkg-config --cflags glib-2.0`

mem-check: check
	valgrind --error-exitcode=2 --track-origins=yes --trace-children=yes --leak-check=full --suppressions=valgrind.supp $(top_builddir)/src/test/test

