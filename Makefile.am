# SOURCES =
#include src/include.am

SUBDIRS = src src/test

#Compilation and linkage flags
#CFLAGS = -std=c99 -g -Wall `pkg-config --cflags glib-2.0`
#LDLIBS = `pkg-config --libs glib-2.0`
#CC = gcc

#Executables
SRC_TEST = $(top_builddir)/src/test
TESTS_OTRV4 = $(SRC_TEST)/test_otrv4
TESTS_DAKE = $(SRC_TEST)/test_dake
TESTS_USER_PROFILE = $(SRC_TEST)/test_user_profile

test: check
	./$(TESTS_OTRV4)
	./$(TESTS_DAKE)
	./$(TESTS_USER_PROFILE)

ci: test mem-check

code-check:
	splint +trytorecover src/*.h src/**.c `pkg-config --cflags glib-2.0`

mem-check: all
	valgrind --quiet --leak-check=full ./$(TESTS_OTRV4)
	valgrind --quiet --leak-check=full ./$(TESTS_DAKE)
	valgrind --quiet --leak-check=full ./$(TESTS_USER_PROFILE)

