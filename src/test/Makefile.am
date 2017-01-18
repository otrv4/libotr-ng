check_PROGRAMS = test_dake \
							   test_otrv4 \
								 test_user_profile

test_dake_SOURCES = test_dake.c
test_dake_CFLAGS = $(GLIB_CFLAGS) 
test_dake_LDFLAGS= $(GLIB_LIBS)
test_dake_LDADD = $(top_srcdir)/src/libotr4.la

test_otrv4_SOURCES = test_otrv4.c
test_otrv4_CFLAGS = $(GLIB_CFLAGS)
test_otrv4_LDFLAGS= $(GLIB_LIBS)
test_otrv4_LDADD = $(top_srcdir)/src/libotr4.la

test_user_profile_SOURCES = test_user_profile.c
test_user_profile_CFLAGS = $(GLIB_CFLAGS)
test_user_profile_LDFLAGS= $(GLIB_LIBS)
test_user_profile_LDADD = $(top_srcdir)/src/libotr4.la


