lib_LTLIBRARIES = libotr4.la

libotr4_la_SOURCES = dake.c \
										 data_types.c \
										 ed448.c \
										 otrv3.c \
										 otrv4.c \
										 serialize.c \
										 str.c \
										 user_profile.c

libotr4_la_CFLAGS = $(AM_CFLAGS) @LIBSODIUM_CFLAGS@ @LIBDECAF_CFLAGS@
libotr4_la_LDFLAGS = $(AM_LDFLAGS) @LIBSODIUM_LIBS@ @LIBDECAF_LIBS@

#libotr4_includedir = $(includedir)/otr4
#libotr4_include_HEADERS = \
#		src/otrv3.h \
#		src/otrv4.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = otr4.pc

