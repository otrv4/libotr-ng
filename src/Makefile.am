lib_LTLIBRARIES = libotr4.la

libotr4_la_SOURCES = \
                     b64.c \
                     cramer_shoup.c \
                     dake.c \
										 data_types.c \
										 deserialize.c \
										 dh.c \
										 ed448.c \
										 mpi.c \
										 otrv3.c \
										 otrv4.c \
										 serialize.c \
										 str.c \
										 user_profile.c

libotr4_la_CFLAGS = $(AM_CFLAGS) @LIBDECAF_CFLAGS@ @LIBGCRYPT_CFLAGS@ @LIBCRAMERSHOUP_CFLAGS@
libotr4_la_LDFLAGS = $(AM_LDFLAGS) @LIBDECAF_LIBS@ @LIBGCRYPT_LIBS@ @LIBCRAMERSHOUP_LIBS@

#libotr4_includedir = $(includedir)/otr4
#libotr4_include_HEADERS = \
#		src/otrv3.h \
#		src/otrv4.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = otr4.pc

