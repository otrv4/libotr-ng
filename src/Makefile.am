lib_LTLIBRARIES = libotr4.la

libotr4_la_SOURCES = \
                     b64.c \
                     dake.c \
										 data_types.c \
										 data_message.c \
										 deserialize.c \
										 dh.c \
										 mpi.c \
										 otrv3.c \
										 otrv4.c \
										 serialize.c \
										 str.c \
										 user_profile.c \
										 key_management.c

libotr4_la_CFLAGS = $(AM_CFLAGS) @LIBDECAF_CFLAGS@ \
                                 @LIBSODIUM_CFLAGS@ \
                                 @LIBGCRYPT_CFLAGS@ \
                                 @LIBCRAMERSHOUP_CFLAGS@

libotr4_la_LDFLAGS = $(AM_LDFLAGS) @LIBDECAF_LIBS@ \
                                   @LIBSODIUM_LIBS@ \
                                   @LIBGCRYPT_LIBS@ \
                                   @LIBCRAMERSHOUP_LIBS@

otrincdir = $(includedir)/libotr4
otrinc_HEADERS = protocol.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = otr4.pc

