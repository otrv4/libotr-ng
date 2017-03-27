lib_LTLIBRARIES = libotr4.la

libotr4_la_SOURCES = \
		     b64.c \
		     client.c \
		     cramershoup_interface.c \
		     dake.c \
		     data_types.c \
		     data_message.c \
		     deserialize.c \
		     dh.c \
		     fingerprint.c \
		     list.c \
		     mpi.c \
		     otrv3.c \
		     otrv4.c \
		     serialize.c \
		     str.c \
		     tlv.c \
		     user_profile.c \
		     key_management.c

libotr4_la_CFLAGS = $(AM_CFLAGS) @LIBDECAF_CFLAGS@ \
                                 @LIBSODIUM_CFLAGS@ \
                                 @LIBGCRYPT_CFLAGS@ \
                                 @LIBCRAMERSHOUP_CFLAGS@ \
				 $(CODE_COVERAGE_CFLAGS)

libotr4_la_LDFLAGS = $(AM_LDFLAGS) @LIBDECAF_LIBS@ \
                                   @LIBSODIUM_LIBS@ \
                                   @LIBGCRYPT_LIBS@ \
                                   @LIBCRAMERSHOUP_LIBS@ \
				   $(CODE_COVERAGE_LIBS)

otrincdir = $(includedir)/libotr4
otrinc_HEADERS = client.h \
		 cramershoup_interface.h \
		 dake.h \
		 dh.h \
		 ed448.h \
		 fingerprint.h \
		 key_management.h \
		 list.h \
		 mpi.h \
		 otrv4.h \
		 random.h \
		 str.h \
		 user_profile.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = otr4.pc

