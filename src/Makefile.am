lib_LTLIBRARIES = libotr4.la

libotr4_la_SOURCES = \
		     auth.c \
		     b64.c \
		     client.c \
		     dake.c \
		     data_types.c \
		     data_message.c \
		     deserialize.c \
		     dh.c \
		     dread.c \
		     ed448.c \
		     fingerprint.c \
		     keys.c \
		     key_management.c \
		     list.c \
		     mpi.c \
		     otrv3.c \
		     otrv4.c \
		     serialize.c \
		     smp.c \
		     str.c \
		     tlv.c \
		     user_profile.c

libotr4_la_CFLAGS = $(AM_CFLAGS) @LIBDECAF_CFLAGS@ \
                                 @LIBSODIUM_CFLAGS@ \
                                 @LIBGCRYPT_CFLAGS@ \
				 $(CODE_COVERAGE_CFLAGS)

libotr4_la_LDFLAGS = $(AM_LDFLAGS) @LIBDECAF_LIBS@ \
                                   @LIBSODIUM_LIBS@ \
                                   @LIBGCRYPT_LIBS@ \
				   $(CODE_COVERAGE_LIBS)

otrincdir = $(includedir)/libotr4
otrinc_HEADERS = client.h \
		 dh.h \
		 ed448.h \
		 fingerprint.h \
		 keys.h \
		 key_management.h \
		 list.h \
		 mpi.h \
		 otrv4.h \
		 smp.h \
		 str.h \
		 tlv.h \
		 user_profile.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = otr4.pc

