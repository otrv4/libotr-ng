lib_LTLIBRARIES = libotr4.la

libotr4_la_SOURCES = \
		     auth.c \
		     b64.c \
		     client.c \
		     client_callbacks.c \
		     client_state.c \
		     dake.c \
		     data_message.c \
		     deserialize.c \
		     dh.c \
		     ed448.c \
		     fingerprint.c \
		     fragment.c \
		     instance_tag.c \
		     keys.c \
		     key_management.c \
		     list.c \
		     mem.c \
		     messaging.c \
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
otrinc_HEADERS = b64.h \
                 client.h \
		 client_state.h \
		 client_callbacks.h \
		 constants.h \
		 dake.h \
		 data_message.h \
		 dh.h \
		 ed448.h \
		 error.h \
		 fingerprint.h \
		 fragment.h \
		 instance_tag.h \
		 keys.h \
		 key_management.h \
		 list.h \
		 mem.h \
		 mpi.h \
		 messaging.h \
		 otrv3.h \
		 otrv4.h \
		 smp.h \
		 str.h \
		 tlv.h \
		 user_profile.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = otr4.pc

