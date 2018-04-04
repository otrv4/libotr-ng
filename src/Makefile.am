lib_LTLIBRARIES = libotr-ng.la

libotr-ng_la_SOURCES = \
		     auth.c \
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
		     messaging.c \
		     mpi.c \
		     v3.c \
		     otrng.c \
		     serialize.c \
		     smp.c \
		     str.c \
		     tlv.c \
		     user_profile.c

libotr-ng_la_CFLAGS = $(AM_CFLAGS) @LIBGOLDILOCKS_CFLAGS@ \
                                 @LIBSODIUM_CFLAGS@ \
                                 @LIBGCRYPT_CFLAGS@ \
				 $(CODE_COVERAGE_CFLAGS)

libotr-ng_la_LDFLAGS = $(AM_LDFLAGS) @LIBGOLDILOCKS_LIBS@ \
                                   @LIBSODIUM_LIBS@ \
                                   @LIBGCRYPT_LIBS@ \
				   $(CODE_COVERAGE_LIBS)




