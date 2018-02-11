check_PROGRAMS = test

test_SOURCES = test.c \
		     ../auth.c \
		     ../client.c \
		     ../client_callbacks.c \
		     ../client_state.c \
		     ../dake.c \
		     ../data_message.c \
		     ../deserialize.c \
		     ../dh.c \
		     ../ed448.c \
		     ../fingerprint.c \
		     ../fragment.c \
		     ../instance_tag.c \
		     ../keys.c \
		     ../key_management.c \
		     ../list.c \
		     ../messaging.c \
		     ../mpi.c \
		     ../otrv3.c \
		     ../otrv4.c \
		     ../serialize.c \
		     ../smp.c \
		     ../str.c \
		     ../tlv.c \
		     ../user_profile.c

test_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS) $(CODE_COVERAGE_CFLAGS) @LIBDECAF_CFLAGS@ @LIBGCRYPT_CFLAGS@ @LIBSODIUM_CFLAGS@ @LIBOTR_CFLAGS@ -DOTRV4_TESTS
test_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LIBS) $(CODE_COVERAGE_LIBS) @LIBDECAF_LIBS@ @LIBGCRYPT_LIBS@ @LIBSODIUM_LIBS@ @LIBOTR_LIBS@
