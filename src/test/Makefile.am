#
#  This file is part of the Off-the-Record Next Generation Messaging
#  library (libotr-ng).
#
#  Copyright (C) 2016-2018, the libotr-ng contributors.
#
#  This library is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation, either version 2.1 of the License, or
#  (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this library.  If not, see <http://www.gnu.org/licenses/>.
#

check_PROGRAMS = functional #unit

otrng_sources = ../alloc.c \
                    ../auth.c \
                    ../base64.c \
                    ../client.c \
                    ../client_callbacks.c \
                    ../client_profile.c \
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
                    ../v3.c \
                    ../otrng.c \
                    ../padding.c \
                    ../prekey_client.c \
                    ../prekey_messages.c \
                    ../prekey_ensemble.c \
                    ../prekey_profile.c \
                    ../prekey_proofs.c \
                    ../persistence.c \
                    ../protocol.c \
                    ../serialize.c \
                    ../shake.c \
                    ../smp.c \
                    ../smp_protocol.c \
                    ../str.c \
                    ../tlv.c

functional_sources = \
		    functionals/test_standard.c \
			functionals/test_messaging.c \
			functionals/test_ed448.c \
			functionals/test_instance_tag.c

# functional/test_api.c \
# functional/test_auth.c \
# functional/test_client.c \
# functional/test_client_profile.c \
# functional/test_dake.c \
# functional/test_data_message.c \
# functional/test_dh.c \
# functional/test_double_ratchet.c \
# functional/test_fragment.c \
# functional/test_identity_message.c \
# functional/test_key_management.c \
# functional/test_list.c \
# functional/test_non_interactive_messages.c \
# functional/test_otrng.c \
# functional/test_prekey_client.c \
# functional/test_prekey_ensemble.c \
# functional/test_prekey_messages.c \
# functional/test_prekey_profile.c \
# functional/test_prekey_proofs.c \
# functional/test_prekey_server_client.c \
# functional/test_serialize.c \
# functional/test_smp.c \
# functional/test_tlv.c

# I wish we didn't have to do it, but listing
# all source files in libotr-ng/src is the only
# way to get access to the tstatic files
functional_SOURCES = functional.c \
			test_fixtures.c \
	        $(functional_sources) \
	        $(otrng_sources)

functional_CFLAGS = -I$(top_builddir)/src $(AM_CFLAGS) $(GLIB_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(GPROF_CFLAGS) $(SANITIZER_CFLAGS) @LIBGOLDILOCKS_CFLAGS@ \
                                                                                                      @LIBGCRYPT_CFLAGS@ \
                                                                                                      @LIBSODIUM_CFLAGS@ \
                                                                                                      @LIBOTR_CFLAGS@ \
                                                                                                      -DOTRNG_TESTS

functional_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LIBS) $(CODE_COVERAGE_LIBS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS) @LIBGOLDILOCKS_LIBS@ \
                                                                                                      @LIBGCRYPT_LIBS@ \
                                                                                                      @LIBSODIUM_LIBS@ \
                                                                                                      @LIBOTR_LIBS@
