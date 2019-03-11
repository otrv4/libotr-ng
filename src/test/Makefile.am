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

check_PROGRAMS = functional unit all

otrng_sources = ../alloc.c \
                    ../auth.c \
                    ../base64.c \
                    ../client.c \
                    ../client_callbacks.c \
                    ../client_orchestration.c \
                    ../client_profile.c \
                    ../dake.c \
                    ../data_message.c \
                    ../debug.c \
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
                    ../prekey_message.c \
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
                    ../util.c \
                    ../tlv.c

functional_sources = \
			functionals/test_api.c \
			functionals/test_client.c \
			functionals/test_double_ratchet.c \
			functionals/test_prekey_client.c \
			functionals/test_smp.c

unit_sources = \
			units/test_auth.c \
			units/test_client.c \
			units/test_client_profile.c \
			units/test_dake.c \
			units/test_data_message.c \
			units/test_dh.c \
			units/test_ed448.c \
			units/test_fragment.c \
			units/test_identity_message.c \
			units/test_instance_tag.c \
			units/test_key_management.c \
			units/test_list.c \
			units/test_messaging.c \
			units/test_non_interactive_messages.c \
			units/test_orchestration.c \
			units/test_otrng.c \
			units/test_prekey_ensemble.c \
			units/test_prekey_messages.c \
			units/test_prekey_profile.c \
			units/test_prekey_proofs.c \
			units/test_prekey_server_client.c \
			units/test_serialize.c \
		    units/test_standard.c \
			units/test_tlv.c

# I wish we didn't have to do it, but listing
# all source files in libotr-ng/src is the only
# way to get access to the tstatic files
functional_SOURCES = functional.c \
			test_fixtures.c \
	        $(functional_sources) \
	        $(otrng_sources)

unit_SOURCES = unit.c \
			test_fixtures.c \
	        $(unit_sources) \
	        $(otrng_sources)

all_SOURCES = all.c \
			test_fixtures.c \
	        $(unit_sources) \
	        $(functional_sources) \
	        $(otrng_sources)

deps_cflags = $(GLIB_CFLAGS) @LIBGOLDILOCKS_CFLAGS@ @LIBGCRYPT_CFLAGS@ @LIBSODIUM_CFLAGS@ @LIBOTR_CFLAGS@
deps_ldflags = $(GLIB_LIBS) @LIBGOLDILOCKS_LIBS@ @LIBGCRYPT_LIBS@ @LIBSODIUM_LIBS@ @LIBOTR_LIBS@

analysis_cflags = $(CODE_COVERAGE_CFLAGS) $(GPROF_CFLAGS) $(SANITIZER_CFLAGS)
analysis_ldflags = $(CODE_COVERAGE_LIBS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS)

functional_CFLAGS = -I$(top_builddir)/src $(AM_CFLAGS) $(analysis_cflags) $(deps_cflags) -DOTRNG_TESTS
functional_LDFLAGS = $(AM_LDFLAGS) $(analysis_ldflags) $(deps_ldflags)

unit_CFLAGS = -I$(top_builddir)/src $(AM_CFLAGS) $(analysis_cflags) $(deps_cflags) -DOTRNG_TESTS
unit_LDFLAGS = $(AM_LDFLAGS) $(analysis_ldflags) $(deps_ldflags)

all_CFLAGS = -I$(top_builddir)/src $(AM_CFLAGS) $(analysis_cflags) $(deps_cflags) -DOTRNG_TESTS
all_LDFLAGS = $(AM_LDFLAGS) $(analysis_ldflags) $(deps_ldflags)
