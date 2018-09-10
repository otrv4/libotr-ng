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

lib_LTLIBRARIES = libotr-ng.la

libotr_ng_la_SOURCES = auth.c \
		     base64.c \
		     client.c \
		     client_callbacks.c \
		     client_profile.c \
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
		     padding.c \
		     prekey_client.c \
		     prekey_messages.c \
		     prekey_ensemble.c \
		     prekey_profile.c \
		     persistence.c \
		     protocol.c \
		     serialize.c \
		     shake.c \
		     smp.c \
		     smp_protocol.c \
		     str.c \
		     tlv.c

libotr_ng_la_CFLAGS = $(AM_CFLAGS) @LIBGOLDILOCKS_CFLAGS@ \
                                   @LIBSODIUM_CFLAGS@ \
                                   @LIBGCRYPT_CFLAGS@ \
				   $(CODE_COVERAGE_CFLAGS) \
                                   $(GPROF_CFLAGS) \
                                   $(SANITIZER_CFLAGS)

libotr_ng_la_LDFLAGS = $(AM_LDFLAGS) @LIBGOLDILOCKS_LIBS@ \
                                     @LIBSODIUM_LIBS@ \
                                     @LIBGCRYPT_LIBS@ \
				     $(CODE_COVERAGE_LIBS) \
			             $(GPROF_LDFLAGS) \
                                     $(SANITIZER_LDFLAGS)
