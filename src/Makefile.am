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

libotr_ng_la_SOURCES = $(top_builddir)/src/auth.c \
		     $(top_builddir)/src/base64.c \
		     $(top_builddir)/src/client.c \
		     $(top_builddir)/src/client_callbacks.c \
		     $(top_builddir)/src/client_profile.c \
		     $(top_builddir)/src/dake.c \
		     $(top_builddir)/src/data_message.c \
		     $(top_builddir)/src/deserialize.c \
		     $(top_builddir)/src/dh.c \
		     $(top_builddir)/src/ed448.c \
		     $(top_builddir)/src/fingerprint.c \
		     $(top_builddir)/src/fragment.c \
		     $(top_builddir)/src/instance_tag.c \
		     $(top_builddir)/src/keys.c \
		     $(top_builddir)/src/key_management.c \
		     $(top_builddir)/src/list.c \
		     $(top_builddir)/src/messaging.c \
		     $(top_builddir)/src/mpi.c \
		     $(top_builddir)/src/v3.c \
		     $(top_builddir)/src/otrng.c \
		     $(top_builddir)/src/padding.c \
		     $(top_builddir)/src/prekey_client.c \
		     $(top_builddir)/src/prekey_messages.c \
		     $(top_builddir)/src/prekey_ensemble.c \
		     $(top_builddir)/src/prekey_profile.c \
		     $(top_builddir)/src/persistence.c \
		     $(top_builddir)/src/protocol.c \
		     $(top_builddir)/src/serialize.c \
		     $(top_builddir)/src/shake.c \
		     $(top_builddir)/src/smp.c \
		     $(top_builddir)/src/smp_protocol.c \
		     $(top_builddir)/src/str.c \
		     $(top_builddir)/src/tlv.c

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
