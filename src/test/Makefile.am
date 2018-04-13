#
#  This file is part of the Off-the-Record Next Generation Messaging
#  library (libotr-ng).
#
#  Copyright (C) 2016-2018, the libotr-ng contributors.
#
#  This library is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
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
		     ../v3.c \
		     ../otrng.c \
		     ../serialize.c \
		     ../shake.c \
		     ../smp.c \
		     ../str.c \
		     ../tlv.c \
		     ../user_profile.c

test_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS) $(CODE_COVERAGE_CFLAGS) @LIBGOLDILOCKS_CFLAGS@ \
                                                                  @LIBGCRYPT_CFLAGS@ \
                                                                  @LIBSODIUM_CFLAGS@ \
                                                                  @LIBOTR_CFLAGS@ \
                                                                  -DOTRNG_TESTS
test_LDFLAGS = $(AM_LDFLAGS) $(GLIB_LIBS) $(CODE_COVERAGE_LIBS) @LIBGOLDILOCKS_LIBS@ \
                                                                @LIBGCRYPT_LIBS@ \
                                                                @LIBSODIUM_LIBS@ \
                                                                @LIBOTR_LIBS@
