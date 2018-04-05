/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OTRNG_USER_PROFILE_H
#define OTRNG_USER_PROFILE_H

#include <stdint.h>

#include "keys.h"
#include "mpi.h"
#include "shared.h"
#include "str.h"

typedef struct {
  otrng_public_key_t pub_key;
  string_t versions;
  uint64_t expires;
  otrng_shared_prekey_pub_t shared_prekey;
  eddsa_signature_t signature;
  otrng_mpi_t transitional_signature; // TODO: this should be a signature type
} user_profile_t;

INTERNAL otrng_bool_t
otrng_user_profile_verify_signature(const user_profile_t *profile);

INTERNAL void otrng_user_profile_copy(user_profile_t *dst,
                                      const user_profile_t *src);

INTERNAL void otrng_user_profile_destroy(user_profile_t *profile);

INTERNAL void otrng_user_profile_free(user_profile_t *profile);

INTERNAL otrng_err_t otrng_user_profile_deserialize(user_profile_t *target,
                                                    const uint8_t *buffer,
                                                    size_t buflen,
                                                    size_t *nread);

INTERNAL otrng_err_t otrng_user_profile_asprintf(uint8_t **dst, size_t *nbytes,
                                                 const user_profile_t *profile);

INTERNAL user_profile_t *
otrng_user_profile_build(const string_t versions, otrng_keypair_t *keypair,
                         otrng_shared_prekey_pair_t *shared_prekey_keypair);

#ifdef OTRNG_USER_PROFILE_PRIVATE

tstatic user_profile_t *user_profile_new(const string_t versions);

tstatic otrng_err_t user_profile_sign(user_profile_t *profile,
                                      const otrng_keypair_t *keypair);

tstatic otrng_err_t user_profile_body_asprintf(uint8_t **dst, size_t *nbytes,
                                               const user_profile_t *profile);

#endif

#endif
