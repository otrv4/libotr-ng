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

#ifndef OTRNG_CLIENT_PROFILE_H
#define OTRNG_CLIENT_PROFILE_H

#include <stdint.h>

#include "keys.h"
#include "mpi.h"
#include "shared.h"
#include "str.h"

typedef struct client_profile_s {
  uint32_t id;
  uint32_t sender_instance_tag;
  otrng_public_key_p long_term_pub_key;
  string_p versions;
  uint64_t expires;

  // TODO: this should be an array of signatures :S
  eddsa_signature_p signature;
  otrng_mpi_p transitional_signature; // TODO: this should be a signature type
} client_profile_s, client_profile_p[1];

INTERNAL otrng_bool
otrng_client_profile_verify_signature(const client_profile_s *profile);

INTERNAL void otrng_client_profile_copy(client_profile_s *dst,
                                        const client_profile_s *src);

INTERNAL void otrng_client_profile_destroy(client_profile_s *profile);

INTERNAL void otrng_client_profile_free(client_profile_s *profile);

INTERNAL otrng_err otrng_client_profile_deserialize(client_profile_s *target,
                                                    const uint8_t *buffer,
                                                    size_t buflen,
                                                    size_t *nread);

INTERNAL otrng_err otrng_client_profile_asprintf(
    uint8_t **dst, size_t *nbytes, const client_profile_s *profile);

INTERNAL client_profile_s *
otrng_client_profile_build(uint32_t id, uint32_t instance_tag,
                           const string_p versions,
                           const otrng_keypair_s *keypair);

INTERNAL otrng_bool otrng_client_profile_valid(const client_profile_s *profile);

#ifdef OTRNG_USER_PROFILE_PRIVATE

tstatic client_profile_s *client_profile_new(const string_p versions);

tstatic otrng_err client_profile_sign(client_profile_s *profile,
                                      const otrng_keypair_s *keypair);

tstatic otrng_err client_profile_body_asprintf(uint8_t **dst, size_t *nbytes,
                                               const client_profile_s *profile);

#endif

#endif
