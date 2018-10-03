/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
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

#ifndef OTRNG_PREKEY_PROFILE_H
#define OTRNG_PREKEY_PROFILE_H

#include "ed448.h"
#include "keys.h"
#include <stdint.h>

typedef struct prekey_profile_s {
  uint32_t instance_tag;
  uint64_t expires;
  ec_point shared_prekey; /* Key "D" */
  eddsa_signature_t signature;
} otrng_prekey_profile_s;

INTERNAL void otrng_prekey_profile_destroy(otrng_prekey_profile_s *destination);

INTERNAL void otrng_prekey_profile_free(otrng_prekey_profile_s *destination);

INTERNAL void otrng_prekey_profile_copy(otrng_prekey_profile_s *destination,
                                        const otrng_prekey_profile_s *source);

INTERNAL otrng_prekey_profile_s *
otrng_prekey_profile_build(uint32_t instance_tag,
                           const otrng_keypair_s *longterm_pair,
                           const otrng_shared_prekey_pair_s *prekey_pair);

INTERNAL otrng_bool otrng_prekey_profile_expired(time_t expires);

INTERNAL otrng_bool otrng_prekey_profile_invalid(time_t expires,
                                                 uint64_t extra_valid_time);

INTERNAL otrng_bool otrng_prekey_profile_valid(
    const otrng_prekey_profile_s *profile, const uint32_t sender_instance_tag,
    const otrng_public_key pub);

INTERNAL otrng_result prekey_profile_sign(otrng_prekey_profile_s *profile,
                                          const otrng_keypair_s *longterm_pair);

INTERNAL otrng_result otrng_prekey_profile_serialize(uint8_t **destination,
                                                     size_t *destinationlen,
                                                     otrng_prekey_profile_s *p);

INTERNAL otrng_result otrng_prekey_profile_deserialize(
    otrng_prekey_profile_s *target, const uint8_t *buffer, size_t buflen,
    size_t *nread);

#ifdef DEBUG_API
API void otrng_prekey_profile_debug_print(FILE *, int,
                                          otrng_prekey_profile_s *);
#endif

#ifdef OTRNG_PREKEY_PROFILE_PRIVATE

tstatic otrng_result otrng_prekey_profile_body_serialize_into(
    uint8_t **destination, size_t *destinationlen, otrng_prekey_profile_s *p);

tstatic size_t otrng_prekey_profile_body_serialize(uint8_t *destination,
                                                   size_t destinationlen,
                                                   otrng_prekey_profile_s *p);

#endif

#endif
