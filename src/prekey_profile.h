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

/**
 * The functions in this file only operate on their arguments, and doesn't touch
 * any global state. It is safe to call these functions concurrently from
 * different threads, as long as arguments pointing to the same memory areas are
 * not used from different threads.
 */

#ifndef OTRNG_PREKEY_PROFILE_H
#define OTRNG_PREKEY_PROFILE_H

#include <stdint.h>

#include "ed448.h"
#include "keys.h"

typedef struct prekey_profile_s {
  uint32_t instance_tag;
  uint64_t expires;
  ec_point shared_prekey; /* Key "D" */
  eddsa_signature signature;

  otrng_shared_prekey_pair_s *keys;

  otrng_bool should_publish;
  otrng_bool is_publishing;

  otrng_bool has_validated;
  otrng_bool validation_result;
} otrng_prekey_profile_s;

INTERNAL void otrng_prekey_profile_destroy(otrng_prekey_profile_s *dst);

INTERNAL void otrng_prekey_profile_free(otrng_prekey_profile_s *dst);

INTERNAL void otrng_prekey_profile_copy(otrng_prekey_profile_s *dst,
                                        const otrng_prekey_profile_s *src);

INTERNAL otrng_prekey_profile_s *
otrng_prekey_profile_build(uint32_t instance_tag,
                           const otrng_keypair_s *longterm_pair);

INTERNAL otrng_bool otrng_prekey_profile_is_close_to_expiry(
    const otrng_prekey_profile_s *profile, uint64_t buffer_time);

INTERNAL otrng_bool otrng_prekey_profile_is_expired_but_valid(
    const otrng_prekey_profile_s *profile, uint32_t itag,
    uint64_t extra_valid_time, const otrng_public_key pub);

INTERNAL otrng_bool otrng_prekey_profile_valid(
    const otrng_prekey_profile_s *profile, const uint32_t sender_instance_tag,
    const otrng_public_key pub);

INTERNAL otrng_bool otrng_prekey_profile_fast_valid(
    otrng_prekey_profile_s *profile, const uint32_t sender_instance_tag,
    const otrng_public_key pub);

INTERNAL otrng_result otrng_prekey_profile_serialize(uint8_t **dst,
                                                     size_t *dst_len,
                                                     otrng_prekey_profile_s *p);

INTERNAL otrng_result otrng_prekey_profile_deserialize(
    otrng_prekey_profile_s *target, const uint8_t *buffer, size_t buflen,
    size_t *nread);

INTERNAL otrng_result otrng_prekey_profile_serialize_with_metadata(
    uint8_t **dst, size_t *dst_len, otrng_prekey_profile_s *p);

INTERNAL otrng_result otrng_prekey_profile_deserialize_with_metadata(
    otrng_prekey_profile_s *target, const uint8_t *buffer, size_t buflen,
    size_t *nread);

API void otrng_prekey_profile_start_publishing(otrng_prekey_profile_s *profile);
API otrng_bool
otrng_prekey_profile_should_publish(const otrng_prekey_profile_s *profile);

#ifdef DEBUG_API
API void otrng_prekey_profile_debug_print(FILE *, int,
                                          otrng_prekey_profile_s *);
#endif

#ifdef OTRNG_PREKEY_PROFILE_PRIVATE

tstatic otrng_result otrng_prekey_profile_sign(
    otrng_prekey_profile_s *profile, const otrng_keypair_s *longterm_pair);

#endif

#endif
