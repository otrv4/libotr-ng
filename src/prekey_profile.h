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

#ifndef OTRNG_PREKEY_PROFILE_H
#define OTRNG_PREKEY_PROFILE_H

#include "ed448.h"
#include "keys.h"
#include <stdint.h>

typedef struct prekey_profile_s {
  uint32_t id;
  uint32_t instance_tag;
  uint64_t expires;
  ec_point_p pub;           // Key "H"
  ec_point_p shared_prekey; // Key "D"
  eddsa_signature_p signature;
} otrng_prekey_profile_s, otrng_prekey_profile_p[1];

INTERNAL void otrng_prekey_profile_destroy(otrng_prekey_profile_s *dst);

INTERNAL void otrng_prekey_profile_free(otrng_prekey_profile_s *dst);

INTERNAL void otrng_prekey_profile_copy(otrng_prekey_profile_s *dst,
                                        const otrng_prekey_profile_s *src);

INTERNAL otrng_prekey_profile_s *
otrng_prekey_profile_build(uint32_t id, uint32_t instance_tag,
                           const otrng_keypair_s *longterm_pair,
                           const otrng_shared_prekey_pair_s *prekey_pair);

INTERNAL otrng_bool
otrng_prekey_profile_valid(const otrng_prekey_profile_s *profile);

INTERNAL otrng_err prekey_profile_sign(otrng_prekey_profile_s *profile,
                                       const otrng_keypair_s *longterm_pair);

#ifdef OTRNG_PREKEY_PROFILE_PRIVATE

tstatic otrng_err otrng_prekey_profile_body_asprint(uint8_t **dst,
                                                    size_t *dstlen,
                                                    otrng_prekey_profile_s *p);

tstatic size_t otrng_prekey_profile_body_serialize(uint8_t *dst, size_t dstlen,
                                                   otrng_prekey_profile_s *p);

#endif

#endif
