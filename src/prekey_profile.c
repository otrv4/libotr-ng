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

#include "prekey_profile.h"

#include "serialize.h"
#include <string.h>
#include <time.h>

INTERNAL void otrng_prekey_profile_destroy(otrng_prekey_profile_s *dst) {
  otrng_ec_point_destroy(dst->pub);
  otrng_ec_point_destroy(dst->shared_prekey);
  memset(dst->signature, 0, sizeof(eddsa_signature_p));
}

INTERNAL void otrng_prekey_profile_free(otrng_prekey_profile_s *dst) {
  if (!dst)
    return;

  otrng_prekey_profile_destroy(dst);
  free(dst);
}

INTERNAL void otrng_prekey_profile_copy(otrng_prekey_profile_s *dst,
                                        const otrng_prekey_profile_s *src) {
  dst->id = src->id;
  dst->instance_tag = src->instance_tag;
  dst->expires = src->expires;

  otrng_ec_point_copy(dst->pub, src->pub);
  otrng_ec_point_copy(dst->shared_prekey, src->shared_prekey);
  memcpy(dst->signature, src->signature, sizeof(eddsa_signature_p));
}

tstatic size_t otrng_prekey_profile_body_serialize(uint8_t *dst, size_t dstlen,
                                                   otrng_prekey_profile_s *p) {
  size_t w = 0;

  if (4 > dstlen - w)
    return 0;

  w += otrng_serialize_uint32(dst + w, p->id);

  if (4 > dstlen - w)
    return 0;

  w += otrng_serialize_uint32(dst + w, p->instance_tag);

  if (ED448_PUBKEY_BYTES > dstlen - w)
    return 0;

  w += otrng_serialize_otrng_public_key(dst + w, p->pub);

  if (8 > dstlen - w)
    return 0;

  w += otrng_serialize_uint64(dst + w, p->expires);

  if (ED448_PUBKEY_BYTES > dstlen - w)
    return 0;

  w += otrng_serialize_otrng_shared_prekey(dst + w, p->shared_prekey);

  return w;
}

tstatic otrng_err otrng_prekey_profile_body_asprint(uint8_t **dst,
                                                    size_t *dstlen,
                                                    otrng_prekey_profile_s *p) {

#define PREKEY_PROFILE_BODY_BYTES                                              \
  4 + 4 + ED448_PUBKEY_BYTES + 8 + ED448_PUBKEY_BYTES

  if (!dst)
    return ERROR;

  *dst = malloc(PREKEY_PROFILE_BODY_BYTES);
  if (*dst == NULL)
    return ERROR;

  size_t written =
      otrng_prekey_profile_body_serialize(*dst, PREKEY_PROFILE_BODY_BYTES, p);
  if (written == 0) {
    free(*dst);
    *dst = NULL;
  }

  if (dstlen)
    *dstlen = written;

  return SUCCESS;
}

// TODO: Add id and instance tag as parameter
INTERNAL otrng_prekey_profile_s *
otrng_prekey_profile_build(const otrng_keypair_s *longterm_pair,
                           const otrng_shared_prekey_pair_s *prekey_pair) {
  otrng_prekey_profile_s *p = malloc(sizeof(otrng_prekey_profile_s));
  if (!p)
    return NULL;

  p->id = 0;
  p->instance_tag = 0;

#define PREKEY_PROFILE_EXPIRATION_SECONDS 1 * 30 * 24 * 60 * 60; /* 1 month */
  time_t expires = time(NULL);
  p->expires = expires + PREKEY_PROFILE_EXPIRATION_SECONDS;

  otrng_ec_point_copy(p->pub, longterm_pair->pub);         // Key "H"
  otrng_ec_point_copy(p->shared_prekey, prekey_pair->pub); // Key "D"

  uint8_t *body = NULL;
  size_t bodylen = 0;
  if (!otrng_prekey_profile_body_asprint(&body, &bodylen, p)) {
    otrng_prekey_profile_free(p);
    return NULL;
  }

  otrng_ec_sign_simple(p->signature, longterm_pair->sym, body, bodylen);
  free(body);

  return p;
}
