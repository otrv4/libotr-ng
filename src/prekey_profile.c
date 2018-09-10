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

#include "prekey_profile.h"

#include <string.h>
#include <time.h>

#include "deserialize.h"
#include "instance_tag.h"
#include "serialize.h"

static otrng_prekey_profile_s *
prekey_profile_init(otrng_prekey_profile_s *profile, const char *versions) {
  profile->instance_tag = 0;
  otrng_ec_bzero(profile->shared_prekey, ED448_POINT_BYTES);
  profile->expires = 0;

  return profile;
}

INTERNAL void otrng_prekey_profile_destroy(otrng_prekey_profile_s *dst) {
  otrng_ec_point_destroy(dst->shared_prekey);
  memset(dst->signature, 0, sizeof(eddsa_signature_p));
}

INTERNAL void otrng_prekey_profile_free(otrng_prekey_profile_s *dst) {
  if (!dst) {
    return;
  }

  otrng_prekey_profile_destroy(dst);
  free(dst);
}

INTERNAL void otrng_prekey_profile_copy(otrng_prekey_profile_s *dst,
                                        const otrng_prekey_profile_s *src) {
  prekey_profile_init(dst, NULL);

  if (!src) {
    return;
  }

  dst->instance_tag = src->instance_tag;
  dst->expires = src->expires;

  otrng_ec_point_copy(dst->shared_prekey, src->shared_prekey);
  memcpy(dst->signature, src->signature, sizeof(eddsa_signature_p));
}

tstatic size_t otrng_prekey_profile_body_serialize(
    uint8_t *dst, size_t dst_len, const otrng_prekey_profile_s *profile) {
  size_t w = 0;

  if (4 > dst_len - w) {
    return 0;
  }

  w += otrng_serialize_uint32(dst + w, profile->instance_tag);

  if (8 > dst_len - w) {
    return 0;
  }

  w += otrng_serialize_uint64(dst + w, profile->expires);

  if (ED448_SHARED_PREKEY_BYTES > dst_len - w) {
    return 0;
  }

  w += otrng_serialize_shared_prekey(dst + w, profile->shared_prekey);

  return w;
}

INTERNAL otrng_result otrng_prekey_profile_deserialize(
    otrng_prekey_profile_s *target, const uint8_t *buffer, size_t buflen,
    size_t *nread) {
  size_t read = 0;
  size_t w = 0;

  if (!target) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&target->instance_tag, buffer + w, buflen - w,
                                &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_uint64(&target->expires, buffer + w, buflen - w,
                                &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_shared_prekey(target->shared_prekey, buffer + w,
                                       buflen - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_bytes_array(target->signature,
                                     sizeof(eddsa_signature_p), buffer + w,
                                     buflen - w)) {
    return OTRNG_ERROR;
  }

  w += sizeof(eddsa_signature_p);

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

#define PREKEY_PROFILE_BODY_BYTES 4 + 8 + ED448_PUBKEY_BYTES

tstatic otrng_result otrng_prekey_profile_body_asprint(
    uint8_t **dst, size_t *nbytes, const otrng_prekey_profile_s *profile) {
  if (!dst) {
    return OTRNG_ERROR;
  }

  size_t s = PREKEY_PROFILE_BODY_BYTES;
  uint8_t *buff = malloc(s);
  if (!buff) {
    return OTRNG_ERROR;
  }

  size_t written = otrng_prekey_profile_body_serialize(buff, s, profile);
  if (written == 0) {
    free(buff);
    return OTRNG_ERROR;
  }

  *dst = buff;

  if (nbytes) {
    *nbytes = written;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_prekey_profile_asprint(
    uint8_t **dst, size_t *nbytes, otrng_prekey_profile_s *profile) {
  size_t s = PREKEY_PROFILE_BODY_BYTES + sizeof(eddsa_signature_p);
  uint8_t *buff = malloc(s);
  if (!buff) {
    return OTRNG_ERROR;
  }

  size_t written = otrng_prekey_profile_body_serialize(
      buff, PREKEY_PROFILE_BODY_BYTES, profile);
  if (written == 0) {
    free(buff);
    return OTRNG_ERROR;
  }

  if (s - written < sizeof(eddsa_signature_p)) {
    free(buff);
    return OTRNG_ERROR;
  }

  written += otrng_serialize_bytes_array(buff + written, profile->signature,
                                         sizeof(eddsa_signature_p));

  *dst = buff;
  if (nbytes) {
    *nbytes = written;
  } else {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result prekey_profile_sign(
    otrng_prekey_profile_s *profile, const otrng_keypair_s *longterm_pair) {
  uint8_t *body = NULL;
  size_t bodylen = 0;
  if (!otrng_prekey_profile_body_asprint(&body, &bodylen, profile)) {
    return OTRNG_ERROR;
  }

  otrng_ec_sign_simple(profile->signature, longterm_pair->sym, body, bodylen);
  free(body);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_prekey_profile_s *
otrng_prekey_profile_build(uint32_t instance_tag,
                           const otrng_keypair_s *longterm_pair,
                           const otrng_shared_prekey_pair_s *prekey_pair) {
  if (!prekey_pair || !longterm_pair ||
      !otrng_instance_tag_valid(instance_tag)) {
    return NULL;
  }

  otrng_prekey_profile_s *p = malloc(sizeof(otrng_prekey_profile_s));
  if (!p) {
    return NULL;
  }

  p->instance_tag = instance_tag;

#define PREKEY_PROFILE_EXPIRATION_SECONDS 1 * 30 * 24 * 60 * 60; /* 1 month */
  time_t expires = time(NULL);
  p->expires = expires + PREKEY_PROFILE_EXPIRATION_SECONDS;
  otrng_ec_point_copy(p->shared_prekey, prekey_pair->pub); /* Key "D" */

  if (!prekey_profile_sign(p, longterm_pair)) {
    otrng_prekey_profile_free(p);
    return NULL;
  }

  return p;
}

static otrng_bool
otrng_prekey_profile_verify_signature(const otrng_prekey_profile_s *profile,
                                      const otrng_public_key_p pub) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  uint8_t zero_buff[ED448_SIGNATURE_BYTES] = {0};
  if (memcmp(profile->signature, zero_buff, ED448_SIGNATURE_BYTES) == 0) {
    return otrng_false;
  }

  if (!otrng_prekey_profile_body_asprint(&body, &bodylen, profile)) {
    return otrng_false;
  }

  uint8_t pubkey[ED448_POINT_BYTES];
  otrng_serialize_ec_point(pubkey, pub);

  otrng_bool valid = otrng_ec_verify(profile->signature, pubkey, body, bodylen);

  free(body);
  return valid;
}

static otrng_bool expired(time_t expires) {
  return (difftime(expires, time(NULL)) <= 0);
}

INTERNAL otrng_bool otrng_prekey_profile_valid(
    const otrng_prekey_profile_s *profile, const uint32_t sender_instance_tag,
    const otrng_public_key_p pub) {
  /* 1. Verify that the Prekey Profile signature is valid. */
  if (!otrng_prekey_profile_verify_signature(profile, pub)) {
    return otrng_false;
  }

  /* 2. Verify that the Prekey Profile owner's instance tag is equal to the
   * Sender Instance tag of the person that sent the DAKE message in which the
   * Prekey Profile is received. */
  if (sender_instance_tag != profile->instance_tag) {
    return otrng_false;
  }

  /* 3. Verify that the Prekey Profile has not expired. */
  if (expired(profile->expires)) {
    return otrng_false;
  }

  /* 4. Validate that the Public Shared Prekey is on the curve Ed448-Goldilocks.
   */
  if (!otrng_ec_point_valid(profile->shared_prekey)) {
    return otrng_false;
  }

  return otrng_true;
}

#ifdef DEBUG_API

#include "debug.h"

API void otrng_prekey_profile_debug_print(FILE *f, int indent,
                                          otrng_prekey_profile_s *pp) {
  if (otrng_debug_print_should_ignore("prekey_profile")) {
    return;
  }

  otrng_print_indent(f, indent);
  fprintf(f, "prekey_profile(");
  otrng_debug_print_pointer(f, pp);
  fprintf(f, ") {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("prekey_profile->instance_tag")) {
    fprintf(f, "instance_tag = IGNORED\n");
  } else {
    fprintf(f, "instance_tag = %x\n", pp->instance_tag);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("prekey_profile->expires")) {
    fprintf(f, "expires = IGNORED\n");
  } else {
    fprintf(f, "expires = ");
    otrng_debug_print_data(f, (uint8_t *)&(pp->expires), 8);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("prekey_profile->shared_prekey")) {
    fprintf(f, "shared_prekey = IGNORED\n");
  } else {
    fprintf(f, "shared_prekey = ");
    otrng_public_key_debug_print(f, pp->shared_prekey);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("prekey_profile->signature")) {
    fprintf(f, "signature = IGNORED\n");
  } else {
    fprintf(f, "signature = ");
    otrng_debug_print_data(f, pp->signature, ED448_SIGNATURE_BYTES);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent);
  fprintf(f, "} // client_profile\n");
}

#endif
