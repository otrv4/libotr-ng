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

#include "alloc.h"
#include "debug.h"
#include "deserialize.h"
#include "instance_tag.h"
#include "serialize.h"

INTERNAL void otrng_prekey_profile_destroy(otrng_prekey_profile_s *dst) {
  otrng_shared_prekey_pair_free(dst->keys);
  otrng_ec_point_destroy(dst->shared_prekey);
  memset(dst->signature, 0, ED448_SIGNATURE_BYTES);
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
  memset(dst, 0, sizeof(otrng_prekey_profile_s));

  if (!src) {
    return;
  }

  dst->instance_tag = src->instance_tag;
  dst->expires = src->expires;

  otrng_ec_point_copy(dst->shared_prekey, src->shared_prekey);
  if (dst->keys != NULL) {
    otrng_shared_prekey_pair_free(dst->keys);
    dst->keys = NULL;
  }

  if (src->keys != NULL) {
    dst->keys = otrng_secure_alloc(sizeof(otrng_shared_prekey_pair_s));
    memcpy(dst->keys, src->keys, sizeof(otrng_shared_prekey_pair_s));
  }

  memcpy(dst->signature, src->signature, ED448_SIGNATURE_BYTES);

  dst->should_publish = src->should_publish;
  dst->is_publishing = src->is_publishing;
}

static size_t
prekey_profile_body_serialize(uint8_t *dst, size_t dst_len,
                              const otrng_prekey_profile_s *profile) {
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
    otrng_prekey_profile_s *target, const uint8_t *buffer, size_t buff_len,
    size_t *nread) {
  size_t read = 0;
  size_t w = 0;

  if (!target) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&target->instance_tag, buffer + w, buff_len - w,
                                &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_uint64(&target->expires, buffer + w, buff_len - w,
                                &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_shared_prekey(target->shared_prekey, buffer + w,
                                       buff_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (!otrng_deserialize_bytes_array(target->signature, ED448_SIGNATURE_BYTES,
                                     buffer + w, buff_len - w)) {
    return OTRNG_ERROR;
  }

  w += ED448_SIGNATURE_BYTES;

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_prekey_profile_deserialize_with_metadata(
    otrng_prekey_profile_s *target, const uint8_t *buffer, size_t buff_len,
    size_t *nread) {
  size_t read = 0;
  size_t w = 0;
  otrng_result result =
      otrng_prekey_profile_deserialize(target, buffer, buff_len, &read);
  if (otrng_failed(result)) {
    return result;
  }

  w += read;

  result = otrng_deserialize_uint8(&target->should_publish, buffer + w,
                                   buff_len - w, &read);

  if (otrng_failed(result)) {
    return result;
  }

  w += read;

  target->keys = otrng_secure_alloc(sizeof(otrng_shared_prekey_pair_s));
  result = otrng_deserialize_bytes_array(target->keys->sym, ED448_PRIVATE_BYTES,
                                         buffer + w, buff_len - w);
  if (otrng_failed(result)) {
    return OTRNG_ERROR;
  }

  if (!otrng_shared_prekey_pair_generate(target->keys, target->keys->sym)) {
    return OTRNG_ERROR;
  }

  otrng_ec_point_copy(target->shared_prekey, target->keys->pub);

  w += ED448_PRIVATE_BYTES;

  if (otrng_failed(result)) {
    return result;
  }

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

#define PREKEY_PROFILE_BODY_BYTES 4 + 8 + ED448_PUBKEY_BYTES

static otrng_result
prekey_profile_body_serialize_into(uint8_t **dst, size_t *dst_len,
                                   const otrng_prekey_profile_s *profile) {
  size_t size = PREKEY_PROFILE_BODY_BYTES;
  uint8_t *buffer;
  size_t written;

  if (!dst) {
    return OTRNG_ERROR;
  }

  buffer = otrng_xmalloc_z(size);

  written = prekey_profile_body_serialize(buffer, size, profile);
  if (written == 0) {
    free(buffer);
    return OTRNG_ERROR;
  }

  *dst = buffer;

  if (dst_len) {
    *dst_len = written;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_prekey_profile_serialize(
    uint8_t **dst, size_t *dst_len, otrng_prekey_profile_s *profile) {
  size_t size = PREKEY_PROFILE_BODY_BYTES + ED448_SIGNATURE_BYTES;
  uint8_t *buffer = otrng_xmalloc_z(size);
  size_t written;

  written =
      prekey_profile_body_serialize(buffer, PREKEY_PROFILE_BODY_BYTES, profile);
  if (written == 0) {
    free(buffer);
    return OTRNG_ERROR;
  }

  if (size - written < ED448_SIGNATURE_BYTES) {
    free(buffer);
    return OTRNG_ERROR;
  }

  written += otrng_serialize_bytes_array(buffer + written, profile->signature,
                                         ED448_SIGNATURE_BYTES);

  *dst = buffer;
  if (dst_len) {
    *dst_len = written;
  } else {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_prekey_profile_serialize_with_metadata(
    uint8_t **dst, size_t *dst_len, otrng_prekey_profile_s *profile) {
  size_t size = PREKEY_PROFILE_BODY_BYTES + ED448_SIGNATURE_BYTES + 1 +
                ED448_PRIVATE_BYTES;
  uint8_t *buffer = otrng_xmalloc_z(size);
  size_t written;

  written =
      prekey_profile_body_serialize(buffer, PREKEY_PROFILE_BODY_BYTES, profile);
  if (written == 0) {
    free(buffer);
    return OTRNG_ERROR;
  }

  if (size - written < ED448_SIGNATURE_BYTES) {
    free(buffer);
    return OTRNG_ERROR;
  }

  written += otrng_serialize_bytes_array(buffer + written, profile->signature,
                                         ED448_SIGNATURE_BYTES);

  written += otrng_serialize_uint8(buffer + written, profile->should_publish);

  written += otrng_serialize_bytes_array(buffer + written, profile->keys->sym,
                                         ED448_PRIVATE_BYTES);

  *dst = buffer;
  if (dst_len) {
    *dst_len = written;
  } else {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result otrng_prekey_profile_sign(
    otrng_prekey_profile_s *profile, const otrng_keypair_s *longterm_pair) {
  uint8_t *body = NULL;
  size_t body_len = 0;
  if (!prekey_profile_body_serialize_into(&body, &body_len, profile)) {
    return OTRNG_ERROR;
  }

  otrng_ec_sign_simple(profile->signature, longterm_pair->sym, body, body_len);
  free(body);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_prekey_profile_s *
otrng_prekey_profile_build(uint32_t instance_tag,
                           const otrng_keypair_s *longterm_pair) {
  otrng_prekey_profile_s *prekey_profile;
  time_t expires = time(NULL);

  if (!longterm_pair || !otrng_instance_tag_valid(instance_tag)) {
    return NULL;
  }

  prekey_profile = otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));

  prekey_profile->keys = otrng_shared_prekey_pair_new();
  gcry_randomize(prekey_profile->keys->sym, ED448_PRIVATE_BYTES,
                 GCRY_VERY_STRONG_RANDOM);
  if (!otrng_shared_prekey_pair_generate(prekey_profile->keys,
                                         prekey_profile->keys->sym)) {
    otrng_prekey_profile_free(prekey_profile);
    return NULL;
  }

  otrng_ec_point_copy(prekey_profile->shared_prekey, prekey_profile->keys->pub);

  prekey_profile->instance_tag = instance_tag;

#define PREKEY_PROFILE_EXPIRATION_SECONDS 1 * 30 * 24 * 60 * 60; /* 1 month */
  prekey_profile->expires = expires + PREKEY_PROFILE_EXPIRATION_SECONDS;

  if (!otrng_prekey_profile_sign(prekey_profile, longterm_pair)) {
    otrng_prekey_profile_free(prekey_profile);
    return NULL;
  }

  return prekey_profile;
}

static otrng_bool
otrng_prekey_profile_verify_signature(const otrng_prekey_profile_s *profile,
                                      const otrng_public_key pub) {
  uint8_t *body = NULL;
  size_t body_len = 0;
  uint8_t zero_buffer[ED448_SIGNATURE_BYTES];
  uint8_t pubkey[ED448_POINT_BYTES];
  otrng_bool valid;

  memset(zero_buffer, 0, ED448_SIGNATURE_BYTES);

  if (memcmp(profile->signature, zero_buffer, ED448_SIGNATURE_BYTES) == 0) {
    return otrng_false;
  }

  if (!prekey_profile_body_serialize_into(&body, &body_len, profile)) {
    return otrng_false;
  }

  if (otrng_serialize_ec_point(pubkey, pub) != ED448_POINT_BYTES) {
    return otrng_false;
  }

  valid = otrng_ec_verify(profile->signature, pubkey, body, body_len);

  free(body);
  return valid;
}

INTERNAL otrng_bool otrng_prekey_profile_expired(time_t expires) {
  return (difftime(expires, time(NULL)) <= 0);
}

INTERNAL otrng_bool otrng_prekey_profile_invalid(time_t expires,
                                                 uint64_t extra_valid_time) {
  return difftime(expires + extra_valid_time, time(NULL)) <= 0;
}

tstatic otrng_bool otrng_prekey_profile_valid_without_expiry(
    const otrng_prekey_profile_s *profile, const uint32_t sender_instance_tag,
    const otrng_public_key pub) {
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

  /* 3. Validate that the Public Shared Prekey is on the curve Ed448-Goldilocks.
   */
  if (!otrng_ec_point_valid(profile->shared_prekey)) {
    return otrng_false;
  }

  return otrng_true;
}

INTERNAL otrng_bool otrng_prekey_profile_valid(
    const otrng_prekey_profile_s *profile, const uint32_t sender_instance_tag,
    const otrng_public_key pub) {
  if (!otrng_prekey_profile_valid_without_expiry(profile, sender_instance_tag,
                                                 pub)) {
    return otrng_false;
  }

  return !otrng_prekey_profile_expired(profile->expires);
}

INTERNAL otrng_bool otrng_prekey_profile_fast_valid(
    otrng_prekey_profile_s *profile, const uint32_t sender_instance_tag,
    const otrng_public_key pub) {
  if (profile->has_validated) {
    return profile->validation_result &&
           !otrng_prekey_profile_expired(profile->expires);
  }

  profile->validation_result =
      otrng_prekey_profile_valid(profile, sender_instance_tag, pub);
  profile->has_validated = otrng_true;

  return profile->validation_result;
}

/* This function should be called on a profile that is valid - it
   assumes this, and doesn't verify it. */
INTERNAL otrng_bool otrng_prekey_profile_is_close_to_expiry(
    const otrng_prekey_profile_s *profile, uint64_t buffer_time) {
  return otrng_prekey_profile_expired(profile->expires - buffer_time);
}

INTERNAL otrng_bool otrng_prekey_profile_is_expired_but_valid(
    const otrng_prekey_profile_s *profile, const uint32_t sender_instance_tag,
    uint64_t extra_valid_time, const otrng_public_key pub) {
  return otrng_prekey_profile_valid_without_expiry(profile, sender_instance_tag,
                                                   pub) &&
         otrng_prekey_profile_expired(profile->expires) &&
         !otrng_prekey_profile_invalid(profile->expires, extra_valid_time);
}

API void
otrng_prekey_profile_start_publishing(otrng_prekey_profile_s *profile) {
  profile->is_publishing = otrng_true;
}

API otrng_bool
otrng_prekey_profile_should_publish(const otrng_prekey_profile_s *profile) {
  return profile->should_publish && !profile->is_publishing;
}

#ifdef DEBUG_API

#include "debug.h"

API void otrng_prekey_profile_debug_print(FILE *f, int indent,
                                          otrng_prekey_profile_s *pp) {
  if (otrng_debug_print_should_ignore("prekey_profile")) {
    return;
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "prekey_profile(");
  otrng_debug_print_pointer(f, pp);
  debug_api_print(f, ") {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("prekey_profile->instance_tag")) {
    debug_api_print(f, "instance_tag = IGNORED\n");
  } else {
    debug_api_print(f, "instance_tag = %x\n", pp->instance_tag);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("prekey_profile->expires")) {
    debug_api_print(f, "expires = IGNORED\n");
  } else {
    debug_api_print(f, "expires = ");
    otrng_debug_print_data(f, (uint8_t *)&(pp->expires), 8);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("prekey_profile->shared_prekey")) {
    debug_api_print(f, "shared_prekey = IGNORED\n");
  } else {
    debug_api_print(f, "shared_prekey = ");
    otrng_public_key_debug_print(f, pp->shared_prekey);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("prekey_profile->signature")) {
    debug_api_print(f, "signature = IGNORED\n");
  } else {
    debug_api_print(f, "signature = ");
    otrng_debug_print_data(f, pp->signature, ED448_SIGNATURE_BYTES);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // client_profile\n");
}

#endif
