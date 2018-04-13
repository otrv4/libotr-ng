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

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OTRNG_DESERIALIZE_PRIVATE

#include "deserialize.h"
#include "serialize.h"
#include "user_profile.h"

tstatic user_profile_s *user_profile_new(const string_p versions) {
  if (!versions)
    return NULL;

  user_profile_s *profile = malloc(sizeof(user_profile_s));
  if (!profile)
    return NULL;

  otrng_ec_bzero(profile->long_term_pub_key, ED448_POINT_BYTES);
  profile->expires = 0;
  profile->versions = otrng_strdup(versions);
  otrng_ec_bzero(profile->shared_prekey, ED448_POINT_BYTES);
  memset(profile->signature, 0, sizeof(profile->signature));
  otrng_mpi_init(profile->transitional_signature);

  return profile;
}

INTERNAL void otrng_user_profile_copy(user_profile_s *dst,
                                      const user_profile_s *src) {
  // TODO should we set dst to a valid (but empty) profile?
  if (!src)
    return;

  otrng_ec_point_copy(dst->long_term_pub_key, src->long_term_pub_key);
  dst->versions = otrng_strdup(src->versions);
  dst->expires = src->expires;
  otrng_ec_point_copy(dst->shared_prekey, src->shared_prekey);

  memcpy(dst->signature, src->signature, sizeof(eddsa_signature_p));
  otrng_mpi_copy(dst->transitional_signature, src->transitional_signature);
}

INTERNAL void otrng_user_profile_destroy(user_profile_s *profile) {
  if (!profile)
    return;

  otrng_ec_point_destroy(profile->long_term_pub_key);
  free(profile->versions);
  profile->versions = NULL;
  sodium_memzero(profile->signature, ED448_SIGNATURE_BYTES);
  otrng_ec_point_destroy(profile->shared_prekey);
  otrng_mpi_free(profile->transitional_signature);
}

INTERNAL void otrng_user_profile_free(user_profile_s *profile) {
  otrng_user_profile_destroy(profile);
  free(profile);
  profile = NULL;
}

tstatic int user_profile_body_serialize(uint8_t *dst,
                                        const user_profile_s *profile) {
  uint8_t *target = dst;

  target +=
      otrng_serialize_otrng_public_key(target, profile->long_term_pub_key);
  target += otrng_serialize_data(target, (uint8_t *)profile->versions,
                                 strlen(profile->versions) + 1);
  target += otrng_serialize_uint64(target, profile->expires);
  target += otrng_serialize_otrng_shared_prekey(target, profile->shared_prekey);

  return target - dst;
}

tstatic otrng_err user_profile_body_asprintf(uint8_t **dst, size_t *nbytes,
                                             const user_profile_s *profile) {
  size_t s = ED448_PUBKEY_BYTES + strlen(profile->versions) +
             ED448_SHARED_PREKEY_BYTES + 1 + 4 + 8;

  uint8_t *buff = malloc(s);
  if (!buff)
    return ERROR;

  user_profile_body_serialize(buff, profile);

  *dst = buff;
  if (nbytes)
    *nbytes = s;

  return SUCCESS;
}

INTERNAL otrng_err otrng_user_profile_asprintf(uint8_t **dst, size_t *nbytes,
                                               const user_profile_s *profile) {
  // TODO: should it checked here for signature?
  if (!(profile->signature > 0))
    return ERROR;

  uint8_t *buff = NULL;
  size_t body_len = 0;
  uint8_t *body = NULL;
  if (user_profile_body_asprintf(&body, &body_len, profile))
    return ERROR;

  size_t s = body_len + 4 + sizeof(eddsa_signature_p) +
             profile->transitional_signature->len;
  buff = malloc(s);
  if (!buff) {
    free(body);
    body = NULL;
    return ERROR;
  }

  uint8_t *cursor = buff;
  cursor += otrng_serialize_bytes_array(cursor, body, body_len);
  cursor += otrng_serialize_bytes_array(cursor, profile->signature,
                                        sizeof(eddsa_signature_p));
  cursor += otrng_serialize_mpi(cursor, profile->transitional_signature);

  *dst = buff;
  if (nbytes)
    *nbytes = s;

  free(body);
  body = NULL;

  return SUCCESS;
}

INTERNAL otrng_err otrng_user_profile_deserialize(user_profile_s *target,
                                                  const uint8_t *buffer,
                                                  size_t buflen,
                                                  size_t *nread) {
  size_t read = 0;
  int walked = 0;

  if (!target)
    return ERROR;

  otrng_err ok = ERROR;
  do {
    if (otrng_deserialize_otrng_public_key(target->long_term_pub_key, buffer,
                                           buflen, &read))
      continue;

    walked += read;

    if (otrng_deserialize_data((uint8_t **)&target->versions, buffer + walked,
                               buflen - walked, &read))
      continue;

    walked += read;

    if (otrng_deserialize_uint64(&target->expires, buffer + walked,
                                 buflen - walked, &read))
      continue;

    walked += read;

    if (otrng_deserialize_otrng_shared_prekey(
            target->shared_prekey, buffer + walked, buflen - walked, &read))
      continue;

    walked += read;

    // TODO: check the len
    if (buflen - walked < sizeof(eddsa_signature_p))
      continue;

    memcpy(target->signature, buffer + walked, sizeof(eddsa_signature_p));

    walked += sizeof(eddsa_signature_p);

    if (otrng_mpi_deserialize(target->transitional_signature, buffer + walked,
                              buflen - walked, &read))
      continue;

    walked += read;

    ok = SUCCESS;
  } while (0);

  if (nread)
    *nread = walked;

  return ok;
}

tstatic otrng_err user_profile_sign(user_profile_s *profile,
                                    const otrng_keypair_s *keypair) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  otrng_ec_point_copy(profile->long_term_pub_key, keypair->pub);
  if (user_profile_body_asprintf(&body, &bodylen, profile))
    return ERROR;

  uint8_t pubkey[ED448_POINT_BYTES];
  otrng_serialize_ec_point(pubkey, keypair->pub);

  // maybe otrng_ec_derive_public_key again?
  otrng_ec_sign(profile->signature, (uint8_t *)keypair->sym, pubkey, body,
                bodylen);

  free(body);
  body = NULL;
  return SUCCESS;
}

// TODO: I dont think this needs the data structure. Could verify from the
// deserialized bytes.
INTERNAL otrng_bool
otrng_user_profile_verify_signature(const user_profile_s *profile) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if (!(profile->signature > 0))
    return otrng_false;

  if (otrng_ec_point_valid(profile->shared_prekey) == ERROR)
    return otrng_false;

  if (user_profile_body_asprintf(&body, &bodylen, profile))
    return otrng_false;

  uint8_t pubkey[ED448_POINT_BYTES];
  otrng_serialize_ec_point(pubkey, profile->long_term_pub_key);

  otrng_bool valid = otrng_ec_verify(profile->signature, pubkey, body, bodylen);

  free(body);
  body = NULL;

  return valid;
}

INTERNAL user_profile_s *
otrng_user_profile_build(const string_p versions, otrng_keypair_s *keypair,
                         otrng_shared_prekey_pair_s *shared_prekey_pair) {
  user_profile_s *profile = user_profile_new(versions);
  if (!profile)
    return NULL;

#define PROFILE_EXPIRATION_SECONDS 2 * 7 * 24 * 60 * 60; /* 2 weeks */
  time_t expires = time(NULL);
  profile->expires = expires + PROFILE_EXPIRATION_SECONDS;

  memcpy(profile->shared_prekey, shared_prekey_pair->pub,
         sizeof(otrng_shared_prekey_pub_p));

  if (user_profile_sign(profile, keypair)) {
    otrng_user_profile_free(profile);
    return NULL;
  }

  return profile;
}
