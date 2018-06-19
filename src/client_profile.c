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

#include "client_profile.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OTRNG_DESERIALIZE_PRIVATE
#include "deserialize.h"
#include "serialize.h"

tstatic client_profile_s *client_profile_new(const string_p versions) {
  if (!versions) {
    return NULL;
  }

  client_profile_s *profile = malloc(sizeof(client_profile_s));
  if (!profile) {
    return NULL;
  }

  profile->id = 0;
  profile->sender_instance_tag = 0;
  otrng_ec_bzero(profile->long_term_pub_key, ED448_POINT_BYTES);
  profile->expires = 0;
  profile->versions = otrng_strdup(versions);
  memset(profile->signature, 0, sizeof(profile->signature));
  otrng_mpi_init(profile->transitional_signature);

  return profile;
}

INTERNAL void otrng_client_profile_copy(client_profile_s *dst,
                                        const client_profile_s *src) {
  // TODO: @client_profile should we set dst to a valid (but empty) profile?
  if (!src) {
    return;
  }

  dst->id = src->id;
  dst->sender_instance_tag = src->sender_instance_tag;
  otrng_ec_point_copy(dst->long_term_pub_key, src->long_term_pub_key);
  dst->versions = otrng_strdup(src->versions);
  dst->expires = src->expires;

  memcpy(dst->signature, src->signature, sizeof(eddsa_signature_p));
  otrng_mpi_copy(dst->transitional_signature, src->transitional_signature);
}

INTERNAL void otrng_client_profile_destroy(client_profile_s *profile) {
  if (!profile) {
    return;
  }

  otrng_ec_point_destroy(profile->long_term_pub_key);
  free(profile->versions);
  profile->versions = NULL;
  sodium_memzero(profile->signature, ED448_SIGNATURE_BYTES);
  otrng_mpi_free(profile->transitional_signature);
}

INTERNAL void otrng_client_profile_free(client_profile_s *profile) {
  otrng_client_profile_destroy(profile);
  free(profile);
}

tstatic size_t client_profile_body_serialize(uint8_t *dst,
                                             const client_profile_s *profile) {
  uint8_t *target = dst;

  target += otrng_serialize_uint32(target, profile->id);
  target += otrng_serialize_uint32(target, profile->sender_instance_tag);
  target +=
      otrng_serialize_otrng_public_key(target, profile->long_term_pub_key);
  target += otrng_serialize_data(target, (uint8_t *)profile->versions,
                                 strlen(profile->versions) + 1);
  target += otrng_serialize_uint64(target, profile->expires);

  return target - dst;
}

tstatic otrng_err client_profile_body_asprintf(
    uint8_t **dst, size_t *nbytes, const client_profile_s *profile) {
  size_t s =
      4 + 4 + ED448_PUBKEY_BYTES + (strlen(profile->versions) + 1) + 4 + 8;

  uint8_t *buff = malloc(s);
  if (!buff) {
    return ERROR;
  }

  size_t written = client_profile_body_serialize(buff, profile);

  *dst = buff;
  if (nbytes) {
    *nbytes = written;
  }

  return SUCCESS;
}

INTERNAL otrng_err otrng_client_profile_asprintf(
    uint8_t **dst, size_t *nbytes, const client_profile_s *profile) {
  // TODO: @client_profile should it checked here for signature?
  if (!(profile->signature > 0)) {
    return ERROR;
  }

  uint8_t *buff = NULL;
  size_t body_len = 0;
  uint8_t *body = NULL;
  if (!client_profile_body_asprintf(&body, &body_len, profile)) {
    return ERROR;
  }

  size_t s = body_len + 4 + sizeof(eddsa_signature_p) +
             profile->transitional_signature->len;
  buff = malloc(s);
  if (!buff) {
    free(body);
    return ERROR;
  }

  uint8_t *cursor = buff;
  cursor += otrng_serialize_bytes_array(cursor, body, body_len);
  cursor += otrng_serialize_bytes_array(cursor, profile->signature,
                                        sizeof(eddsa_signature_p));
  cursor += otrng_serialize_mpi(cursor, profile->transitional_signature);

  *dst = buff;
  if (nbytes) {
    *nbytes = (cursor - buff);
  }

  free(body);
  return SUCCESS;
}

INTERNAL otrng_err otrng_client_profile_deserialize(client_profile_s *target,
                                                    const uint8_t *buffer,
                                                    size_t buflen,
                                                    size_t *nread) {
  size_t read = 0;
  int walked = 0;

  if (!target) {
    return ERROR;
  }

  otrng_err result = ERROR;
  do {
    if (!otrng_deserialize_uint32(&target->id, buffer + walked, buflen - walked,
                                  &read)) {
      continue;
    }

    walked += read;

    if (!otrng_deserialize_uint32(&target->sender_instance_tag, buffer + walked,
                                  buflen - walked, &read)) {
      continue;
    }

    walked += read;

    if (!otrng_deserialize_otrng_public_key(target->long_term_pub_key,
                                            buffer + walked, buflen - walked,
                                            &read)) {
      continue;
    }

    walked += read;

    if (!otrng_deserialize_data((uint8_t **)&target->versions, buffer + walked,
                                buflen - walked, &read)) {
      continue;
    }

    walked += read;

    if (!otrng_deserialize_uint64(&target->expires, buffer + walked,
                                  buflen - walked, &read)) {
      continue;
    }

    walked += read;

    // TODO: @client_profile check the len
    if (buflen - walked < sizeof(eddsa_signature_p)) {
      continue;
    }

    memcpy(target->signature, buffer + walked, sizeof(eddsa_signature_p));

    walked += sizeof(eddsa_signature_p);

    if (!otrng_mpi_deserialize(target->transitional_signature, buffer + walked,
                               buflen - walked, &read)) {
      continue;
    }

    walked += read;

    result = SUCCESS;
  } while (0);

  if (nread) {
    *nread = walked;
  }

  return result;
}

tstatic otrng_err client_profile_sign(client_profile_s *profile,
                                      const otrng_keypair_s *keypair) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  otrng_ec_point_copy(profile->long_term_pub_key, keypair->pub);
  if (!client_profile_body_asprintf(&body, &bodylen, profile)) {
    return ERROR;
  }

  otrng_ec_sign_simple(profile->signature, keypair->sym, body, bodylen);

  free(body);
  return SUCCESS;
}

// TODO: @client_profile I dont think this needs the data structure. Could
// verify from the deserialized bytes.
INTERNAL otrng_bool
otrng_client_profile_verify_signature(const client_profile_s *profile) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if (!client_profile_body_asprintf(&body, &bodylen, profile)) {
    return otrng_false;
  }

  uint8_t pubkey[ED448_POINT_BYTES];
  otrng_serialize_ec_point(pubkey, profile->long_term_pub_key);

  otrng_bool valid = otrng_ec_verify(profile->signature, pubkey, body, bodylen);

  free(body);
  return valid;
}

INTERNAL client_profile_s *
otrng_client_profile_build(uint32_t id, uint32_t instance_tag,
                           const string_p versions,
                           const otrng_keypair_s *keypair) {
  client_profile_s *profile = client_profile_new(versions);
  if (!profile) {
    return NULL;
  }

  profile->id = id;
  profile->sender_instance_tag = instance_tag;
#define PROFILE_EXPIRATION_SECONDS 2 * 7 * 24 * 60 * 60; /* 2 weeks */
  time_t expires = time(NULL);
  profile->expires = expires + PROFILE_EXPIRATION_SECONDS;

  if (!client_profile_sign(profile, keypair)) {
    otrng_client_profile_free(profile);
    return NULL;
  }

  return profile;
}

tstatic otrng_bool expired(time_t expires) {
  return difftime(expires, time(NULL)) <= 0;
}

tstatic otrng_bool rollback_detected(const char *versions) {
  while (*versions) {
    if (*versions != '3' && *versions != '4') {
      return otrng_true;
    }

    versions++;
  }

  return otrng_false;
}

// TODO: client_profile check if client profile is validate in every place it
// needs to
INTERNAL otrng_bool
otrng_client_profile_valid(const client_profile_s *profile) {
  if (expired(profile->expires)) {
    return otrng_false;
  }

  if (rollback_detected(profile->versions)) {
    return otrng_false;
  }

  if (!otrng_ec_point_valid(profile->long_term_pub_key)) {
    return otrng_false;
  }

  // TODO: @client_profile If the Transitional Signature is present, verify its
  // validity using the OTRv3 DSA key.
  // TODO: @client_profile @spec How are we going to have access to the OTRv3
  // long-term key in order to validate this signature?

  /* Verify their profile is valid (and not expired). */
  return otrng_client_profile_verify_signature(profile);
}
