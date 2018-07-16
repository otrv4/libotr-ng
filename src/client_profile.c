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
  profile->signature = NULL;
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

  dst->signature = NULL;
  if (src->signature) {
    dst->signature = malloc(sizeof(eddsa_signature_p));
    if (!dst->signature) {
      return; // OTRNG_ERROR
    }
    memcpy(dst->signature, src->signature, sizeof(eddsa_signature_p));
  }

  otrng_mpi_copy(dst->transitional_signature, src->transitional_signature);
}

INTERNAL void otrng_client_profile_destroy(client_profile_s *profile) {
  if (!profile) {
    return;
  }

  /* @secret_information: the long-term public key gets deleted with the
     destruction of the client profile but can live beyond that */
  otrng_ec_point_destroy(profile->long_term_pub_key);
  free(profile->versions);
  profile->versions = NULL;
  free(profile->signature);
  profile->signature = NULL;
  otrng_mpi_free(profile->transitional_signature);
}

INTERNAL void otrng_client_profile_free(client_profile_s *profile) {
  otrng_client_profile_destroy(profile);
  free(profile);
}

// This serializes the body WITHOUT the signature
tstatic otrng_err
client_profile_body_serialize(uint8_t *dst, size_t dst_len, size_t *nbytes,
                              const client_profile_s *profile) {
  size_t w = 4;
  uint32_t num_fields = 0;

  // TODO: Add error checking for writing more than what is allocated

  // Instance tag
  w += otrng_serialize_uint16(dst + w, 0x01);
  w += otrng_serialize_uint32(dst + w, profile->sender_instance_tag);
  num_fields++;

  // Ed448 public key
  w += otrng_serialize_uint16(dst + w, 0x02);
  w += otrng_serialize_otrng_public_key(dst + w, profile->long_term_pub_key);
  num_fields++;

  // TODO: Forger public key

  // Versions
  w += otrng_serialize_uint16(dst + w, 0x04);
  w += otrng_serialize_data(dst + w, (uint8_t *)profile->versions,
                            strlen(profile->versions) + 1);
  num_fields++;

  // Expiration
  w += otrng_serialize_uint16(dst + w, 0x05);
  w += otrng_serialize_uint64(dst + w, profile->expires);
  num_fields++;

  // TODO: DSA key

  // Transitional Signature
  w += otrng_serialize_uint16(dst + w, 0x08);
  w += otrng_serialize_mpi(dst + w, profile->transitional_signature);
  num_fields++;

  // Writes the number of fields at the beginning
  otrng_serialize_uint32(dst, num_fields);

  if (nbytes) {
    *nbytes = w;
  }

  return OTRNG_SUCCESS;
}

// Serializes client profile without signature
tstatic otrng_err client_profile_body_asprintf(
    uint8_t **dst, size_t *nbytes, const client_profile_s *profile) {

  size_t versions_len = profile->versions ? strlen(profile->versions) + 1 : 1;

#define DH1536_MOD_LEN_BYTES 192
  size_t s = 4                        /* num fields */
             + 2 + 4                  /* instance tag */
             + 2 + ED448_PUBKEY_BYTES /* Ed448 pub key */
             + 0                      /* TODO: Forger Public key */
             + 2 + versions_len       /* Versions */
             + 2 + 8                  /* Expiration */
             + 2 + (2 + 4 * (4 + DH1536_MOD_LEN_BYTES)) /* DSA public key */
             + 2 + (2 * 20) /* Transitional signature */;

  uint8_t *buff = malloc(s);
  if (!buff) {
    return OTRNG_ERROR;
  }

  size_t written = 0;

  if (!client_profile_body_serialize(buff, s, &written, profile)) {
    free(buff);
    return OTRNG_ERROR;
  }

  *dst = buff;
  if (nbytes) {
    *nbytes = written;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_err otrng_client_profile_asprintf(
    uint8_t **dst, size_t *nbytes, const client_profile_s *profile) {

  if (!profile->signature) {
    return OTRNG_ERROR;
  }

  size_t versions_len = profile->versions ? strlen(profile->versions) + 1 : 1;
  size_t fields_len =
      2 + 4                                        /* instance tag */
      + 2 + ED448_PUBKEY_BYTES /* Ed448 pub key */ /* TODO: Forger Public key */
      + 2 + versions_len                           /* Versions */
      + 2 + 8                                      /* Expiration */
      + 2 + (2 + 4 * (4 + DH1536_MOD_LEN_BYTES))   /* DSA public key */
      + 2 + (2 * 20) /* Transitional signature */;

  size_t s = fields_len + ED448_SIGNATURE_BYTES;

  uint8_t *buff = malloc(s);
  if (!buff) {
    return OTRNG_ERROR;
  }

  size_t written = 0;
  if (!client_profile_body_serialize(buff, s, &written, profile)) {
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
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_err deserialize_field(client_profile_s *target,
                                    const uint8_t *buffer, size_t buflen,
                                    size_t *nread) {
  size_t read = 0;
  size_t w = 0;

  uint16_t field_type = 0;

  if (!otrng_deserialize_uint16(&field_type, buffer + w, buflen - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  switch (field_type) {
  case 0x01: // Owner Instance Tag
    if (!otrng_deserialize_uint32(&target->sender_instance_tag, buffer + w,
                                  buflen - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case 0x02: // Ed448 public key
    if (!otrng_deserialize_otrng_public_key(target->long_term_pub_key,
                                            buffer + w, buflen - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case 0x03: // Forger public key
    // TODO add field and deserialize
    break;
  case 0x04: // Versions
    if (!otrng_deserialize_data((uint8_t **)&target->versions, buffer + w,
                                buflen - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case 0x05: // Expiration
    // TODO: Double check if the format is the same
    if (!otrng_deserialize_uint64(&target->expires, buffer + w, buflen - w,
                                  &read)) {
      return OTRNG_ERROR;
    }
    break;
  case 0x06: // DSA key
    // TODO add field
    break;
  case 0x07: //???
    // ???
    break;
  case 0x08: // Transitional Signature
    // TODO Double check format: Is CLIENT-SIG a MPI?
    if (!otrng_mpi_deserialize(target->transitional_signature, buffer + w,
                               buflen - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  }

  w += read;

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_err otrng_client_profile_deserialize(client_profile_s *target,
                                                    const uint8_t *buffer,
                                                    size_t buflen,
                                                    size_t *nread) {
  size_t read = 0;
  int w = 0;

  if (!target) {
    return OTRNG_ERROR;
  }

  uint32_t num_fields = 0;
  if (!otrng_deserialize_uint32(&num_fields, buffer + w, buflen - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  for (; num_fields; num_fields--) {
    if (!deserialize_field(target, buffer + w, buflen - w, &read)) {
      return OTRNG_ERROR;
    }

    w += read;
  }

  // TODO: Extract function deserialize_transitional_signature
  // TODO: Double check format: is CLIENT-EDDSA-SIG a eddsa_signature_p?
  if (buflen - w < sizeof(eddsa_signature_p)) {
    return OTRNG_ERROR;
  }

  target->signature = malloc(sizeof(eddsa_signature_p));
  if (!target->signature) {
    return OTRNG_ERROR;
  }

  memcpy(target->signature, buffer + w, sizeof(eddsa_signature_p));

  w += sizeof(eddsa_signature_p);

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_err client_profile_sign(client_profile_s *profile,
                                      const otrng_keypair_s *keypair) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  profile->signature = malloc(sizeof(eddsa_signature_p));
  if (!profile->signature) {
    return OTRNG_ERROR;
  }

  otrng_ec_point_copy(profile->long_term_pub_key, keypair->pub);
  if (!client_profile_body_asprintf(&body, &bodylen, profile)) {
    free(profile->signature);
    profile->signature = NULL;
    return OTRNG_ERROR;
  }

  otrng_ec_sign_simple(profile->signature, keypair->sym, body, bodylen);

  free(body);
  return OTRNG_SUCCESS;
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

  uint8_t pubkey[ED448_POINT_BYTES] = {0};
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

INTERNAL otrng_bool otrng_client_profile_valid(
    const client_profile_s *profile, const uint32_t sender_instance_tag) {
  if (sender_instance_tag != profile->sender_instance_tag) {
    return otrng_false;
  }

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
