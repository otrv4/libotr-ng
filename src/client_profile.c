/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

#include "client_profile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OTRNG_DESERIALIZE_PRIVATE

#include "alloc.h"
#include "debug.h"
#include "deserialize.h"
#include "instance_tag.h"
#include "serialize.h"
#include "util.h"

tstatic /*@null@*/ otrng_client_profile_s *
client_profile_new(const char *versions) {
  otrng_client_profile_s *client_profile;
  if (!versions) {
    return NULL;
  }

  client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));
  client_profile->versions = otrng_xstrdup(versions);

  return client_profile;
}

static void copy_transitional_signature(otrng_client_profile_s *dst,
                                        const otrng_client_profile_s *src) {
  if (!src->transitional_signature) {
    return;
  }

  dst->transitional_signature = otrng_xmalloc_z(OTRv3_DSA_SIG_BYTES);

  memcpy(dst->transitional_signature, src->transitional_signature,
         OTRv3_DSA_SIG_BYTES);
}

static otrng_result
otrng_client_profile_set_dsa_key_mpis(otrng_client_profile_s *client_profile,
                                      const uint8_t *mpis, size_t mpis_len) {
  size_t w;

  // mpis* points to a PUBKEY structure AFTER the "Pubkey type" field
  // We need to allocate 2 extra bytes for the "Pubkey type" field
  client_profile->dsa_key_len = mpis_len + 2;
  client_profile->dsa_key = otrng_xmalloc_z(client_profile->dsa_key_len);

  w = otrng_serialize_uint16(client_profile->dsa_key, OTRL_PUBKEY_TYPE_DSA);
  memcpy(client_profile->dsa_key + w, mpis, mpis_len);

  return OTRNG_SUCCESS;
}

static otrng_bool copy_dsa_key(otrng_client_profile_s *dst,
                               const otrng_client_profile_s *src) {
  size_t read = 0;
  uint16_t key_type = 0xFF;

  if (!src->dsa_key || !src->dsa_key_len) {
    return otrng_true;
  }

  if (!otrng_deserialize_uint16(&key_type, src->dsa_key, src->dsa_key_len,
                                &read)) {
    return otrng_false;
  }

  if (key_type != OTRL_PUBKEY_TYPE_DSA) {
    /* Not a DSA public key */
    return otrng_false;
  }

  if (!otrng_client_profile_set_dsa_key_mpis(dst, src->dsa_key + read,
                                             src->dsa_key_len - read)) {
    return otrng_false;
  }

  return otrng_true;
}

INTERNAL otrng_bool otrng_client_profile_copy(
    otrng_client_profile_s *dst, const otrng_client_profile_s *src) {
  /* If there are no fields present, do not point to invalid memory */
  memset(dst, 0, sizeof(otrng_client_profile_s));

  if (!src) {
    return otrng_true;
  }

  dst->sender_instance_tag = src->sender_instance_tag;
  otrng_ec_point_copy(dst->long_term_pub_key, src->long_term_pub_key);
  otrng_ec_point_copy(dst->forging_pub_key, src->forging_pub_key);
  dst->versions = src->versions ? otrng_xstrdup(src->versions) : NULL;

  dst->expires = src->expires;
  if (!copy_dsa_key(dst, src)) {
    return otrng_false;
  }

  copy_transitional_signature(dst, src);

  memcpy(dst->signature, src->signature, ED448_SIGNATURE_BYTES);

  dst->should_publish = src->should_publish;
  dst->is_publishing = src->is_publishing;

  return otrng_true;
}

INTERNAL void
otrng_client_profile_destroy(otrng_client_profile_s *client_profile) {
  if (!client_profile) {
    return;
  }

  /* @secret_information: the long-term public key gets deleted with the
     destruction of the client profile but can live beyond that */
  otrng_ec_point_destroy(client_profile->long_term_pub_key);

  otrng_ec_point_destroy(client_profile->forging_pub_key);

  otrng_free(client_profile->versions);
  client_profile->versions = NULL;

  otrng_free(client_profile->dsa_key);
  client_profile->dsa_key = NULL;

  otrng_free(client_profile->transitional_signature);
  client_profile->transitional_signature = NULL;
}

INTERNAL void
otrng_client_profile_free(otrng_client_profile_s *client_profile) {
  otrng_client_profile_destroy(client_profile);
  otrng_free(client_profile);
}

tstatic uint32_t client_profile_body_serialize_pre_transitional_signature(
    uint8_t *dst, size_t dst_len, size_t *nbytes,
    const otrng_client_profile_s *client_profile) {
  size_t w = 0;
  uint32_t num_fields = 0;
  (void)dst_len;

  // TODO: Check for buffer overflows

  /* Instance tag */
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_INSTANCE_TAG);
  w += otrng_serialize_uint32(dst + w, client_profile->sender_instance_tag);
  num_fields++;

  printf("\n CHECK 11 \n");
  /* Ed448 public key */
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_PUBLIC_KEY);
  w += otrng_serialize_public_key(dst + w, client_profile->long_term_pub_key);
  num_fields++;

  printf("\n CHECK 12 \n");
  /* Ed448 forging key */
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_FORGING_KEY);
  w += otrng_serialize_forging_key(dst + w, client_profile->forging_pub_key);
  num_fields++;

  printf("\n CHECK 13 \n");
  /* Versions */
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_VERSIONS);
  w += otrng_serialize_data(dst + w, (uint8_t *)client_profile->versions,
                            otrng_strlen_ns(client_profile->versions));
  num_fields++;

  /* Expiration */
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_EXPIRATION);
  w += otrng_serialize_uint64(dst + w, client_profile->expires);
  num_fields++;

  /* DSA key */
  if ((client_profile->dsa_key != NULL) && (client_profile->dsa_key_len != 0)) {
    w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_DSA_KEY);
    w += otrng_serialize_bytes_array(dst + w, client_profile->dsa_key,
                                     client_profile->dsa_key_len);
    num_fields++;
  }

  if (nbytes) {
    *nbytes = w;
  }

  return num_fields;
}

tstatic otrng_result
client_profile_body_serialize(uint8_t *dst, size_t dst_len, size_t *nbytes,
                              const otrng_client_profile_s *client_profile) {
  size_t w = 0;
  uint32_t num_fields = 0;

  printf("\n CHECK 1 \n");
  num_fields = client_profile_body_serialize_pre_transitional_signature(
      dst + 4, dst_len - 4, &w, client_profile);
  w += 4;
  printf("\n CHECK 2 \n");

  /* Transitional Signature */
  if (client_profile->transitional_signature) {
    w += otrng_serialize_uint16(
        dst + w, OTRNG_CLIENT_PROFILE_FIELD_TRANSITIONAL_SIGNATURE);
    w += otrng_serialize_bytes_array(
        dst + w, client_profile->transitional_signature, OTRv3_DSA_SIG_BYTES);
    num_fields++;
  }

  printf("\n CHECK 3 \n");
  /* Write the number of fields at the beginning */
  /* TODO: this can't actually fail - so we should stop returning otrng_result
   * from this function */
  if (otrng_serialize_uint32(dst, num_fields) == 0) {
    return OTRNG_ERROR;
  }

  if (nbytes) {
    *nbytes = w;
  }

  printf("\n CHECK 4 \n");
  return OTRNG_SUCCESS;
}

/* Serializes client profile without the signature */
tstatic otrng_result client_profile_body_serialize_into(
    uint8_t **dst, size_t *nbytes,
    const otrng_client_profile_s *client_profile) {

  size_t s = OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(
      otrng_strlen_ns(client_profile->versions));
  size_t written = 0;

  uint8_t *buffer = otrng_xmalloc_z(s);

  if (!client_profile_body_serialize(buffer, s, &written, client_profile)) {
    otrng_free(buffer);
    return OTRNG_ERROR;
  }

  *dst = buffer;
  if (nbytes) {
    *nbytes = written;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_profile_serialize_with_metadata(
    uint8_t **dst, size_t *nbytes,
    const otrng_client_profile_s *client_profile) {

  size_t s = OTRNG_CLIENT_PROFILE_MAX_WITH_METADATA_BYTES(
      otrng_strlen_ns(client_profile->versions));

  size_t written = 0;
  uint8_t *buffer = otrng_xmalloc_z(s);

  if (!client_profile_body_serialize(buffer, s, &written, client_profile)) {
    otrng_free(buffer);
    return OTRNG_ERROR;
  }

  written += otrng_serialize_bytes_array(
      buffer + written, client_profile->signature, ED448_SIGNATURE_BYTES);

  written +=
      otrng_serialize_uint8(buffer + written, client_profile->should_publish);

  *dst = buffer;
  if (nbytes) {
    *nbytes = written;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_profile_serialize(uint8_t **dst, size_t *nbytes,
                               const otrng_client_profile_s *client_profile) {

  size_t s =
      OTRNG_CLIENT_PROFILE_MAX_BYTES(otrng_strlen_ns(client_profile->versions));

  size_t written = 0;
  uint8_t *buffer = otrng_xmalloc_z(s);

  if (!client_profile_body_serialize(buffer, s, &written, client_profile)) {
    otrng_free(buffer);
    return OTRNG_ERROR;
  }

  if (s - written < ED448_SIGNATURE_BYTES) {
    otrng_free(buffer);
    return OTRNG_ERROR;
  }

  written += otrng_serialize_bytes_array(
      buffer + written, client_profile->signature, ED448_SIGNATURE_BYTES);

  *dst = buffer;
  if (nbytes) {
    *nbytes = written;
  }

  return OTRNG_SUCCESS;
}

static otrng_result deserialize_dsa_key_field(otrng_client_profile_s *target,
                                              const uint8_t *buffer,
                                              size_t buff_len, size_t *nread) {
  size_t read = 0;
  size_t w = 0;
  int i;

  uint16_t key_type = 0xFF;
  if (!otrng_deserialize_uint16(&key_type, buffer + w, buff_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (key_type != OTRL_PUBKEY_TYPE_DSA) {
    /* Not a DSA public key */
    return OTRNG_ERROR;
  }

  for (i = 0; i < 4; i++) {
    otrng_mpi_s mpi = {.len = 0, .data = NULL};
    if (!otrng_mpi_deserialize_no_copy(&mpi, buffer + w, buff_len - w, &read)) {
      return OTRNG_ERROR;
    }

    w += read + mpi.len;
  }

  target->dsa_key = otrng_xmalloc_z(w);

  target->dsa_key_len = w;
  memcpy(target->dsa_key, buffer, w);

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result deserialize_field(otrng_client_profile_s *target,
                                       const uint8_t *buffer, size_t buff_len,
                                       size_t *nread) {
  size_t read = 0;
  size_t w = 0;

  uint16_t field_type = 0;

  if (!otrng_deserialize_uint16(&field_type, buffer + w, buff_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  read = 0;
  switch (field_type) {
  case OTRNG_CLIENT_PROFILE_FIELD_INSTANCE_TAG: /* Owner Instance Tag */
    if (!otrng_deserialize_uint32(&target->sender_instance_tag, buffer + w,
                                  buff_len - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_PUBLIC_KEY: /* Ed448 public key */
    if (!otrng_deserialize_public_key(target->long_term_pub_key, buffer + w,
                                      buff_len - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_FORGING_KEY: /* Ed448 forging key */
    if (!otrng_deserialize_forging_key(target->forging_pub_key, buffer + w,
                                       buff_len - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_VERSIONS: /* Versions */
  {
    uint8_t *versions = NULL;
    size_t versions_len = 0;

    if (!otrng_deserialize_data(&versions, &versions_len, buffer + w,
                                buff_len - w, &read)) {
      return OTRNG_ERROR;
    }
    target->versions = otrng_xmalloc_z(versions_len + 1);
    memcpy(target->versions, versions, versions_len);

    otrng_free(versions);
  } break;
  case OTRNG_CLIENT_PROFILE_FIELD_EXPIRATION: /* Expiration */
    if (!otrng_deserialize_uint64(&target->expires, buffer + w, buff_len - w,
                                  &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_DSA_KEY: /* DSA key */
    if (!deserialize_dsa_key_field(target, buffer + w, buff_len - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_TRANSITIONAL_SIGNATURE: /* Transitional
                                                             Signature */
    target->transitional_signature = otrng_xmalloc_z(OTRv3_DSA_SIG_BYTES);

    if (!otrng_deserialize_bytes_array(target->transitional_signature,
                                       OTRv3_DSA_SIG_BYTES, buffer + w,
                                       buff_len - w)) {
      return OTRNG_ERROR;
    }

    read = OTRv3_DSA_SIG_BYTES;

    break;
  default:
    break;
  }

  w += read;

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_profile_deserialize(
    otrng_client_profile_s *target, const uint8_t *buffer, size_t buff_len,
    size_t *nread) {
  size_t read = 0;
  int w = 0;
  uint32_t num_fields = 0;

  if (!target) {
    return OTRNG_ERROR;
  }

  /* So if there are fields not present they do not point to invalid memory */
  memset(target, 0, sizeof(otrng_client_profile_s));

  if (!otrng_deserialize_uint32(&num_fields, buffer + w, buff_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  for (; num_fields; num_fields--) {
    if (!deserialize_field(target, buffer + w, buff_len - w, &read)) {
      return OTRNG_ERROR;
    }

    w += read;
  }

  // TODO: @refactor Extract function deserialize_transitional_signature
  if (buff_len - w < ED448_SIGNATURE_BYTES) {
    return OTRNG_ERROR;
  }

  memcpy(target->signature, buffer + w, ED448_SIGNATURE_BYTES);

  w += ED448_SIGNATURE_BYTES;

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_profile_deserialize_with_metadata(
    otrng_client_profile_s *target, const uint8_t *buffer, size_t buff_len,
    size_t *nread) {
  size_t nread1 = 0, nread2 = 0;
  otrng_result result =
      otrng_client_profile_deserialize(target, buffer, buff_len, &nread1);
  if (otrng_failed(result)) {
    return result;
  }

  result = otrng_deserialize_uint8(&target->should_publish, buffer + nread1,
                                   buff_len - nread1, &nread2);

  if (otrng_failed(result)) {
    return result;
  }

  if (nread) {
    *nread = nread1 + nread2;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result client_profile_sign(otrng_client_profile_s *client_profile,
                                         const otrng_keypair_s *keypair) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  printf("\n AM I HERE INSIDE 31\n");
  otrng_ec_point_copy(client_profile->long_term_pub_key, keypair->pub);

  printf("\n AM I HERE INSIDE 32\n");
  if (!client_profile_body_serialize_into(&body, &bodylen, client_profile)) {
    return OTRNG_ERROR;
  }

  printf("\n AM I HERE INSIDE 33\n");
  otrng_ec_sign_simple(client_profile->signature, keypair->sym, body, bodylen);

  otrng_free(body);
  return OTRNG_SUCCESS;
}

tstatic otrng_bool
client_profile_verify_signature(const otrng_client_profile_s *client_profile) {
  uint8_t *body = NULL;
  size_t bodylen = 0;
  uint8_t pubkey[ED448_POINT_BYTES];
  otrng_bool valid;

  memset(pubkey, 0, ED448_POINT_BYTES);

  if (otrng_bool_is_true(otrng_is_empty_array(client_profile->signature,
                                              ED448_SIGNATURE_BYTES))) {
    return otrng_false;
  }

  if (!client_profile_body_serialize_into(&body, &bodylen, client_profile)) {
    return otrng_false;
  }

  if (otrng_serialize_ec_point(pubkey, client_profile->long_term_pub_key) !=
      ED448_POINT_BYTES) {
    return otrng_false;
  }

  valid = otrng_ec_verify(client_profile->signature, pubkey, body, bodylen);

  otrng_free(body);
  return valid;
}

INTERNAL /*@null@*/ otrng_client_profile_s *
otrng_client_profile_build_with_custom_expiration(
    uint32_t instance_tag, const char *versions, const otrng_keypair_s *keypair,
    const otrng_public_key forging_key, time_t expiration_time) {

  otrng_client_profile_s *client_profile;
  if ((otrng_instance_tag_valid(instance_tag) == otrng_false) || !versions ||
      !keypair) {
    return NULL;
  }

  printf("\n AM I HERE INSIDE 1\n");
  client_profile = client_profile_new(versions);
  if (!client_profile) {
    return NULL;
  }

  client_profile->sender_instance_tag = instance_tag;
  client_profile->expires = expiration_time;

  printf("\n AM I HERE INSIDE 2\n");
  otrng_ec_point_copy(client_profile->forging_pub_key, forging_key);

  printf("\n AM I HERE INSIDE 3\n");
  if (!client_profile_sign(client_profile, keypair)) {
    otrng_client_profile_free(client_profile);
    return NULL;
  }

  return client_profile;
}

INTERNAL /*@null@*/ otrng_client_profile_s *otrng_client_profile_build(
    uint32_t instance_tag, const char *versions, const otrng_keypair_s *keypair,
    const otrng_public_key forging_key, uint64_t expiration_time) {
  return otrng_client_profile_build_with_custom_expiration(
      instance_tag, versions, keypair, forging_key,
      time(NULL) + expiration_time);
}

static otrng_bool client_profile_expired(time_t expires) {
  return difftime(expires, time(NULL)) <= 0;
}

static otrng_bool client_profile_invalid(time_t expires,
                                         uint64_t extra_valid_time) {
  return difftime(expires + extra_valid_time, time(NULL)) <= 0;
}

tstatic otrng_bool rollback_detected(const char *versions) {
  while (*versions != '\0') {
    if (*versions != '3' && *versions != '4') {
      return otrng_true;
    }

    versions++;
  }

  return otrng_false;
}

static otrng_result generate_dsa_key_sexp(gcry_sexp_t *pubs,
                                          const uint8_t *buffer,
                                          size_t buff_len) {
  dh_mpi p = NULL, q = NULL, g = NULL, y = NULL;
  dh_mpi *mpis[4] = {&p, &q, &g, &y};

  size_t read = 0;
  size_t w = 0;
  int i;
  gcry_error_t ret;

  uint16_t key_type = 0xFF;

  if (!buffer || !buff_len) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint16(&key_type, buffer + w, buff_len - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (key_type != OTRL_PUBKEY_TYPE_DSA) {
    // Not a DSA public key, so we dont know what to do from here
    return OTRNG_ERROR;
  }

  for (i = 0; i < 4 && w < buff_len; i++) {
    if (!otrng_deserialize_dh_mpi_otr(mpis[i], buffer + w, buff_len - w,
                                      &read)) {
      if (p) {
        otrng_dh_mpi_release(p);
      }

      if (q) {
        otrng_dh_mpi_release(q);
      }

      if (g) {
        otrng_dh_mpi_release(g);
      }

      if (y) {
        otrng_dh_mpi_release(y);
      }

      return OTRNG_ERROR;
    }

    w += read;
  }

#define DSA_PUBKEY_SEXP "(public-key (dsa (p %m)(q %m)(g %m)(y %m)))"
  ret = gcry_sexp_build(pubs, NULL, DSA_PUBKEY_SEXP, p, q, g, y);

  otrng_dh_mpi_release(p);
  otrng_dh_mpi_release(q);
  otrng_dh_mpi_release(g);
  otrng_dh_mpi_release(y);

  if (ret) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result client_profile_verify_transitional_signature(
    const otrng_client_profile_s *client_profile) {
  gcry_sexp_t pubs = NULL;
  size_t size, data_len = 0;
  uint8_t *data;
  gcry_error_t err;

  if (!client_profile->transitional_signature || !client_profile->dsa_key ||
      !client_profile->dsa_key_len) {
    return OTRNG_ERROR;
  }

  if (!generate_dsa_key_sexp(&pubs, client_profile->dsa_key,
                             client_profile->dsa_key_len)) {
    return OTRNG_ERROR;
  }

  size = OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(
      otrng_strlen_ns(client_profile->versions));

  data = otrng_xmalloc_z(size);

  if (client_profile_body_serialize_pre_transitional_signature(
          data, size, &data_len, client_profile) < 5) {
    otrng_free(data);
    gcry_sexp_release(pubs);
    return OTRNG_ERROR;
  }

  err = otrl_privkey_verify(client_profile->transitional_signature,
                            OTRv3_DSA_SIG_BYTES, OTRL_PUBKEY_TYPE_DSA, pubs,
                            data, data_len);

  otrng_free(data);
  gcry_sexp_release(pubs);

  if (err) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

static otrng_bool
verify_transitional_signature(const otrng_client_profile_s *client_profile) {
  if (!client_profile->dsa_key || !client_profile->dsa_key_len) {
    return otrng_true;
  }

  if (!client_profile->transitional_signature) {
    return otrng_true;
  }

  if (!client_profile_verify_transitional_signature(client_profile)) {
    return otrng_false;
  }

  return otrng_true;
}

static otrng_bool client_profile_valid_without_expiry(
    const otrng_client_profile_s *client_profile,
    const uint32_t sender_instance_tag) {
  if (!client_profile_verify_signature(client_profile)) {
    return otrng_false;
  }

  if (sender_instance_tag != client_profile->sender_instance_tag) {
    return otrng_false;
  }

  if (rollback_detected(client_profile->versions)) {
    return otrng_false;
  }

  if (!otrng_ec_point_valid(client_profile->long_term_pub_key)) {
    return otrng_false;
  }

  if (!otrng_ec_point_valid(client_profile->forging_pub_key)) {
    return otrng_false;
  }

  if (!verify_transitional_signature(client_profile)) {
    return otrng_false;
  }

  return otrng_true;
}

INTERNAL otrng_bool
otrng_client_profile_valid(const otrng_client_profile_s *client_profile,
                           const uint32_t sender_instance_tag) {
  if (!client_profile_valid_without_expiry(client_profile,
                                           sender_instance_tag)) {
    return otrng_false;
  }

  return !client_profile_expired(client_profile->expires);
}

INTERNAL otrng_bool
otrng_client_profile_fast_valid(otrng_client_profile_s *client_profile,
                                const uint32_t sender_instance_tag) {
  if (client_profile->has_validated) {
    return client_profile->validation_result &&
           !client_profile_expired(client_profile->expires);
  }

  client_profile->validation_result =
      otrng_client_profile_valid(client_profile, sender_instance_tag);
  client_profile->has_validated = otrng_true;

  return client_profile->validation_result;
}

/* This function should be called on a profile that is valid - it
   assumes this, and doesn't verify it. */
INTERNAL otrng_bool otrng_client_profile_is_close_to_expiry(
    const otrng_client_profile_s *profile, uint64_t buffer_time) {
  return client_profile_expired(profile->expires - buffer_time);
}

INTERNAL otrng_bool otrng_client_profile_is_expired_but_valid(
    const otrng_client_profile_s *profile, uint32_t itag,
    uint64_t extra_valid_time) {
  return client_profile_valid_without_expiry(profile, itag) &&
         client_profile_expired(profile->expires) &&
         !client_profile_invalid(profile->expires, extra_valid_time);
}

INTERNAL otrng_result otrng_client_profile_transitional_sign(
    otrng_client_profile_s *client_profile, OtrlPrivKey *privkey) {
  size_t size;
  uint8_t *data;
  size_t data_len;
  size_t written;
  gcry_error_t err;

  if (!client_profile || !privkey) {
    return OTRNG_ERROR;
  }

  if (privkey->pubkey_type != OTRL_PUBKEY_TYPE_DSA) {
    /* Not a DSA public key */
    return OTRNG_ERROR;
  }

  if (!otrng_client_profile_set_dsa_key_mpis(
          client_profile, privkey->pubkey_data, privkey->pubkey_datalen)) {
    return OTRNG_ERROR;
  }

  size = OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(
      otrng_strlen_ns(client_profile->versions));

  data = otrng_xmalloc_z(size);
  data_len = 0;

  if (client_profile_body_serialize_pre_transitional_signature(
          data, size, &data_len, client_profile) < 5) {
    otrng_free(data);
    return OTRNG_ERROR;
  }

  written = 0;
  err = otrl_privkey_sign(&client_profile->transitional_signature, &written,
                          privkey, data, data_len);
  otrng_free(data);

  if (err) {
    return OTRNG_ERROR;
  }

  if (written != OTRv3_DSA_SIG_BYTES) {
    otrng_free(client_profile->transitional_signature);
    client_profile->transitional_signature = NULL;
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

API void
otrng_client_profile_start_publishing(otrng_client_profile_s *profile) {
  profile->is_publishing = otrng_true;
}

#include "debug.h"

API otrng_bool
otrng_client_profile_should_publish(const otrng_client_profile_s *profile) {
  return profile->should_publish && !profile->is_publishing;
}

#ifdef DEBUG_API

#include "debug.h"

API void otrng_client_profile_debug_print(FILE *f, int indent,
                                          otrng_client_profile_s *cp) {
  if (otrng_debug_print_should_ignore("client_profile")) {
    return;
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "client_profile(");
  otrng_debug_print_pointer(f, cp);
  debug_api_print(f, ") {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->sender_instance_tag")) {
    debug_api_print(f, "sender_instance_tag = IGNORED\n");
  } else {
    debug_api_print(f, "sender_instance_tag = %x\n", cp->sender_instance_tag);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->long_term_pub_key")) {
    debug_api_print(f, "long_term_pub_key = IGNORED\n");
  } else {
    debug_api_print(f, "long_term_pub_key = ");
    otrng_public_key_debug_print(f, cp->long_term_pub_key);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->versions")) {
    debug_api_print(f, "versions = IGNORED\n");
  } else {
    debug_api_print(f, "versions = %s\n", cp->versions);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->expires")) {
    debug_api_print(f, "expires = IGNORED\n");
  } else {
    debug_api_print(f, "expires = ");
    otrng_debug_print_data(f, (uint8_t *)&(cp->expires), 8);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->dsa_key")) {
    debug_api_print(f, "dsa_key = IGNORED\n");
  } else {
    debug_api_print(f, "dsa_key = ");
    otrng_debug_print_data(f, cp->dsa_key, cp->dsa_key_len);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore(
          "client_profile->transitional_signature")) {
    debug_api_print(f, "transitional_signature = IGNORED\n");
  } else {
    debug_api_print(f, "transitional_signature = ");
    otrng_debug_print_data(f, cp->transitional_signature, OTRv3_DSA_SIG_BYTES);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->signature")) {
    debug_api_print(f, "signature = IGNORED\n");
  } else {
    debug_api_print(f, "signature = ");
    otrng_debug_print_data(f, cp->signature, ED448_SIGNATURE_BYTES);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // client_profile\n");
}

#endif
