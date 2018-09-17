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

#include "client_profile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#define OTRNG_DESERIALIZE_PRIVATE
#include "deserialize.h"
#include "instance_tag.h"
#include "serialize.h"

static client_profile_s *client_profile_init(client_profile_s *profile,
                                             const char *versions) {
  memset(profile, 0, sizeof(client_profile_s));

  profile->versions = versions ? otrng_strdup(versions) : NULL;

  return profile;
}

tstatic client_profile_s *client_profile_new(const char *versions) {
  if (!versions) {
    return NULL;
  }

  client_profile_s *profile = malloc(sizeof(client_profile_s));
  if (!profile) {
    return NULL;
  }

  return client_profile_init(profile, versions);
}

static void copy_transitional_signature(client_profile_s *dst,
                                        const client_profile_s *src) {
  if (!src->transitional_signature) {
    return;
  }

  dst->transitional_signature = malloc(OTRv3_DSA_SIG_BYTES);

  if (!dst->transitional_signature) {
    return; // TODO: ERROR
  }

  memcpy(dst->transitional_signature, src->transitional_signature,
         OTRv3_DSA_SIG_BYTES);
}

static void copy_dsa_key(client_profile_s *dst, const client_profile_s *src) {
  if (!src->dsa_key || !src->dsa_key_len) {
    return;
  }

  size_t read = 0;
  uint16_t key_type = 0xFF;
  if (!otrng_deserialize_uint16(&key_type, src->dsa_key, src->dsa_key_len,
                                &read)) {
    return; // TODO: ERROR
  }

  if (key_type != OTRL_PUBKEY_TYPE_DSA) {
    // Not a DSA public key, so we dont know what to do from here
    return; // TODO: ERROR
  }

  if (!otrng_client_profile_set_dsa_key_mpis(dst, src->dsa_key + read,
                                             src->dsa_key_len - read)) {
    return; // TODO: ERROR
  }
}

INTERNAL void otrng_client_profile_copy(client_profile_s *dst,
                                        const client_profile_s *src) {
  /* If there are no fields present, do not point to invalid memory */
  client_profile_init(dst, NULL);

  if (!src) {
    return;
  }

  dst->sender_instance_tag = src->sender_instance_tag;
  otrng_ec_point_copy(dst->long_term_pub_key, src->long_term_pub_key);
  otrng_ec_point_copy(dst->forging_pub_key, src->forging_pub_key);
  dst->versions = otrng_strdup(src->versions);
  dst->expires = src->expires;
  copy_dsa_key(dst, src);
  copy_transitional_signature(dst, src);

  memcpy(dst->signature, src->signature, sizeof(eddsa_signature_p));
}

INTERNAL void otrng_client_profile_destroy(client_profile_s *profile) {
  if (!profile) {
    return;
  }

  /* @secret_information: the long-term public key gets deleted with the
     destruction of the client profile but can live beyond that */
  otrng_ec_point_destroy(profile->long_term_pub_key);

  otrng_ec_point_destroy(profile->forging_pub_key);

  free(profile->versions);
  profile->versions = NULL;

  free(profile->dsa_key);
  profile->dsa_key = NULL;

  free(profile->transitional_signature);
  profile->transitional_signature = NULL;
}

INTERNAL void otrng_client_profile_free(client_profile_s *profile) {
  otrng_client_profile_destroy(profile);
  free(profile);
}

tstatic uint32_t client_profile_body_serialize_pre_transitional_signature(
    uint8_t *dst, size_t dst_len, size_t *nbytes,
    const client_profile_s *profile) {
  size_t w = 0;
  uint32_t num_fields = 0;

  // TODO: Check for buffer overflows

  /* Instance tag */
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_INSTANCE_TAG);
  w += otrng_serialize_uint32(dst + w, profile->sender_instance_tag);
  num_fields++;

  /* Ed448 public key */
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_PUBLIC_KEY);
  w += otrng_serialize_public_key(dst + w, profile->long_term_pub_key);
  num_fields++;

  /* Ed448 forging key */
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_FORGING_KEY);
  w += otrng_serialize_forging_key(dst + w, profile->forging_pub_key);
  num_fields++;

  /* Versions */
  size_t versions_len = profile->versions ? strlen(profile->versions) + 1 : 1;
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_VERSIONS);
  w +=
      otrng_serialize_data(dst + w, (uint8_t *)profile->versions, versions_len);
  num_fields++;

  /* Expiration */
  w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_EXPIRATION);
  w += otrng_serialize_uint64(dst + w, profile->expires);
  num_fields++;

  /* DSA key */
  if (profile->dsa_key && profile->dsa_key_len) {
    w += otrng_serialize_uint16(dst + w, OTRNG_CLIENT_PROFILE_FIELD_DSA_KEY);
    w += otrng_serialize_bytes_array(dst + w, profile->dsa_key,
                                     profile->dsa_key_len);
    num_fields++;
  }

  if (nbytes) {
    *nbytes = w;
  }

  return num_fields;
}

tstatic otrng_result
client_profile_body_serialize(uint8_t *dst, size_t dst_len, size_t *nbytes,
                              const client_profile_s *profile) {
  size_t w = 0;
  uint32_t num_fields = 0;

  num_fields = client_profile_body_serialize_pre_transitional_signature(
      dst + 4, dst_len - 4, &w, profile);
  w += 4;

  // Transitional Signature
  if (profile->transitional_signature) {
    w += otrng_serialize_uint16(
        dst + w, OTRNG_CLIENT_PROFILE_FIELD_TRANSITIONAL_SIGNATURE);
    w += otrng_serialize_bytes_array(dst + w, profile->transitional_signature,
                                     OTRv3_DSA_SIG_BYTES);
    num_fields++;
  }

  // Writes the number of fields at the beginning
  otrng_serialize_uint32(dst, num_fields);

  if (nbytes) {
    *nbytes = w;
  }

  return OTRNG_SUCCESS;
}

/* Serializes client profile without the signature */
tstatic otrng_result client_profile_body_asprintf(
    uint8_t **dst, size_t *nbytes, const client_profile_s *profile) {

  size_t versions_len = profile->versions ? strlen(profile->versions) + 1 : 1;
  size_t s = OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(versions_len);

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

INTERNAL otrng_result otrng_client_profile_asprintf(
    uint8_t **dst, size_t *nbytes, const client_profile_s *profile) {

  size_t versions_len = profile->versions ? strlen(profile->versions) + 1 : 1;
  size_t s = OTRNG_CLIENT_PROFILE_MAX_BYTES(versions_len);

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

static otrng_result deserialize_dsa_key_field(client_profile_s *target,
                                              const uint8_t *buffer,
                                              size_t buflen, size_t *nread) {
  size_t read = 0;
  size_t w = 0;

  uint16_t key_type = 0xFF;
  if (!otrng_deserialize_uint16(&key_type, buffer + w, buflen - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (key_type != OTRL_PUBKEY_TYPE_DSA) {
    // Not a DSA public key, so we dont know what to do from here
    return OTRNG_ERROR;
  }

  // We dont care about the individual p, q, g, y
  // We just care about finding the end of this key

  for (int i = 0; i < 4; i++) {
    otrng_mpi_p mpi;
    if (!otrng_mpi_deserialize_no_copy(mpi, buffer + w, buflen - w, &read)) {
      return OTRNG_ERROR;
    }

    w += read + mpi->len;
  }

  target->dsa_key = malloc(w);
  if (!target->dsa_key) {
    return OTRNG_ERROR;
  }

  target->dsa_key_len = w;
  memcpy(target->dsa_key, buffer, w);

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result deserialize_field(client_profile_s *target,
                                       const uint8_t *buffer, size_t buflen,
                                       size_t *nread) {
  size_t read = 0;
  size_t w = 0;

  uint16_t field_type = 0;

  if (!otrng_deserialize_uint16(&field_type, buffer + w, buflen - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  read = 0;
  switch (field_type) {
  case OTRNG_CLIENT_PROFILE_FIELD_INSTANCE_TAG: /* Owner Instance Tag */
    if (!otrng_deserialize_uint32(&target->sender_instance_tag, buffer + w,
                                  buflen - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_PUBLIC_KEY: /* Ed448 public key */
    if (!otrng_deserialize_public_key(target->long_term_pub_key, buffer + w,
                                      buflen - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_FORGING_KEY: /* Ed448 forging key */
    if (!otrng_deserialize_forging_key(target->forging_pub_key, buffer + w,
                                       buflen - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_VERSIONS: /* Versions */
  {
    uint8_t *versions = NULL;
    size_t versions_len = 0;
    if (!otrng_deserialize_data(&versions, &versions_len, buffer + w,
                                buflen - w, &read)) {
      return OTRNG_ERROR;
    }

    target->versions = otrng_strndup((char *)versions, versions_len);
    free(versions);
  } break;
  case OTRNG_CLIENT_PROFILE_FIELD_EXPIRATION: /* Expiration */
    if (!otrng_deserialize_uint64(&target->expires, buffer + w, buflen - w,
                                  &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_DSA_KEY: /* DSA key */
    if (!deserialize_dsa_key_field(target, buffer + w, buflen - w, &read)) {
      return OTRNG_ERROR;
    }
    break;
  case OTRNG_CLIENT_PROFILE_FIELD_TRANSITIONAL_SIGNATURE: /* Transitional
                                                             Signature */
    target->transitional_signature = malloc(OTRv3_DSA_SIG_BYTES);
    if (!target->transitional_signature) {
      return OTRNG_ERROR;
    }

    if (!otrng_deserialize_bytes_array(target->transitional_signature,
                                       OTRv3_DSA_SIG_BYTES, buffer + w,
                                       buflen - w)) {
      return OTRNG_ERROR;
    }

    read = OTRv3_DSA_SIG_BYTES;

    break;
  }

  w += read;

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_profile_deserialize(client_profile_s *target,
                                                       const uint8_t *buffer,
                                                       size_t buflen,
                                                       size_t *nread) {
  size_t read = 0;
  int w = 0;

  if (!target) {
    return OTRNG_ERROR;
  }

  // So if there are fields not present they do not point to invalid memory
  client_profile_init(target, NULL);

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
  if (buflen - w < sizeof(eddsa_signature_p)) {
    return OTRNG_ERROR;
  }

  memcpy(target->signature, buffer + w, sizeof(eddsa_signature_p));

  w += sizeof(eddsa_signature_p);

  if (nread) {
    *nread = w;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result client_profile_sign(client_profile_s *profile,
                                         const otrng_keypair_s *keypair) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  otrng_ec_point_copy(profile->long_term_pub_key, keypair->pub);
  if (!client_profile_body_asprintf(&body, &bodylen, profile)) {
    return OTRNG_ERROR;
  }

  otrng_ec_sign_simple(profile->signature, keypair->sym, body, bodylen);

  free(body);
  return OTRNG_SUCCESS;
}

tstatic otrng_bool
client_profile_verify_signature(const client_profile_s *profile) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  uint8_t zero_buff[ED448_SIGNATURE_BYTES] = {0};
  if (memcmp(profile->signature, zero_buff, ED448_SIGNATURE_BYTES) == 0) {
    return otrng_false;
  }

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
otrng_client_profile_build(uint32_t instance_tag, const char *versions,
                           const otrng_keypair_s *keypair,
                           const otrng_public_key_p forging_key) {

  if (!otrng_instance_tag_valid(instance_tag) || !versions || !keypair) {
    return NULL;
  }

  client_profile_s *profile = client_profile_new(versions);
  if (!profile) {
    return NULL;
  }

  profile->sender_instance_tag = instance_tag;
// TODO: this should be configurable
#define PROFILE_EXPIRATION_SECONDS 2 * 7 * 24 * 60 * 60; /* 2 weeks */
  time_t expires = time(NULL);
  profile->expires = expires + PROFILE_EXPIRATION_SECONDS;

  otrng_ec_point_copy(profile->forging_pub_key, forging_key);

  if (!client_profile_sign(profile, keypair)) {
    otrng_client_profile_free(profile);
    return NULL;
  }

  return profile;
}

INTERNAL otrng_bool otrng_client_profile_expired(time_t expires) {
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

static otrng_result
generate_dsa_key_sexp(gcry_sexp_t *pubs, const uint8_t *buffer, size_t buflen) {
  if (!buffer || !buflen) {
    return OTRNG_ERROR;
  }

  dh_mpi_p p = NULL, q = NULL, g = NULL, y = NULL;
  dh_mpi_p *mpis[4] = {&p, &q, &g, &y};

  size_t read = 0;
  size_t w = 0;

  uint16_t key_type = 0xFF;
  if (!otrng_deserialize_uint16(&key_type, buffer + w, buflen - w, &read)) {
    return OTRNG_ERROR;
  }

  w += read;

  if (key_type != OTRL_PUBKEY_TYPE_DSA) {
    // Not a DSA public key, so we dont know what to do from here
    return OTRNG_ERROR;
  }

  for (int i = 0; i < 4 && w < buflen; i++) {
    if (!otrng_deserialize_dh_mpi_otr(mpis[i], buffer + w, buflen - w, &read)) {
      otrng_dh_mpi_release(p);
      otrng_dh_mpi_release(q);
      otrng_dh_mpi_release(g);
      otrng_dh_mpi_release(y);

      return OTRNG_ERROR;
    }

    w += read;
  }

#define DSA_PUBKEY_SEXP "(public-key (dsa (p %m)(q %m)(g %m)(y %m)))"
  gcry_error_t ret = gcry_sexp_build(pubs, NULL, DSA_PUBKEY_SEXP, p, q, g, y);

  otrng_dh_mpi_release(p);
  otrng_dh_mpi_release(q);
  otrng_dh_mpi_release(g);
  otrng_dh_mpi_release(y);

  if (ret) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result
client_profile_verify_transitional_signature(const client_profile_s *profile) {

  if (!profile->transitional_signature || !profile->dsa_key ||
      !profile->dsa_key_len) {
    return OTRNG_ERROR;
  }

  gcry_sexp_t pubs = NULL;
  if (!generate_dsa_key_sexp(&pubs, profile->dsa_key, profile->dsa_key_len)) {
    return OTRNG_ERROR;
  }

  size_t versions_len = profile->versions ? strlen(profile->versions) + 1 : 1;
  size_t s = OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(versions_len);

  uint8_t *data = malloc(s);
  if (!data) {
    gcry_sexp_release(pubs);
    return OTRNG_ERROR;
  }

  size_t datalen = 0;
  client_profile_body_serialize_pre_transitional_signature(data, s, &datalen,
                                                           profile);

  gcry_error_t err =
      otrl_privkey_verify(profile->transitional_signature, OTRv3_DSA_SIG_BYTES,
                          OTRL_PUBKEY_TYPE_DSA, pubs, data, datalen);

  free(data);
  gcry_sexp_release(pubs);
  if (err) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

static otrng_bool
verify_transitional_signature(const client_profile_s *profile) {
  if (!profile->dsa_key || !profile->dsa_key_len) {
    return otrng_true;
  }

  if (!profile->transitional_signature) {
    return otrng_true;
  }

  if (!client_profile_verify_transitional_signature(profile)) {
    return otrng_false;
  }

  return otrng_true;
}

INTERNAL otrng_bool otrng_client_profile_valid(
    const client_profile_s *profile, const uint32_t sender_instance_tag) {
  if (!client_profile_verify_signature(profile)) {
    return otrng_false;
  }

  if (sender_instance_tag != profile->sender_instance_tag) {
    return otrng_false;
  }

  if (otrng_client_profile_expired(profile->expires)) {
    return otrng_false;
  }

  if (rollback_detected(profile->versions)) {
    return otrng_false;
  }

  if (!otrng_ec_point_valid(profile->long_term_pub_key)) {
    return otrng_false;
  }

  if (!otrng_ec_point_valid(profile->forging_pub_key)) {
    return otrng_false;
  }

  if (!verify_transitional_signature(profile)) {
    return otrng_false;
  }

  return otrng_true;
}

INTERNAL otrng_result otrng_client_profile_set_dsa_key_mpis(
    client_profile_s *profile, const uint8_t *mpis, size_t mpis_len) {

  // mpis* points to a PUBKEY structure AFTER the "Pubkey type" field
  // We need to allocate 2 extra bytes for the "Pubkey type" field
  profile->dsa_key_len = mpis_len + 2;
  profile->dsa_key = malloc(profile->dsa_key_len);
  if (!profile->dsa_key) {
    return OTRNG_ERROR;
  }

  size_t w = otrng_serialize_uint16(profile->dsa_key, OTRL_PUBKEY_TYPE_DSA);
  memcpy(profile->dsa_key + w, mpis, mpis_len);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_profile_transitional_sign(
    client_profile_s *profile, OtrlPrivKey *privkey) {

  if (!profile || !privkey) {
    return OTRNG_ERROR;
  }

  if (privkey->pubkey_type != OTRL_PUBKEY_TYPE_DSA) {
    // Not a DSA public key, so we dont know what to do from here
    return OTRNG_ERROR;
  }

  if (!otrng_client_profile_set_dsa_key_mpis(profile, privkey->pubkey_data,
                                             privkey->pubkey_datalen)) {
    return OTRNG_ERROR;
  }

  size_t versions_len = profile->versions ? strlen(profile->versions) + 1 : 1;
  size_t s = OTRNG_CLIENT_PROFILE_FIELDS_MAX_BYTES(versions_len);

  uint8_t *data = malloc(s);
  if (!data) {
    return OTRNG_ERROR;
  }

  size_t datalen = 0;
  client_profile_body_serialize_pre_transitional_signature(data, s, &datalen,
                                                           profile);

  size_t written = 0;
  gcry_error_t err = otrl_privkey_sign(&profile->transitional_signature,
                                       &written, privkey, data, datalen);
  free(data);

  if (err) {
    return OTRNG_ERROR;
  }

  if (written != 40) {
    free(profile->transitional_signature);
    profile->transitional_signature = NULL;
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

#ifdef DEBUG_API

#include "debug.h"

API void otrng_client_profile_debug_print(FILE *f, int indent,
                                          client_profile_s *cp) {
  if (otrng_debug_print_should_ignore("client_profile")) {
    return;
  }

  otrng_print_indent(f, indent);
  fprintf(f, "client_profile(");
  otrng_debug_print_pointer(f, cp);
  fprintf(f, ") {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->sender_instance_tag")) {
    fprintf(f, "sender_instance_tag = IGNORED\n");
  } else {
    fprintf(f, "sender_instance_tag = %x\n", cp->sender_instance_tag);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->long_term_pub_key")) {
    fprintf(f, "long_term_pub_key = IGNORED\n");
  } else {
    fprintf(f, "long_term_pub_key = ");
    otrng_public_key_debug_print(f, cp->long_term_pub_key);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->versions")) {
    fprintf(f, "versions = IGNORED\n");
  } else {
    fprintf(f, "versions = %s\n", cp->versions);
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->expires")) {
    fprintf(f, "expires = IGNORED\n");
  } else {
    fprintf(f, "expires = ");
    otrng_debug_print_data(f, (uint8_t *)&(cp->expires), 8);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->dsa_key")) {
    fprintf(f, "dsa_key = IGNORED\n");
  } else {
    fprintf(f, "dsa_key = ");
    otrng_debug_print_data(f, cp->dsa_key, cp->dsa_key_len);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore(
          "client_profile->transitional_signature")) {
    fprintf(f, "transitional_signature = IGNORED\n");
  } else {
    fprintf(f, "transitional_signature = ");
    otrng_debug_print_data(f, cp->transitional_signature, OTRv3_DSA_SIG_BYTES);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client_profile->signature")) {
    fprintf(f, "signature = IGNORED\n");
  } else {
    fprintf(f, "signature = ");
    otrng_debug_print_data(f, cp->signature, ED448_SIGNATURE_BYTES);
    fprintf(f, "\n");
  }

  otrng_print_indent(f, indent);
  fprintf(f, "} // client_profile\n");
}

#endif
