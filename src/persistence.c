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

#include <assert.h>

#include "alloc.h"
#include "base64.h"
#include "deserialize.h"
#include "messaging.h"
#include "persistence.h"
#include "serialize.h"

static size_t otrng_client_get_storage_id_len(const otrng_client_s *client) {
  return strlen(client->client_id.protocol) +
         strlen(client->client_id.account) + 1;
}

static char *otrng_client_get_storage_id(const otrng_client_s *client) {
  size_t n = otrng_client_get_storage_id_len(client) + 1;
  char *key = otrng_xmalloc(n);
  int res = snprintf(key, n, "%s:%s", client->client_id.protocol,
                     client->client_id.account);

  if (res < 0) {
    free(key);
    return NULL;
  }

  return key;
}

#define BASE64_ENCODED_SYMMETRIC_SECRET_LENGTH                                 \
  ((ED448_PRIVATE_BYTES + 2) / 3 * 4)

/* Returns the maximum length a serialization of a v4 private key can take,
   for given client. It is usually going to be dependent on the identifiers,
   so the calculation can't be used for another client. It assumes
   everything is correct about the client id - the result is undefined if not.
 */
INTERNAL size_t
otrng_client_private_key_v4_get_max_length(const otrng_client_s *client) {
  return otrng_client_get_storage_id_len(client) + 1 +
         BASE64_ENCODED_SYMMETRIC_SECRET_LENGTH + 1;
}

API otrng_result otrng_client_private_key_v4_write_to_buffer(
    const otrng_client_s *client, uint8_t *buf, size_t buflen,
    size_t *written) {
  char *key;
  size_t s = 0;
  size_t keylen = 0;
  size_t w = 0;

  if (!client->keypair) {
    return OTRNG_ERROR;
  }

  key = otrng_client_get_storage_id(client);
  if (!key) {
    return OTRNG_ERROR;
  }
  keylen = strlen(key);

  if (s + keylen + 1 > buflen) {
    return OTRNG_ERROR;
  }
  memcpy(buf + s, key, keylen);
  free(key);
  s += keylen;

  *(buf + s) = '\n';
  s++;

  if (s + BASE64_ENCODED_SYMMETRIC_SECRET_LENGTH + 1 > buflen) {
    return OTRNG_ERROR;
  }
  w = otrl_base64_encode((char *)buf + s, client->keypair->sym,
                         ED448_PRIVATE_BYTES);
  s += w;

  *(buf + s) = '\n';
  s++;

  if (written) {
    *written = s;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_private_key_v4_write_to(const otrng_client_s *client, FILE *fp) {
  size_t w = 0;
  size_t buflen = otrng_client_private_key_v4_get_max_length(client);
  uint8_t *buffer = otrng_xmalloc_z(buflen * sizeof(uint8_t));
  int err;

  if (!fp) {
    free(buffer);
    return OTRNG_ERROR;
  }

  if (otrng_failed(otrng_client_private_key_v4_write_to_buffer(client, buffer,
                                                               buflen, &w))) {
    free(buffer);
    return OTRNG_ERROR;
  }

  err = fwrite(buffer, 1, w, fp);
  free(buffer);

  if (err != 1) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_forging_key_write_to(
    const otrng_client_s *client, FILE *forgingf) {
  uint8_t *buffer;
  size_t size;
  char *encoded;
  char *storage_id;

  if (!forgingf) {
    return OTRNG_ERROR;
  }

  if (!client->forging_key) {
    return OTRNG_ERROR;
  }

  buffer = otrng_secure_alloc((2 + ED448_POINT_BYTES) * sizeof(uint8_t));

  size = otrng_serialize_forging_key(buffer, *client->forging_key);
  if (size == 0) {
    return OTRNG_ERROR;
  }

  encoded = otrng_base64_encode(buffer, size);
  otrng_secure_wipe(buffer, (2 + ED448_POINT_BYTES) * sizeof(uint8_t));
  free(buffer);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    otrng_secure_wipe(encoded, strlen(encoded));
    free(encoded);
    return OTRNG_ERROR;
  }

  if (fprintf(forgingf, "%s\n%s\n", storage_id, encoded) < 0) {
    free(storage_id);
    otrng_secure_wipe(encoded, strlen(encoded));
    free(encoded);
    return OTRNG_ERROR;
  }

  free(storage_id);
  otrng_secure_wipe(encoded, strlen(encoded));
  free(encoded);

  return OTRNG_SUCCESS;
}

#define MAX_LINE_LENGTH 1000

static int get_limited_line(char **buf, FILE *f) {
  char *res = NULL;

  assert(buf);

  *buf = otrng_xmalloc_z(MAX_LINE_LENGTH * sizeof(char));

  res = fgets(*buf, MAX_LINE_LENGTH, f);
  if (res == NULL) {
    free(*buf);
    *buf = NULL;
    return -1;
  }

  return strlen(*buf);
}

tstatic otrng_result otrng_client_read_from_prefix(FILE *fp, uint8_t **dec,
                                                   size_t *dec_len) {

  char *line;
  int len;

  assert(fp);

  len = get_limited_line(&line, fp);

  if (len < 0) {
    return OTRNG_ERROR;
  }

  *dec = otrng_xmalloc_z(OTRNG_BASE64_DECODE_LEN(len));
  *dec_len = otrl_base64_decode(*dec, line, len);
  free(line);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_private_key_v4_read_from(otrng_client_s *client, FILE *privf) {
  char *line = NULL;
  int len = 0;
  otrng_keypair_s *keypair;

  if (!privf) {
    return OTRNG_ERROR;
  }

  if (feof(privf)) {
    return OTRNG_ERROR;
  }

  // Free current keypair if any
  otrng_keypair_free(client->keypair);
  client->keypair = NULL;

  keypair = otrng_keypair_new();
  if (!keypair) {
    return OTRNG_ERROR;
  }

  len = get_limited_line(&line, privf);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  if (!otrng_symmetric_key_deserialize(keypair, line, len)) {
    free(line);
    otrng_keypair_free(keypair);
    return OTRNG_ERROR;
  }

  free(line);

  client->keypair = keypair;

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_forging_key_read_from(otrng_client_s *client,
                                                         FILE *fp) {
  uint8_t *dec;
  size_t dec_len;
  otrng_public_key key;
  otrng_result result = otrng_client_read_from_prefix(fp, &dec, &dec_len);

  if (otrng_failed(result)) {
    return result;
  }

  result = otrng_deserialize_forging_key(key, dec, dec_len, NULL);
  free(dec);

  if (otrng_failed(result)) {
    return result;
  }

  if (client->forging_key) {
    otrng_ec_point_destroy(*client->forging_key);
    free(client->forging_key);
    client->forging_key = NULL;
  }

  return otrng_client_add_forging_key(client, key);
}

INTERNAL otrng_result otrng_client_instance_tag_write_to(otrng_client_s *client,
                                                         FILE *instagf) {
  gcry_error_t ret;

  ret = otrl_instag_generate_FILEp(client->global_state->user_state_v3, instagf,
                                   client->client_id.account,
                                   client->client_id.protocol);

  if (ret) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_instance_tag_read_from(otrng_client_s *client, FILE *instagf) {
  gcry_error_t ret;

  if (client->global_state->user_state_v3 == NULL) {
    return OTRNG_ERROR;
  }

  ret = otrl_instag_read_FILEp(client->global_state->user_state_v3, instagf);

  if (ret) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_private_key_v3_read_from(const otrng_client_s *client, FILE *fp) {
  OtrlUserState us = client->global_state->user_state_v3;

  if (otrl_privkey_read_FILEp(us, fp)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_client_profile_read_from(otrng_client_s *client, FILE *fp) {
  uint8_t *dec;
  size_t dec_len;
  otrng_client_profile_s profile;
  otrng_result result = otrng_client_read_from_prefix(fp, &dec, &dec_len);

  if (otrng_failed(result)) {
    return result;
  }

  memset(&profile, 0, sizeof(otrng_client_profile_s));
  result = otrng_client_profile_deserialize_with_metadata(&profile, dec,
                                                          dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  otrng_client_profile_free(client->client_profile);
  client->client_profile = NULL;

  result = otrng_client_add_client_profile(client, &profile);
  otrng_client_profile_destroy(&profile);

  return result;
}

INTERNAL otrng_result otrng_client_expired_client_profile_read_from(
    otrng_client_s *client, FILE *fp) {
  uint8_t *dec;
  size_t dec_len;
  otrng_client_profile_s exp_profile;
  otrng_result result = otrng_client_read_from_prefix(fp, &dec, &dec_len);

  if (otrng_failed(result)) {
    return result;
  }

  memset(&exp_profile, 0, sizeof(otrng_client_profile_s));
  result = otrng_client_profile_deserialize(&exp_profile, dec, dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  otrng_client_profile_free(client->exp_client_profile);
  client->exp_client_profile = NULL;

  result = otrng_client_add_exp_client_profile(client, &exp_profile);

  otrng_client_profile_destroy(&exp_profile);

  return result;
}

INTERNAL otrng_result otrng_client_client_profile_write_to(
    const otrng_client_s *client, FILE *profilef) {
  uint8_t *buffer = NULL;
  size_t s = 0;
  char *encoded;
  char *storage_id;

  if (!profilef) {
    return OTRNG_ERROR;
  }

  if (!client->client_profile) {
    return OTRNG_ERROR;
  }

  if (!otrng_client_profile_serialize_with_metadata(&buffer, &s,
                                                    client->client_profile)) {
    return OTRNG_ERROR;
  }

  encoded = otrng_base64_encode(buffer, s);
  free(buffer);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    free(encoded);
    return OTRNG_ERROR;
  }

  if (fprintf(profilef, "%s\n%s\n", storage_id, encoded) < 0) {
    free(storage_id);
    free(encoded);
    return OTRNG_ERROR;
  }

  free(storage_id);
  free(encoded);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_expired_client_profile_write_to(
    const otrng_client_s *client, FILE *profilef) {
  uint8_t *buffer = NULL;
  size_t s = 0;
  char *encoded;
  char *storage_id;

  if (!profilef) {
    return OTRNG_ERROR;
  }

  if (!client->exp_client_profile) {
    return OTRNG_ERROR;
  }

  if (!otrng_client_profile_serialize_with_metadata(
          &buffer, &s, client->exp_client_profile)) {
    return OTRNG_ERROR;
  }

  encoded = otrng_base64_encode(buffer, s);
  free(buffer);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    free(encoded);
    return OTRNG_ERROR;
  }

  if (fprintf(profilef, "%s\n%s\n", storage_id, encoded) < 0) {
    free(storage_id);
    free(encoded);
    return OTRNG_ERROR;
  }

  free(storage_id);
  free(encoded);

  return OTRNG_SUCCESS;
}

static otrng_result serialize_and_store_prekey(const prekey_message_s *prekey,
                                               const char *storage_id,
                                               FILE *prekeyf) {
  int ret;
  uint8_t *tmp_buffer = NULL;
  otrng_result result;
  size_t w = 0;
  char *encoded = NULL;

  if (fprintf(prekeyf, "%s\n", storage_id) < 0) {
    return OTRNG_ERROR;
  }

  tmp_buffer = otrng_secure_alloc(PRE_KEY_WITH_METADATA_MAX_BYTES);
  result = otrng_prekey_message_serialize_with_metadata(
      tmp_buffer, PRE_KEY_WITH_METADATA_MAX_BYTES, &w, prekey);
  if (otrng_failed(result)) {
    otrng_secure_wipe(tmp_buffer, PRE_KEY_WITH_METADATA_MAX_BYTES);
    free(tmp_buffer);
    return result;
  }

  encoded = otrng_base64_encode(tmp_buffer, w);
  otrng_secure_wipe(tmp_buffer, PRE_KEY_WITH_METADATA_MAX_BYTES);
  free(tmp_buffer);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  ret = fprintf(prekeyf, "%s\n", encoded);
  otrng_secure_wipe(encoded, strlen(encoded));

  if (ret < 0) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_prekeys_write_to(const otrng_client_s *client, FILE *prekeyf) {
  char *storage_id;
  list_element_s *current;

  if (!prekeyf) {
    return OTRNG_ERROR;
  }

  if (!client->our_prekeys) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    return OTRNG_ERROR;
  }

  current = client->our_prekeys;
  while (current) {
    if (!serialize_and_store_prekey(current->data, storage_id, prekeyf)) {
      free(storage_id);
      return OTRNG_ERROR;
    }

    current = current->next;
  }

  free(storage_id);
  return OTRNG_SUCCESS;
}

static otrng_result read_and_deserialize_prekey(otrng_client_s *client,
                                                FILE *fp) {
  uint8_t *dec = NULL;
  size_t dec_len = 0;
  prekey_message_s *prekey_msg = NULL;
  otrng_result result = otrng_client_read_from_prefix(fp, &dec, &dec_len);

  if (otrng_failed(result)) {
    return result;
  }

  prekey_msg = otrng_xmalloc_z(sizeof(prekey_message_s));

  result = otrng_prekey_message_deserialize_with_metadata(prekey_msg, dec,
                                                          dec_len, NULL);
  otrng_secure_wipe(dec, dec_len);
  free(dec);
  if (otrng_failed(result)) {
    free(prekey_msg);
    return result;
  }

  client->our_prekeys = otrng_list_add(prekey_msg, client->our_prekeys);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_prekey_messages_read_from(otrng_client_s *client, FILE *prekeyf) {
  if (!prekeyf) {
    return OTRNG_ERROR;
  }

  if (!read_and_deserialize_prekey(client, prekeyf)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_prekey_profile_write_to(otrng_client_s *client, FILE *profilef) {
  uint8_t *buffer = NULL;
  size_t s = 0;
  char *encoded;
  char *storage_id;

  if (!profilef) {
    return OTRNG_ERROR;
  }

  if (!client->prekey_profile) {
    return OTRNG_ERROR;
  }

  if (!otrng_prekey_profile_serialize_with_metadata(&buffer, &s,
                                                    client->prekey_profile)) {
    return OTRNG_ERROR;
  }

  encoded = otrng_base64_encode(buffer, s);
  free(buffer);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    free(encoded);
    return OTRNG_ERROR;
  }

  if (fprintf(profilef, "%s\n%s\n", storage_id, encoded) < 0) {
    free(encoded);
    free(storage_id);
    return OTRNG_ERROR;
  }

  free(encoded);
  free(storage_id);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_expired_prekey_profile_write_to(
    otrng_client_s *client, FILE *profilef) {
  uint8_t *buffer = NULL;
  size_t s = 0;
  char *encoded;
  char *storage_id;

  if (!profilef) {
    return OTRNG_ERROR;
  }

  if (!client->exp_prekey_profile) {
    return OTRNG_ERROR;
  }

  if (!otrng_prekey_profile_serialize_with_metadata(
          &buffer, &s, client->exp_prekey_profile)) {
    return OTRNG_ERROR;
  }

  encoded = otrng_base64_encode(buffer, s);
  free(buffer);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    free(encoded);
    return OTRNG_ERROR;
  }

  if (fprintf(profilef, "%s\n%s\n", storage_id, encoded) < 0) {
    free(encoded);
    free(storage_id);
    return OTRNG_ERROR;
  }

  free(encoded);
  free(storage_id);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_prekey_profile_read_from(otrng_client_s *client, FILE *fp) {
  uint8_t *dec = NULL;
  size_t dec_len = 0;
  otrng_prekey_profile_s profile;
  otrng_result result = otrng_client_read_from_prefix(fp, &dec, &dec_len);

  if (otrng_failed(result)) {
    return result;
  }

  memset(&profile, 0, sizeof(otrng_prekey_profile_s));
  result = otrng_prekey_profile_deserialize_with_metadata(&profile, dec,
                                                          dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  otrng_prekey_profile_free(client->prekey_profile);
  client->prekey_profile = NULL;

  result = otrng_client_add_prekey_profile(client, &profile);
  otrng_prekey_profile_destroy(&profile);

  return result;
}

INTERNAL otrng_result otrng_client_expired_prekey_profile_read_from(
    otrng_client_s *client, FILE *fp) {
  uint8_t *dec = NULL;
  size_t dec_len = 0;
  otrng_prekey_profile_s exp_profile;
  otrng_result result = otrng_client_read_from_prefix(fp, &dec, &dec_len);

  if (otrng_failed(result)) {
    return result;
  }

  memset(&exp_profile, 0, sizeof(otrng_prekey_profile_s));
  result = otrng_prekey_profile_deserialize(&exp_profile, dec, dec_len, NULL);
  free(dec);

  if (otrng_failed(result)) {
    return result;
  }

  otrng_prekey_profile_free(client->exp_prekey_profile);
  client->exp_prekey_profile = NULL;

  result = otrng_client_add_exp_prekey_profile(client, &exp_profile);

  otrng_prekey_profile_destroy(&exp_profile);

  return result;
}
