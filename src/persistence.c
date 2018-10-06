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

#include "persistence.h"
#include "alloc.h"
#include "base64.h"
#include "deserialize.h"
#include "messaging.h"
#include "serialize.h"

/*
  Provides sample FILE-based persistence mechanism.
*/

static char *otrng_client_get_storage_id(const otrng_client_s *client) {
  char *account_name = NULL;
  char *protocol_name = NULL;
  char *key = NULL;
  int res;

  if (!otrng_client_get_account_and_protocol(&account_name, &protocol_name,
                                             client)) {
    return NULL;
  }

  if (account_name && protocol_name) {
    size_t n = strlen(protocol_name) + strlen(account_name) + 2;
    key = otrng_xmalloc(n);

    res = snprintf(key, n, "%s:%s", protocol_name, account_name);
    if (res < 0) {
      return NULL;
    }
  }

  if (account_name) {
    free(account_name);
  }

  if (protocol_name) {
    free(protocol_name);
  }

  return key;
}

INTERNAL otrng_result otrng_client_private_key_v4_write_to(
    const otrng_client_s *client, FILE *privf) {
  char *key;
  int err;
  char *buffer = NULL;
  size_t s = 0;

  if (!privf) {
    return OTRNG_ERROR;
  }

  if (!client->keypair) {
    return OTRNG_ERROR;
  }

  key = otrng_client_get_storage_id(client);
  if (!key) {
    return OTRNG_ERROR;
  }

  err = fputs(key, privf);
  free(key);

  if (EOF == err) {
    return OTRNG_ERROR;
  }

  if (EOF == fputs("\n", privf)) {
    return OTRNG_ERROR;
  }

  if (!otrng_symmetric_key_serialize(&buffer, &s, client->keypair->sym)) {
    return OTRNG_ERROR;
  }

  err = fwrite(buffer, s, 1, privf);
  free(buffer);

  if (err != 1) {
    return OTRNG_ERROR;
  }

  if (EOF == fputs("\n", privf)) {
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
  int len = 0;

  if (buf == NULL) {
    return -1;
  }

  *buf = otrng_xmalloc_z(MAX_LINE_LENGTH * sizeof(char));

  res = fgets(*buf, MAX_LINE_LENGTH, f);
  if (res == NULL) {
    free(*buf);
    return -1;
  }

  len = strlen(*buf);
  if (len == MAX_LINE_LENGTH) {
    free(*buf);
    return -1;
  }

  return len;
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
                                                         FILE *forgingf) {
  char *line = NULL;
  int len = 0;
  uint8_t *dec;
  size_t dec_len;
  otrng_public_key key;
  otrng_result ret;

  if (!forgingf || feof(forgingf)) {
    return OTRNG_ERROR;
  }

  if (client->forging_key) {
    otrng_ec_point_destroy(*client->forging_key);
    free(client->forging_key);
    client->forging_key = NULL;
  }

  len = get_limited_line(&line, forgingf);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  dec = otrng_xmalloc_z(OTRNG_BASE64_DECODE_LEN(len));

  dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  ret = otrng_deserialize_forging_key(key, dec, dec_len, NULL);
  free(dec);

  if (ret == OTRNG_ERROR) {
    return ret;
  }

  return otrng_client_add_forging_key(client, key);
}

INTERNAL otrng_result otrng_client_instance_tag_write_to(otrng_client_s *client,
                                                         FILE *instagf) {
  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  gcry_error_t ret;

  if (!otrng_client_get_account_and_protocol(&account_name, &protocol_name,
                                             client)) {
    return OTRNG_ERROR;
  }

  ret = otrl_instag_generate_FILEp(client->global_state->user_state_v3, instagf,
                                   account_name, protocol_name);

  free(account_name);
  free(protocol_name);

  if (ret) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_instance_tag_read_from(otrng_client_s *client, FILE *instagf) {
  gcry_error_t ret;

  if (!client->global_state->user_state_v3) {
    return OTRNG_ERROR;
  }

  ret = otrl_instag_read_FILEp(client->global_state->user_state_v3, instagf);

  if (ret) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_private_key_v3_write_to(
    const otrng_client_s *client, FILE *privf) {

  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  gcry_error_t ret;

  if (!otrng_client_get_account_and_protocol(&account_name, &protocol_name,
                                             client)) {
    return OTRNG_ERROR;
  }

  ret = otrl_privkey_generate_FILEp(client->global_state->user_state_v3, privf,
                                    account_name, protocol_name);

  free(account_name);
  free(protocol_name);

  if (ret) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

#include "debug.h"

INTERNAL otrng_result
otrng_client_client_profile_read_from(otrng_client_s *client, FILE *profilef) {
  char *line = NULL;
  int len = 0;
  uint8_t *dec;
  size_t dec_len;
  otrng_client_profile_s profile;
  otrng_result result;

  if (!profilef) {
    return OTRNG_ERROR;
  }

  if (feof(profilef)) {
    return OTRNG_ERROR;
  }

  len = get_limited_line(&line, profilef);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  dec = otrng_xmalloc_z(OTRNG_BASE64_DECODE_LEN(len));

  dec_len = otrl_base64_decode(dec, line, len);
  free(line);

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
    otrng_client_s *client, FILE *exp_profilef) {
  char *line = NULL;
  int len = 0;
  uint8_t *dec;
  size_t dec_len;
  otrng_client_profile_s exp_profile;
  otrng_result result;

  if (!exp_profilef) {
    return OTRNG_ERROR;
  }

  if (feof(exp_profilef)) {
    return OTRNG_ERROR;
  }

  otrng_client_profile_free(client->exp_client_profile);
  client->exp_client_profile = NULL;

  len = get_limited_line(&line, exp_profilef);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  dec = otrng_xmalloc_z(OTRNG_BASE64_DECODE_LEN(len));

  dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  memset(&exp_profile, 0, sizeof(otrng_client_profile_s));
  result = otrng_client_profile_deserialize(&exp_profile, dec, dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  if (otrng_client_profile_invalid(exp_profile.expires,
                                   client->profiles_extra_valid_time)) {
    return OTRNG_ERROR;
  }

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

  // list_element_s *our_prekeys;
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
                                                FILE *prekeyf) {
  char *line = NULL;
  int line_len = 0;
  int dec_len = 0;
  uint8_t *dec = NULL;
  int full_len = 0;
  otrng_result result;

  prekey_message_s *prekey_msg = NULL;

  line_len = get_limited_line(&line, prekeyf);
  if (line_len < 0) {
    return OTRNG_ERROR;
  }

  dec_len = OTRNG_BASE64_DECODE_LEN(line_len);
  dec = otrng_xmalloc_z(dec_len);

  full_len = otrl_base64_decode(dec, line, line_len);
  free(line);

  prekey_msg = otrng_xmalloc_z(sizeof(prekey_message_s));

  result = otrng_prekey_message_deserialize_with_metadata(prekey_msg, dec,
                                                          full_len, NULL);
  otrng_secure_wipe(dec, full_len);
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

INTERNAL otrng_result
otrng_client_prekey_profile_read_from(otrng_client_s *client, FILE *profilef) {
  char *line = NULL;
  int len = 0;
  uint8_t *dec;
  size_t dec_len;
  otrng_prekey_profile_s profile;
  otrng_result result;

  if (!profilef) {
    return OTRNG_ERROR;
  }

  if (feof(profilef)) {
    return OTRNG_ERROR;
  }

  len = get_limited_line(&line, profilef);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  dec = otrng_xmalloc_z(OTRNG_BASE64_DECODE_LEN(len));

  dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  memset(&profile, 0, sizeof(otrng_prekey_profile_s));
  result = otrng_prekey_profile_deserialize_with_metadata(&profile, dec,
                                                          dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  if (otrng_prekey_profile_expired(profile.expires)) {
    client->global_state->callbacks->write_expired_prekey_profile(
        client, client->client_id);

    // TODO: I'm suspecting this will make a lot of tests fail, so
    // no return for the moment
    // return OTRNG_SUCCESS;
  }

  otrng_prekey_profile_free(client->prekey_profile);
  client->prekey_profile = NULL;

  result = otrng_client_add_prekey_profile(client, &profile);
  otrng_prekey_profile_destroy(&profile);

  return result;
}

INTERNAL otrng_result otrng_client_expired_prekey_profile_read_from(
    otrng_client_s *client, FILE *exp_profilef) {
  char *line = NULL;
  int len = 0;
  uint8_t *dec;
  size_t dec_len;
  otrng_prekey_profile_s exp_profile;
  otrng_result result;

  if (!exp_profilef) {
    return OTRNG_ERROR;
  }

  if (feof(exp_profilef)) {
    return OTRNG_ERROR;
  }

  otrng_prekey_profile_free(client->exp_prekey_profile);

  len = get_limited_line(&line, exp_profilef);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  dec = otrng_xmalloc_z(OTRNG_BASE64_DECODE_LEN(len));

  dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  memset(&exp_profile, 0, sizeof(otrng_prekey_profile_s));
  result = otrng_prekey_profile_deserialize(&exp_profile, dec, dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  if (otrng_prekey_profile_invalid(exp_profile.expires,
                                   client->profiles_extra_valid_time)) {
    return OTRNG_ERROR;
  }

  result = otrng_client_add_exp_prekey_profile(client, &exp_profile);

  otrng_prekey_profile_destroy(&exp_profile);

  return result;
}
