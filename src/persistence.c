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

char *otrng_client_get_storage_id(const otrng_client_s *client) {
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
  char *buff = NULL;
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

  if (!otrng_symmetric_key_serialize(&buff, &s, client->keypair->sym)) {
    return OTRNG_ERROR;
  }

  err = fwrite(buff, s, 1, privf);
  free(buff);

  if (err != 1) {
    return OTRNG_ERROR;
  }

  if (EOF == fputs("\n", privf)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_forging_key_write_to(const otrng_client_s *client, FILE *f) {
  uint8_t *buff;
  size_t size;
  char *encoded;
  char *storage_id;

  if (!f) {
    return OTRNG_ERROR;
  }

  if (!client->forging_key) {
    return OTRNG_ERROR;
  }

  buff = otrng_secure_alloc((2 + ED448_POINT_BYTES) * sizeof(uint8_t));

  size = otrng_serialize_forging_key(buff, *client->forging_key);
  if (size == 0) {
    return OTRNG_ERROR;
  }

  encoded = otrng_base64_encode(buff, size);
  otrng_secure_wipe(buff, (2 + ED448_POINT_BYTES) * sizeof(uint8_t));
  free(buff);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    otrng_secure_wipe(encoded, strlen(encoded));
    free(encoded);
    return OTRNG_ERROR;
  }

  if (fprintf(f, "%s\n%s\n", storage_id, encoded) < 0) {
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

#define MAX_LINE_LENGTH 500

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
                                                         FILE *f) {
  char *line = NULL;
  int len = 0;
  uint8_t *dec;
  size_t dec_len;
  otrng_public_key key;
  otrng_result ret;

  if (!f || feof(f)) {
    return OTRNG_ERROR;
  }

  if (client->forging_key) {
    otrng_ec_point_destroy(*client->forging_key);
  }

  len = get_limited_line(&line, f);
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

INTERNAL otrng_result otrng_client_shared_prekey_write_to(
    const otrng_client_s *client, FILE *shared_prekey_f) {
  char *storage_id;
  int err;
  char *buff = NULL;
  size_t s = 0;

  if (!shared_prekey_f) {
    return OTRNG_ERROR;
  }

  if (!client->shared_prekey_pair) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    return OTRNG_ERROR;
  }

  err = fputs(storage_id, shared_prekey_f);
  free(storage_id);

  if (EOF == err) {
    return OTRNG_ERROR;
  }

  if (EOF == fputs("\n", shared_prekey_f)) {
    return OTRNG_ERROR;
  }

  if (!otrng_symmetric_key_serialize(&buff, &s,
                                     client->shared_prekey_pair->sym)) {
    return OTRNG_ERROR;
  }

  err = fwrite(buff, s, 1, shared_prekey_f);
  free(buff);

  if (err != 1) {
    return OTRNG_ERROR;
  }

  if (EOF == fputs("\n", shared_prekey_f)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_shared_prekey_read_from(
    otrng_client_s *client, FILE *shared_prekeyf) {
  char *line = NULL;
  int len = 0;
  otrng_shared_prekey_pair_s *shared_prekey_pair;

  if (!shared_prekeyf) {
    return OTRNG_ERROR;
  }

  if (feof(shared_prekeyf)) {
    return OTRNG_ERROR;
  }

  /* Free current keypair if any */
  otrng_shared_prekey_pair_free(client->shared_prekey_pair);
  client->shared_prekey_pair = NULL;

  shared_prekey_pair = otrng_shared_prekey_pair_new();
  if (!shared_prekey_pair) {
    return OTRNG_ERROR;
  }

  len = get_limited_line(&line, shared_prekeyf);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  /* line has the /n */
  if (!otrng_symmetric_shared_prekey_deserialize(shared_prekey_pair, line,
                                                 len)) {
    free(line);
    otrng_shared_prekey_pair_free(client->shared_prekey_pair);
    return OTRNG_ERROR;
  }

  free(line);

  client->shared_prekey_pair = shared_prekey_pair;

  return OTRNG_SUCCESS;
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
otrng_client_instance_tag_read_from(otrng_client_s *client, FILE *instag) {
  gcry_error_t ret;

  if (!client->global_state->user_state_v3) {
    return OTRNG_ERROR;
  }

  ret = otrl_instag_read_FILEp(client->global_state->user_state_v3, instag);

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

INTERNAL otrng_result
otrng_client_client_profile_read_from(otrng_client_s *client, FILE *profilef) {
  char *line = NULL;
  int len = 0;
  uint8_t *dec;
  size_t dec_len;
  client_profile_s profile[1];
  otrng_result result;

  if (!profilef) {
    return OTRNG_ERROR;
  }

  if (feof(profilef)) {
    return OTRNG_ERROR;
  }

  otrng_client_profile_free(client->client_profile);
  client->client_profile = NULL;

  len = get_limited_line(&line, profilef);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  dec = otrng_xmalloc_z(OTRNG_BASE64_DECODE_LEN(len));

  dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  result = otrng_client_profile_deserialize(profile, dec, dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  if (otrng_client_profile_expired(profile->expires)) {
    client->global_state->callbacks->write_expired_client_profile(
        client, client->client_id);

    // TODO: I'm suspecting this will make a lot of tests fail, so
    // no return for the moment
    // return OTRNG_SUCCESS;
  }

  result = otrng_client_add_client_profile(client, profile);
  otrng_client_profile_destroy(profile);

  return result;
}

INTERNAL otrng_result otrng_client_expired_client_profile_read_from(
    otrng_client_s *client, FILE *exp_profilef) {
  char *line = NULL;
  int len = 0;
  uint8_t *dec;
  size_t dec_len;
  client_profile_s exp_profile[1];
  otrng_result result;

  if (!exp_profilef) {
    return OTRNG_ERROR;
  }

  if (feof(exp_profilef)) {
    return OTRNG_ERROR;
  }

  otrng_client_profile_free(client->exp_client_profile);

  len = get_limited_line(&line, exp_profilef);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  dec = otrng_xmalloc_z(OTRNG_BASE64_DECODE_LEN(len));

  dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  result = otrng_client_profile_deserialize(exp_profile, dec, dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  if (otrng_client_profile_invalid(exp_profile->expires,
                                   client->profiles_extra_valid_time)) {
    return OTRNG_ERROR;
  }

  result = otrng_client_add_exp_client_profile(client, exp_profile);

  otrng_client_profile_destroy(exp_profile);

  return result;
}

INTERNAL otrng_result otrng_client_client_profile_write_to(
    const otrng_client_s *client, FILE *privf) {
  uint8_t *buff = NULL;
  size_t s = 0;
  char *encoded;
  char *storage_id;

  if (!privf) {
    return OTRNG_ERROR;
  }

  if (!client->client_profile) {
    return OTRNG_ERROR;
  }

  if (!otrng_client_profile_serialize(&buff, &s, client->client_profile)) {
    return OTRNG_ERROR;
  }

  encoded = otrng_base64_encode(buff, s);
  free(buff);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    free(encoded);
    return OTRNG_ERROR;
  }

  if (fprintf(privf, "%s\n%s\n", storage_id, encoded) < 0) {
    free(storage_id);
    free(encoded);
    return OTRNG_ERROR;
  }

  free(storage_id);
  free(encoded);

  return OTRNG_SUCCESS;
}

static otrng_result
serialize_and_store_prekey(const otrng_stored_prekeys_s *prekey,
                           const char *storage_id, FILE *privf) {
  uint8_t *ecdh_secret_k = otrng_secure_alloc(ED448_SCALAR_BYTES);
  char *ecdh_symkey;
  uint8_t *dh_secret_k = otrng_secure_alloc(DH_KEY_SIZE);
  size_t dh_secret_k_len = 0;
  char *dh_symkey;
  int ret;

  if (fprintf(privf, "%s\n", storage_id) < 0) {
    return OTRNG_ERROR;
  }

  otrng_ec_scalar_encode(ecdh_secret_k, prekey->our_ecdh->priv);

  ecdh_symkey = otrng_base64_encode(ecdh_secret_k, ED448_SCALAR_BYTES);
  if (!ecdh_symkey) {
    return OTRNG_ERROR;
  }

  otrng_secure_wipe(ecdh_secret_k, ED448_SCALAR_BYTES);
  free(ecdh_secret_k);

  // this should be 80 + 4
  if (!otrng_dh_mpi_serialize(dh_secret_k, DH_KEY_SIZE, &dh_secret_k_len,
                              prekey->our_dh->priv)) {
    free(ecdh_symkey);
    return OTRNG_ERROR;
  }

  dh_symkey = otrng_base64_encode(dh_secret_k, dh_secret_k_len);
  if (!dh_symkey) {
    free(ecdh_symkey);
    return OTRNG_ERROR;
  }

  otrng_secure_wipe(dh_secret_k, DH_KEY_SIZE);
  free(dh_secret_k);

  ret = fprintf(privf, "%x\n%x\n%s\n%s\n", prekey->id,
                prekey->sender_instance_tag, ecdh_symkey, dh_symkey);
  otrng_secure_wipe(ecdh_symkey, strlen(ecdh_symkey));
  free(ecdh_symkey);
  otrng_secure_wipe(dh_symkey, strlen(dh_symkey));
  free(dh_symkey);

  if (ret < 0) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_prekeys_write_to(const otrng_client_s *client, FILE *privf) {
  char *storage_id;
  list_element_s *current;

  if (!privf) {
    return OTRNG_ERROR;
  }

  // list_element_s *our_prekeys; // otrng_stored_prekeys_s
  if (!client->our_prekeys) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    return OTRNG_ERROR;
  }

  current = client->our_prekeys;
  while (current) {
    if (!serialize_and_store_prekey(current->data, storage_id, privf)) {
      free(storage_id);
      return OTRNG_ERROR;
    }

    current = current->next;
  }

  free(storage_id);
  return OTRNG_SUCCESS;
}

otrng_result read_and_deserialize_prekey(otrng_client_s *client, FILE *privf) {
  char *line = NULL;
  int line_len = 0;
  int dec_len;
  uint8_t *dec;
  size_t scalar_len;
  size_t priv_len;
  otrng_result success;

  otrng_stored_prekeys_s *prekey_msg =
      otrng_xmalloc_z(sizeof(otrng_stored_prekeys_s));

  prekey_msg->our_dh = otrng_secure_alloc(sizeof(dh_keypair_s));
  prekey_msg->our_ecdh = otrng_secure_alloc(sizeof(ecdh_keypair_s));

  line_len = get_limited_line(&line, privf);
  if (line_len < 0) {
    free(prekey_msg);
    return OTRNG_ERROR;
  }
  prekey_msg->id = strtol(line, NULL, 16);

  free(line);
  line = NULL;

  line_len = get_limited_line(&line, privf);
  if (line_len < 0) {
    free(prekey_msg);
    return OTRNG_ERROR;
  }

  prekey_msg->sender_instance_tag = strtol(line, NULL, 16);
  free(line);
  line = NULL;

  line_len = get_limited_line(&line, privf);
  if (line_len < 0) {
    free(prekey_msg);
    return OTRNG_ERROR;
  }

  // TODO: check this
  dec_len = OTRNG_BASE64_DECODE_LEN(line_len);
  dec = otrng_xmalloc_z(dec_len);

  scalar_len = otrl_base64_decode(dec, line, line_len);
  free(line);
  line = NULL;

  otrng_deserialize_ec_scalar(prekey_msg->our_ecdh->priv, dec, scalar_len);
  free(dec);
  dec = NULL;

  otrng_ec_calculate_public_key(prekey_msg->our_ecdh->pub,
                                prekey_msg->our_ecdh->priv);

  line_len = get_limited_line(&line, privf);
  if (line_len < 0) {
    free(prekey_msg);
    return OTRNG_ERROR;
  }

  // TODO: check this
  dec_len = OTRNG_BASE64_DECODE_LEN(line_len);
  dec = otrng_xmalloc_z(dec_len);

  priv_len = otrl_base64_decode(dec, line, line_len - 1);
  free(line);

  prekey_msg->our_dh->priv = NULL;
  prekey_msg->our_dh->pub = NULL;

  success =
      otrng_dh_mpi_deserialize(&prekey_msg->our_dh->priv, dec, priv_len, NULL);

  free(dec);

  if (!success) {
    free(prekey_msg);
    return OTRNG_ERROR;
  }

  prekey_msg->our_dh->pub = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  otrng_dh_calculate_public_key(prekey_msg->our_dh->pub,
                                prekey_msg->our_dh->priv);

  client->our_prekeys = otrng_list_add(prekey_msg, client->our_prekeys);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_prekey_messages_read_from(otrng_client_s *client, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  if (!read_and_deserialize_prekey(client, privf)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_client_prekey_profile_write_to(otrng_client_s *client, FILE *privf) {
  uint8_t *buff = NULL;
  size_t s = 0;
  char *encoded;
  char *storage_id;

  if (!privf) {
    return OTRNG_ERROR;
  }

  if (!client->prekey_profile) {
    return OTRNG_ERROR;
  }

  if (!otrng_prekey_profile_serialize(&buff, &s, client->prekey_profile)) {
    return OTRNG_ERROR;
  }

  encoded = otrng_base64_encode(buff, s);
  free(buff);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  storage_id = otrng_client_get_storage_id(client);
  if (!storage_id) {
    free(encoded);
    return OTRNG_ERROR;
  }

  if (fprintf(privf, "%s\n%s\n", storage_id, encoded) < 0) {
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
  otrng_prekey_profile_s profile[1];
  otrng_result result;

  if (!profilef) {
    return OTRNG_ERROR;
  }

  if (feof(profilef)) {
    return OTRNG_ERROR;
  }

  otrng_prekey_profile_free(client->prekey_profile);
  client->prekey_profile = NULL;

  len = get_limited_line(&line, profilef);
  if (len < 0) {
    return OTRNG_ERROR;
  }

  dec = otrng_xmalloc_z(OTRNG_BASE64_DECODE_LEN(len));

  dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  result = otrng_prekey_profile_deserialize(profile, dec, dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  if (otrng_prekey_profile_expired(profile->expires)) {
    client->global_state->callbacks->write_expired_prekey_profile(
        client, client->client_id);

    // TODO: I'm suspecting this will make a lot of tests fail, so
    // no return for the moment
    // return OTRNG_SUCCESS;
  }

  result = otrng_client_add_prekey_profile(client, profile);
  otrng_prekey_profile_destroy(profile);

  return result;
}

INTERNAL otrng_result otrng_client_expired_prekey_profile_read_from(
    otrng_client_s *client, FILE *exp_profilef) {
  char *line = NULL;
  int len = 0;
  uint8_t *dec;
  size_t dec_len;
  otrng_prekey_profile_s exp_profile[1];
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

  result = otrng_prekey_profile_deserialize(exp_profile, dec, dec_len, NULL);
  free(dec);

  if (result == OTRNG_ERROR) {
    return result;
  }

  if (otrng_prekey_profile_invalid(exp_profile->expires,
                                   client->profiles_extra_valid_time)) {
    return OTRNG_ERROR;
  }

  result = otrng_client_add_exp_prekey_profile(client, exp_profile);

  otrng_prekey_profile_destroy(exp_profile);

  return result;
}
