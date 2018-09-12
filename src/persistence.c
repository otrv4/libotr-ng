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
#include "base64.h"
#include "deserialize.h"
#include "messaging.h"

/*
  Provides sample FILE-based persistence mechanism.
*/

char *otrng_client_state_get_storage_id(const otrng_client_state_s *state) {
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!otrng_client_state_get_account_and_protocol(&account_name,
                                                   &protocol_name, state)) {
    return NULL;
  }

  char *key = NULL;
  if (account_name && protocol_name) {
    size_t n = strlen(protocol_name) + strlen(account_name) + 2;
    key = malloc(n);
    snprintf(key, n, "%s:%s", protocol_name, account_name);
  }

  free(account_name);
  free(protocol_name);
  return key;
}

INTERNAL otrng_result otrng_client_state_private_key_v4_write_FILEp(
    const otrng_client_state_s *state, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  if (!state->keypair) {
    return OTRNG_ERROR;
  }

  char *key = otrng_client_state_get_storage_id(state);
  if (!key) {
    return OTRNG_ERROR;
  }

  int err = fputs(key, privf);
  free(key);

  if (EOF == err) {
    return OTRNG_ERROR;
  }

  if (EOF == fputs("\n", privf)) {
    return OTRNG_ERROR;
  }

  char *buff = NULL;
  size_t s = 0;
  if (!otrng_symmetric_key_serialize(&buff, &s, state->keypair->sym)) {
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

INTERNAL otrng_result otrng_client_state_private_key_v4_read_FILEp(
    otrng_client_state_s *state, FILE *privf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;

  if (!privf) {
    return OTRNG_ERROR;
  }

  if (feof(privf)) {
    return OTRNG_ERROR;
  }

  // Free current keypair if any
  otrng_keypair_free(state->keypair);
  state->keypair = NULL;

  otrng_keypair_s *keypair = otrng_keypair_new();
  if (!keypair) {
    return OTRNG_ERROR;
  }

  // TODO: we need to remove getline. It is not c99.
  // OR ignore if this will be moved to the plugin.
  len = getline(&line, &cap, privf);
  if (len < 0) {
    free(line);
    return OTRNG_ERROR;
  }

  // line includes the /n
  if (!otrng_symmetric_key_deserialize(keypair, line, len - 1)) {
    free(line);
    otrng_keypair_free(keypair);
    return OTRNG_ERROR;
  }

  free(line);

  state->keypair = keypair;

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_shared_prekey_write_FILEp(
    const otrng_client_state_s *state, FILE *shared_prekey_f) {
  if (!shared_prekey_f) {
    return OTRNG_ERROR;
  }

  if (!state->shared_prekey_pair) {
    return OTRNG_ERROR;
  }

  char *storage_id = otrng_client_state_get_storage_id(state);
  if (!storage_id) {
    return OTRNG_ERROR;
  }

  int err = fputs(storage_id, shared_prekey_f);
  free(storage_id);

  if (EOF == err) {
    return OTRNG_ERROR;
  }

  if (EOF == fputs("\n", shared_prekey_f)) {
    return OTRNG_ERROR;
  }

  char *buff = NULL;
  size_t s = 0;
  if (!otrng_symmetric_key_serialize(&buff, &s,
                                     state->shared_prekey_pair->sym)) {
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

INTERNAL otrng_result otrng_client_state_shared_prekey_read_FILEp(
    otrng_client_state_s *state, FILE *shared_prekeyf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;

  if (!shared_prekeyf) {
    return OTRNG_ERROR;
  }

  if (feof(shared_prekeyf)) {
    return OTRNG_ERROR;
  }

  /* Free current keypair if any */
  otrng_shared_prekey_pair_free(state->shared_prekey_pair);
  state->shared_prekey_pair = NULL;

  otrng_shared_prekey_pair_s *shared_prekey_pair =
      otrng_shared_prekey_pair_new();
  if (!shared_prekey_pair) {
    return OTRNG_ERROR;
  }

  // TODO: we need to remove getline. It is not c99.
  // OR ignore if this will be moved to the plugin.
  len = getline(&line, &cap, shared_prekeyf);
  if (len < 0) {
    free(line);
    return OTRNG_ERROR;
  }

  /* line has the /n */
  if (!otrng_symmetric_shared_prekey_deserialize(shared_prekey_pair, line,
                                                 len - 1)) {
    free(line);
    otrng_shared_prekey_pair_free(state->shared_prekey_pair);
    return OTRNG_ERROR;
  }

  free(line);

  state->shared_prekey_pair = shared_prekey_pair;

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_instance_tag_write_FILEp(
    otrng_client_state_s *state, FILE *instagf) {
  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!otrng_client_state_get_account_and_protocol(&account_name,
                                                   &protocol_name, state)) {
    return OTRNG_ERROR;
  }

  gcry_error_t ret = otrl_instag_generate_FILEp(
      state->global_state->user_state_v3, instagf, account_name, protocol_name);

  free(account_name);
  free(protocol_name);

  if (ret) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_instance_tag_read_FILEp(
    otrng_client_state_s *state, FILE *instag) {
  if (!state->global_state->user_state_v3) {
    return OTRNG_ERROR;
  }

  gcry_error_t ret =
      otrl_instag_read_FILEp(state->global_state->user_state_v3, instag);

  if (ret) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_private_key_v3_write_FILEp(
    const otrng_client_state_s *state, FILE *privf) {

  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!otrng_client_state_get_account_and_protocol(&account_name,
                                                   &protocol_name, state)) {
    return OTRNG_ERROR;
  }

  gcry_error_t ret = otrl_privkey_generate_FILEp(
      state->global_state->user_state_v3, privf, account_name, protocol_name);

  free(account_name);
  free(protocol_name);

  if (ret) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_client_profile_read_FILEp(
    otrng_client_state_s *state, FILE *privf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;

  if (!privf) {
    return OTRNG_ERROR;
  }

  if (feof(privf)) {
    return OTRNG_ERROR;
  }

  otrng_client_profile_free(state->client_profile);

  // TODO: we need to remove getline. It is not c99.
  // OR ignore if this will be moved to the plugin.
  len = getline(&line, &cap, privf);
  if (len < 0) {
    free(line);
    return OTRNG_ERROR;
  }

  uint8_t *dec = malloc(OTRNG_BASE64_DECODE_LEN(len));
  if (!dec) {
    free(line);
    return OTRNG_ERROR;
  }

  size_t dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  client_profile_s profile[1];
  otrng_result ret =
      otrng_client_profile_deserialize(profile, dec, dec_len, NULL);
  free(dec);

  if (ret == OTRNG_ERROR) {
    return ret;
  }

  otrng_result result = otrng_client_state_add_client_profile(state, profile);
  otrng_client_profile_destroy(profile);

  return result;
}

INTERNAL otrng_result otrng_client_state_client_profile_write_FILEp(
    const otrng_client_state_s *state, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  if (!state->client_profile) {
    return OTRNG_ERROR;
  }

  uint8_t *buff = NULL;
  size_t s = 0;
  if (!otrng_client_profile_asprintf(&buff, &s, state->client_profile)) {
    return OTRNG_ERROR;
  }

  char *encoded = otrng_base64_encode(buff, s);
  free(buff);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  char *storage_id = otrng_client_state_get_storage_id(state);
  if (!storage_id) {
    free(encoded);
    return OTRNG_ERROR;
  }

  if (0 > fprintf(privf, "%s\n%s\n", storage_id, encoded)) {
    free(encoded);
    return OTRNG_ERROR;
  }

  free(encoded);

  return OTRNG_SUCCESS;
}

static otrng_result
serialize_and_store_prekey(const otrng_stored_prekeys_s *prekey,
                           const char *storage_id, FILE *privf) {
  if (fprintf(privf, "%s\n", storage_id) < 0) {
    return OTRNG_ERROR;
  }

  uint8_t ecdh_secret_k[ED448_SCALAR_BYTES] = {0};
  otrng_ec_scalar_encode(ecdh_secret_k, prekey->our_ecdh->priv);

  char *ecdh_symkey = otrng_base64_encode(ecdh_secret_k, ED448_SCALAR_BYTES);
  if (!ecdh_symkey) {
    return OTRNG_ERROR;
  }

  // TODO: securely erase ecdh_secret_k

  uint8_t dh_secret_k[DH_KEY_SIZE] = {0};
  size_t dh_secret_k_len = 0;
  // this should be 80 + 4
  if (!otrng_dh_mpi_serialize(dh_secret_k, DH_KEY_SIZE, &dh_secret_k_len,
                              prekey->our_dh->priv)) {
    free(ecdh_symkey);
    return OTRNG_ERROR;
  }

  char *dh_symkey = otrng_base64_encode(dh_secret_k, dh_secret_k_len);
  if (!dh_symkey) {
    free(ecdh_symkey);
    return OTRNG_ERROR;
  }

  // TODO: securely erase dh_secret_k

  int ret = fprintf(privf, "%x\n%x\n%s\n%s\n", prekey->id,
                    prekey->sender_instance_tag, ecdh_symkey, dh_symkey);
  free(ecdh_symkey);
  free(dh_symkey);

  if (ret < 0) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_prekeys_write_FILEp(
    const otrng_client_state_s *state, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  // list_element_s *our_prekeys; // otrng_stored_prekeys_s
  if (!state->our_prekeys) {
    return OTRNG_ERROR;
  }

  char *storage_id = otrng_client_state_get_storage_id(state);
  if (!storage_id) {
    return OTRNG_ERROR;
  }

  list_element_s *current = state->our_prekeys;
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

otrng_result read_and_deserialize_prekey(otrng_client_state_s *state,
                                         FILE *privf) {
  char *line = NULL;
  int line_len = 0;
  size_t cap;

  otrng_stored_prekeys_s *prekey_msg = malloc(sizeof(otrng_stored_prekeys_s));
  if (!prekey_msg) {
    return OTRNG_ERROR;
  }

  // TODO: we need to remove getline. It is not c99.
  // OR ignore if this will be moved to the plugin.
  line_len = getline(&line, &cap, privf);
  if (line_len < 0) {
    free(line);
    return OTRNG_ERROR;
  }
  prekey_msg->id = strtol(line, NULL, 16);

  free(line);
  line = NULL;

  line_len = getline(&line, &cap, privf);
  if (line_len < 0) {
    free(line);
    return OTRNG_ERROR;
  }
  prekey_msg->sender_instance_tag = strtol(line, NULL, 16);
  free(line);
  line = NULL;

  line_len = getline(&line, &cap, privf);
  if (line_len < 0) {
    free(line);
    return OTRNG_ERROR;
  }

  // TODO: check this
  int dec_len = OTRNG_BASE64_DECODE_LEN(line_len - 1);
  uint8_t *dec = malloc(dec_len);
  if (!dec) {
    free(line);
    return OTRNG_ERROR;
  }

  size_t scalar_len = otrl_base64_decode(dec, line, line_len);
  free(line);
  line = NULL;

  otrng_deserialize_ec_scalar(prekey_msg->our_ecdh->priv, dec, scalar_len);
  free(dec);
  dec = NULL;
  dec_len = 0;

  otrng_ec_calculate_public_key(prekey_msg->our_ecdh->pub,
                                prekey_msg->our_ecdh->priv);

  line_len = getline(&line, &cap, privf);
  if (line_len < 0) {
    free(line);
    return OTRNG_ERROR;
  }

  // TODO: check this
  dec_len = OTRNG_BASE64_DECODE_LEN(line_len - 1);
  dec = malloc(dec_len);
  if (!dec) {
    free(line);
    return OTRNG_ERROR;
  }

  size_t priv_len = otrl_base64_decode(dec, line, line_len - 1);
  free(line);

  prekey_msg->our_dh->priv = NULL;
  prekey_msg->our_dh->pub = NULL;

  otrng_result success =
      otrng_dh_mpi_deserialize(&prekey_msg->our_dh->priv, dec, priv_len, NULL);

  free(dec);

  if (!success) {
    return OTRNG_ERROR;
  }

  prekey_msg->our_dh->pub = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  otrng_dh_calculate_public_key(prekey_msg->our_dh->pub,
                                prekey_msg->our_dh->priv);

  state->our_prekeys = otrng_list_add(prekey_msg, state->our_prekeys);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_prekey_messages_read_FILEp(
    otrng_client_state_s *state, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  if (!read_and_deserialize_prekey(state, privf)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_prekey_profile_write_FILEp(
    otrng_client_state_s *state, FILE *privf) {
  if (!privf) {
    return OTRNG_ERROR;
  }

  if (!state->prekey_profile) {
    return OTRNG_ERROR;
  }

  uint8_t *buff = NULL;
  size_t s = 0;
  if (!otrng_prekey_profile_asprint(&buff, &s, state->prekey_profile)) {
    return OTRNG_ERROR;
  }

  char *encoded = otrng_base64_encode(buff, s);
  free(buff);
  if (!encoded) {
    return OTRNG_ERROR;
  }

  char *storage_id = otrng_client_state_get_storage_id(state);
  if (!storage_id) {
    free(encoded);
    return OTRNG_ERROR;
  }

  if (0 > fprintf(privf, "%s\n%s\n", storage_id, encoded)) {
    free(encoded);
    return OTRNG_ERROR;
  }

  free(encoded);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_client_state_prekey_profile_read_FILEp(
    otrng_client_state_s *state, FILE *privf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;

  if (!privf) {
    return OTRNG_ERROR;
  }

  if (feof(privf)) {
    return OTRNG_ERROR;
  }

  otrng_prekey_profile_free(state->prekey_profile);

  len = getline(&line, &cap, privf);
  if (len < 0) {
    free(line);
    return OTRNG_ERROR;
  }

  uint8_t *dec = malloc(OTRNG_BASE64_DECODE_LEN(len));
  if (!dec) {
    free(line);
    return OTRNG_ERROR;
  }

  size_t dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  otrng_prekey_profile_s profile[1];
  otrng_result ret =
      otrng_prekey_profile_deserialize(profile, dec, dec_len, NULL);
  free(dec);

  if (ret == OTRNG_ERROR) {
    return ret;
  }

  return otrng_client_state_add_prekey_profile(state, profile);
}
