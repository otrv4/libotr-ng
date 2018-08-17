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

#include "persistence.h"
#include "base64.h"
#include "deserialize.h"

/*
 * Provides sample FILE-based persistence mechanism.
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

INTERNAL int
otrng_client_state_private_key_v4_write_FILEp(const otrng_client_state_s *state,
                                              FILE *privf) {
  if (!privf) {
    return 1;
  }

  if (!state->keypair) {
    return 1;
  }

  char *key = otrng_client_state_get_storage_id(state);
  if (!key) {
    return 1;
  }

  int err = fputs(key, privf);
  free(key);

  if (EOF == err) {
    return 1;
  }

  if (EOF == fputs("\n", privf)) {
    return 1;
  }

  char *buff = NULL;
  size_t s = 0;
  if (!otrng_symmetric_key_serialize(&buff, &s, state->keypair->sym)) {
    return 1;
  }

  err = fwrite(buff, s, 1, privf);
  free(buff);

  if (err != 1) {
    return 1;
  }

  if (EOF == fputs("\n", privf)) {
    return 1;
  }

  return 0;
}

INTERNAL int
otrng_client_state_private_key_v4_read_FILEp(otrng_client_state_s *state,
                                             FILE *privf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;

  if (!privf) {
    return 1;
  }

  if (feof(privf)) {
    return 1;
  }

  // Free current keypair if any
  otrng_keypair_free(state->keypair);
  state->keypair = NULL;

  otrng_keypair_s *keypair = otrng_keypair_new();
  if (!keypair) {
    return 1;
  }

  // TODO: we need to remove getline. It is not c99.
  // OR ignore if this will be moved to the plugin.
  len = getline(&line, &cap, privf);
  if (len < 0) {
    free(line);
    return 1;
  }

  // line includes the /n
  if (!otrng_symmetric_key_deserialize(keypair, line, len - 1)) {
    free(line);
    otrng_keypair_free(keypair);
    return 1;
  }

  free(line);

  state->keypair = keypair;

  return 0;
}

INTERNAL int
otrng_client_state_instance_tag_write_FILEp(otrng_client_state_s *state,
                                            FILE *instagf) {
  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!otrng_client_state_get_account_and_protocol(&account_name,
                                                   &protocol_name, state)) {
    return 1;
  }

  gcry_error_t ret = otrl_instag_generate_FILEp(state->user_state, instagf,
                                                account_name, protocol_name);

  free(account_name);
  free(protocol_name);
  return ret;
}

INTERNAL int
otrng_client_state_instance_tag_read_FILEp(otrng_client_state_s *state,
                                           FILE *instag) {
  if (!state->user_state) {
    return 1;
  }

  return otrl_instag_read_FILEp(state->user_state, instag);
}

INTERNAL int
otrng_client_state_private_key_v3_write_FILEp(const otrng_client_state_s *state,
                                              FILE *privf) {

  // TODO: We could use a "get storage key" callback and use it as
  // account_name plus an arbitrary "libotrng-storage" protocol.
  char *account_name = NULL;
  char *protocol_name = NULL;
  if (!otrng_client_state_get_account_and_protocol(&account_name,
                                                   &protocol_name, state)) {
    return 1;
  }

  int err = otrl_privkey_generate_FILEp(state->user_state, privf, account_name,
                                        protocol_name);

  free(account_name);
  free(protocol_name);
  return err;
}

INTERNAL int
otrng_client_state_client_profile_read_FILEp(otrng_client_state_s *state,
                                             FILE *privf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;

  if (!privf) {
    return -1;
  }

  if (feof(privf)) {
    return 1;
  }

  otrng_client_profile_free(state->client_profile);

  // TODO: we need to remove getline. It is not c99.
  // OR ignore if this will be moved to the plugin.
  len = getline(&line, &cap, privf);
  if (len < 0) {
    free(line);
    return 1;
  }

  uint8_t *dec = malloc(((len + 3) / 4) * 3);
  if (!dec) {
    free(line);
    return 1;
  }

  size_t dec_len = otrl_base64_decode(dec, line, len);
  free(line);

  client_profile_s profile[1];
  otrng_err ret = otrng_client_profile_deserialize(profile, dec, dec_len, NULL);
  free(dec);

  int err = (ret == OTRNG_ERROR);

  if (!err) {
    err = otrng_client_state_add_client_profile(state, profile);
    otrng_client_profile_destroy(profile);
  }

  return err;
}

INTERNAL int
otrng_client_state_client_profile_write_FILEp(const otrng_client_state_s *state,
                                              FILE *privf) {
  if (!privf) {
    return 1;
  }

  if (!state->client_profile) {
    return 1;
  }

  uint8_t *buff = NULL;
  size_t s = 0;
  if (!otrng_client_profile_asprintf(&buff, &s, state->client_profile)) {
    return 1;
  }

  char *encoded = otrng_base64_encode(buff, s);
  free(buff);
  if (!encoded) {
    return 1;
  }

  char *key = otrng_client_state_get_storage_id(state);
  if (!key) {
    free(encoded);
    return 1;
  }

  if (0 > fprintf(privf, "%s\n%s\n", key, encoded)) {
    free(encoded);
    return 1;
  }

  free(encoded);

  return 0;
}

static otrng_err
serialize_and_store_prekey(const otrng_stored_prekeys_s *prekey,
                           const char *storage_id, FILE *privf) {
  if (0 > fprintf(privf, "%s\n", storage_id)) {
    return OTRNG_ERROR;
  }

  uint8_t ecdh_secret_k[ED448_SCALAR_BYTES] = {0};
  otrng_ec_scalar_encode(ecdh_secret_k, prekey->our_ecdh->priv);

  char *ecdh_symkey = otrng_base64_encode(ecdh_secret_k, ED448_SCALAR_BYTES);
  if (!ecdh_symkey) {
    return OTRNG_ERROR;
  }

  // TODO: securely erase ecdh_secret_k

  uint8_t dh_secret_k[DH3072_MOD_LEN_BYTES] = {0};
  size_t dh_secret_k_len = 0;
  if (!otrng_dh_mpi_serialize(dh_secret_k, DH3072_MOD_LEN_BYTES,
                              &dh_secret_k_len, prekey->our_dh->priv)) {
    free(ecdh_symkey);
    return OTRNG_ERROR;
  }

  char *dh_symkey = otrng_base64_encode(dh_secret_k, dh_secret_k_len);
  if (!dh_symkey) {
    free(ecdh_symkey);
    return OTRNG_ERROR;
  }

  // TODO: securely erase dh_secret_k

  int ret = fprintf(privf, "%x\n%x\n%s\n%s\n", prekey->id, prekey->sender_instance_tag,
                    ecdh_symkey, dh_symkey);
  free(ecdh_symkey);
  free(dh_symkey);

  if (0 > ret) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL int
otrng_client_state_prekeys_write_FILEp(const otrng_client_state_s *state,
                                       FILE *privf) {
  if (!privf) {
    return 1;
  }

  // list_element_s *our_prekeys; // otrng_stored_prekeys_s
  if (!state->our_prekeys) {
    return 1;
  }

  char *storage_id = otrng_client_state_get_storage_id(state);
  if (!storage_id) {
    return 1;
  }

  list_element_s *current = state->our_prekeys;
  while (current) {
    if (!serialize_and_store_prekey(current->data, storage_id, privf)) {
      free(storage_id);
      return 1;
    }

    current = current->next;
  }

  free(storage_id);
  return 0;
}
