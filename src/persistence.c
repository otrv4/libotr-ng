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

#include <libotr/b64.h>

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
    return -1;
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

  otrng_client_profile_destroy(state->client_profile);

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

  otrng_err ret = otrng_client_profile_deserialize(state->client_profile, dec,
                                                   dec_len, NULL);
  free(dec);

  return ret == OTRNG_ERROR;
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

  size_t written = 0;
  char *encoded = malloc((s + 2) / 3 * 4);
  if (!encoded) {
    free(buff);
    return 1;
  }

  written = otrl_base64_encode(encoded, buff, s);
  free(buff);

  char *key = otrng_client_state_get_storage_id(state);
  if (!key) {
    free(encoded);
    return 1;
  }

  int err = fputs(key, privf);
  free(key);

  if (EOF == err) {
    free(encoded);
    return 1;
  }

  if (EOF == fputs("\n", privf)) {
    free(encoded);
    return 1;
  }

  err = fwrite(encoded, written, 1, privf);
  free(encoded);

  if (err != 1) {
    return 1;
  }

  if (EOF == fputs("\n", privf)) {
    return 1;
  }

  return 0;
}
