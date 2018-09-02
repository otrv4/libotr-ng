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

#include "../base64.h"
#include "../messaging.h"
#include "../persistence.h"

static const char *alice_account = "alice@xmpp";
static const char *bob_account = "bob@xmpp";
static const char *charlie_account = "charlie@xmpp";

static const void *read_client_id_for_privf(FILE *privf) {
  char *line = NULL;
  size_t n = 0;
  ssize_t len = getline(&line, &n, privf);
  free(line);

  if (len != strlen(charlie_account) + 1) {
    return NULL;
  }

  /* The account name acts as client_id (PidginAccount* for pidgin) */
  return charlie_account;
}

void test_user_state_key_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};

  otrng_user_state_s *state = otrng_user_state_new(NULL);
  otrng_user_state_add_private_key_v4(state, alice_account, alice_sym);
  otrng_user_state_add_private_key_v4(state, bob_account, bob_sym);

  otrng_assert(otrng_user_state_get_private_key_v4(state, alice_account));
  otrng_assert(otrng_user_state_get_private_key_v4(state, bob_account));
  otrng_assert(!otrng_user_state_get_private_key_v4(state, charlie_account));

  /* Generate file */
  FILE *keys = tmpfile();
  fputs("charlie@xmpp\n"
        "RQ8MfhJljp+d1KUybu73Hj+Bve8lYTxE1wL5WDLyy+"
        "pLryYcPUYGIODpKqfEtrRH2d6fgbpBGmhA\n",
        keys);
  rewind(keys);

  otrng_result err = otrng_user_state_private_key_v4_read_FILEp(
      state, keys, read_client_id_for_privf);
  otrng_assert_is_success(err);
  fclose(keys);

  otrng_keypair_s *keypair =
      otrng_user_state_get_private_key_v4(state, charlie_account);

  char *buffer = NULL;
  size_t s = 0;
  otrng_symmetric_key_serialize(&buffer, &s, keypair->sym);

  const char *expected = "RQ8MfhJljp+d1KUybu73Hj+Bve8lYTxE1wL5WDLyy+"
                         "pLryYcPUYGIODpKqfEtrRH2d6fgbpBGmhA";
  otrng_assert_cmpmem(expected, buffer, s);

  free(buffer);
  otrng_user_state_free(state);
}

void test_user_state_client_profile_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};

  otrng_user_state_s *state = otrng_user_state_new(NULL);
  otrng_user_state_add_private_key_v4(state, alice_account, alice_sym);
  otrng_user_state_add_private_key_v4(state, bob_account, bob_sym);

  otrng_assert(otrng_user_state_get_private_key_v4(state, alice_account));
  otrng_assert(otrng_user_state_get_private_key_v4(state, bob_account));
  otrng_assert(!otrng_user_state_get_private_key_v4(state, charlie_account));

  /* Generate file */
  FILE *client_profile = tmpfile();
  fputs("charlie@xmpp\n"
        "AAAABAAB26FP8QACABA7tTzNTkCSyKHJ/"
        "OSxJvdNXa6yLZG2KRVbqpF0mBbm8SMsHVcQ3xaeJIqzAsFFB5e1ZNqJ750yhoAABAAAAAM"
        "zNAAABQAAAABbnbX8F1Jf/8JRR20QtKJ+8RJw2lfuRMtaPKlaGPkoK/76VSPXS/"
        "rwyWpXmXcE6CMaWLBs6z4ccGJOz+"
        "EARUYZBZ2Kvob3InDvlXnPGu91U7OjGadUVPJN2QdtANwF6pV+"
        "qNRpGTnUDwHq9wgblNT0WAzlHSwA\n",
        client_profile);
  rewind(client_profile);

  otrng_result result = otrng_user_state_client_profile_read_FILEp(
      state, client_profile, read_client_id_for_privf);
  otrng_assert_is_success(result);
  fclose(client_profile);

  otrng_client_state_s *client_state = get_client_state(state, charlie_account);

  otrng_assert(client_state->client_profile);

  uint8_t *buffer = NULL;
  size_t s = 0;
  otrng_client_profile_asprintf(&buffer, &s, client_state->client_profile);
  char *encoded = otrng_base64_encode(buffer, s);
  const char *expected =
      "AAAABAAB26FP8QACABA7tTzNTkCSyKHJ/"
      "OSxJvdNXa6yLZG2KRVbqpF0mBbm8SMsHVcQ3xaeJIqzAsFFB5e1ZNqJ750yhoAABAAAAAMzN"
      "AAABQAAAABbnbX8F1Jf/8JRR20QtKJ+8RJw2lfuRMtaPKlaGPkoK/76VSPXS/"
      "rwyWpXmXcE6CMaWLBs6z4ccGJOz+"
      "EARUYZBZ2Kvob3InDvlXnPGu91U7OjGadUVPJN2QdtANwF6pV+"
      "qNRpGTnUDwHq9wgblNT0WAzlHSwA";

  otrng_assert_cmpmem(expected, encoded, s);

  free(buffer);
  otrng_user_state_free(state);
}

void test_user_state_prekey_message_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};

  otrng_user_state_s *state = otrng_user_state_new(NULL);
  otrng_user_state_add_private_key_v4(state, alice_account, alice_sym);
  otrng_user_state_add_private_key_v4(state, bob_account, bob_sym);

  otrng_assert(otrng_user_state_get_private_key_v4(state, alice_account));
  otrng_assert(otrng_user_state_get_private_key_v4(state, bob_account));
  otrng_assert(!otrng_user_state_get_private_key_v4(state, charlie_account));

  /* Generate file */
  FILE *prekey = tmpfile();
  fputs("charlie@xmpp\n"
        "f139c0c4\n"
        "dba14ff1\n"
        "/j+dnA2sffO2yDwB3rOVPEzeCDsFfTss8NCwHsQaN4Hjsn/"
        "NpstdI0vbcFPUApJsK70NzpaTZjU=\n"
        "ZwK68U7e8nicaW1EqcZUfZnoLPzkyQqJcvtv1c6AS5M6uqFdH3PIjwup81/"
        "dpOTgSesSPWaW/J79884Dnn3FDudlXVq9kH4K+xABjgekNGk=\n",
        prekey);
  rewind(prekey);

  otrng_result res = otrng_user_state_prekeys_read_FILEp(
      state, prekey, read_client_id_for_privf);
  otrng_assert_is_success(res);

  fclose(prekey);

  otrng_client_state_s *client_state = get_client_state(state, charlie_account);

  otrng_assert(client_state->our_prekeys);

  uint32_t message_id = 4047093956;
  const otrng_stored_prekeys_s *stored_prekey = NULL;
  stored_prekey = get_my_prekeys_by_id(message_id, client_state);

  uint8_t ecdh_secret_k[ED448_SCALAR_BYTES] = {0};
  otrng_ec_scalar_encode(ecdh_secret_k, stored_prekey->our_ecdh->priv);

  char *ecdh_symkey = otrng_base64_encode(ecdh_secret_k, ED448_SCALAR_BYTES);

  const char *expected_ecdh = "/j+dnA2sffO2yDwB3rOVPEzeCDsFfTss8NCwHsQaN4Hjsn/"
                              "NpstdI0vbcFPUApJsK70NzpaTZjU=";
  otrng_assert_cmpmem(expected_ecdh, ecdh_symkey, 76);

  free(ecdh_symkey);

  uint8_t dh_secret_k[DH_KEY_SIZE] = {0};
  size_t dh_secret_k_len = 0;
  otrng_dh_mpi_serialize(dh_secret_k, DH_KEY_SIZE, &dh_secret_k_len,
                         stored_prekey->our_dh->priv);

  char *dh_symkey = otrng_base64_encode(dh_secret_k, dh_secret_k_len);

  const char *expected_dh =
      "ZwK68U7e8nicaW1EqcZUfZnoLPzkyQqJcvtv1c6AS5M6uqFdH3PIjwup81/"
      "dpOTgSesSPWaW/J79884Dnn3FDudlXVq9kH4K+xABjgekNGk=";
  otrng_assert_cmpmem(expected_dh, dh_symkey, 108);

  free(dh_symkey);

  otrng_user_state_free(state);
}

void test_instance_tag_api(void) {
  const char *alice_protocol = "otr";
  unsigned int instance_tag = 0x9abcdef0;

  otrng_client_state_s *alice = otrng_client_state_new(alice_account);
  alice->callbacks = test_callbacks;
  alice->user_state = otrl_userstate_create();

  FILE *instagFILEp = tmpfile();

  fprintf(instagFILEp, "%s\t%s\t%08x\n", alice_account, alice_protocol,
          instance_tag);
  rewind(instagFILEp);
  otrng_client_state_instance_tag_read_FILEp(alice, instagFILEp);
  fclose(instagFILEp);

  unsigned int alice_instag = otrng_client_state_get_instance_tag(alice);
  otrng_assert(alice_instag);

  char sone[9];
  snprintf(sone, sizeof(sone), "%08x", alice_instag);

  g_assert_cmpstr(sone, ==, "9abcdef0");

  otrl_userstate_free(alice->user_state);
  otrng_client_state_free(alice);
}
