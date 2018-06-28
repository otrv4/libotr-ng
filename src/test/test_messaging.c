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

#include "../messaging.h"

// These must be fixed pointers managed by the messaging app
static const char *alice_account = "alice@xmpp";
static const char *bob_account = "bob@xmpp";
static const char *charlie_account = "charlie@xmpp";

static const void *read_client_id_for_privf(FILE *privf) {
  // Uses the file pointer to read and locate the appropriate client_id in your
  // mesaging app
  fseek(privf, strlen(charlie_account) + 1, SEEK_CUR);
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

  // Generate file
  FILE *keys = tmpfile();
  fputs("charlie@xmpp:"
        "RQ8MfhJljp+d1KUybu73Hj+Bve8lYTxE1wL5WDLyy+"
        "pLryYcPUYGIODpKqfEtrRH2d6fgbpBGmhA\n",
        keys);
  rewind(keys);

  int err = otrng_user_state_private_key_v4_read_FILEp(
      state, keys, read_client_id_for_privf);
  g_assert_cmpint(err, ==, 0);
  fclose(keys);

  // TODO: @test Assert it is equal to deserializing the symkey
  // RQ8MfhJljp+d1KUybu73Hj+Bve8lYTxE1wL5WDLyy+pLryYcPUYGIODpKqfEtrRH2d6fgbpBGmhA"
  otrng_assert(otrng_user_state_get_private_key_v4(state, charlie_account));

  otrng_user_state_free(state);
}

/*
 * Create callbacks for testing the callbacks API
 */

/* TODO: @client @refactoring The below test is commented out because it didn't
 * test anything
 * - plus, the use of a global to manage things imply that these
 * APIs are not well thouht out:
 *   If you need access to the user state in order to reasonable create
 *   a private key, it seems it should be an argument - neh?
 */

/* static otrng_user_state_s *test_state = NULL; */

/* static void create_privkey_cb(void *client_id) { */
/*   const uint8_t sym[ED448_PRIVATE_BYTES] = {1}; */
/*   otrng_user_state_add_private_key_v4(test_state, client_id, sym); */
/* } */

/* static otrng_client_callbacks_s test_calbacks = { */
/*     create_privkey_cb, NULL, NULL, NULL, NULL, NULL, NULL, NULL, */
/* }; */

/* void test_api_messaging(void) { */

/*   test_state = otrng_user_state_new(&test_calbacks); */

/*   // This will invoke create_privkey_cb() to create the private keys */
/*   otrng_assert(otrng_user_state_get_private_key_v4(test_state,
 * alice_account)); */
/*   otrng_assert(otrng_user_state_get_private_key_v4(test_state, bob_account));
 */

/*   otrng_user_state_free(test_state); */
/* } */

void test_instance_tag_api(void) {
  const char *icq_alice_account = "alice_icq";
  const char *icq_protocol = "ICQ";
  unsigned int icq_instag_value = 0x9abcdef0;

  otrng_client_state_s *alice = otrng_client_state_new(alice_account);
  alice->user_state = otrl_userstate_create();
  alice->account_name = otrng_strdup(icq_alice_account);
  alice->protocol_name = otrng_strdup(icq_protocol);

  FILE *instagFILEp = tmpfile();

  fprintf(instagFILEp, "%s\t%s\t%08x\n", icq_alice_account, icq_protocol,
          icq_instag_value);
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
