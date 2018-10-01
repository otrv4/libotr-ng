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

#include <glib.h>

#include "test_helpers.h"

#include "test_fixtures.h"

#include "base64.h"
#include "messaging.h"
#include "persistence.h"

static const char *alice_account = "alice@xmpp";
static const char *bob_account = "bob@xmpp";
static const char *charlie_account = "charlie@xmpp";

static otrng_client_id_s read_client_id_for_privf(FILE *privf) {
  char *line = otrng_xmalloc_z(50 * sizeof(char));
  size_t len = 0;
  char *line2 = fgets(line, 50, privf);
  if (line2 != NULL) {
    len = strlen(line2);
  }
  free(line);

  otrng_client_id_s result = {
      .protocol = NULL,
      .account = NULL,
  };

  if (len != strlen(charlie_account) + 1) {
    return result;
  }

  /* The account name acts as client_id (PidginAccount* for pidgin) */
  result.protocol = "otr";
  result.account = charlie_account;
  return result;
}

static void test_global_state_key_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};

  otrng_global_state_s *state = otrng_global_state_new(NULL);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", alice_account), alice_sym);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", bob_account), bob_sym);

  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", alice_account)));
  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", bob_account)));
  otrng_assert(!otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", charlie_account)));

  /* Generate file */
  FILE *keys = tmpfile();

  fputs("charlie@xmpp\n"
        "RQ8MfhJljp+d1KUybu73Hj+Bve8lYTxE1wL5WDLyy+"
        "pLryYcPUYGIODpKqfEtrRH2d6fgbpBGmhA\n",
        keys);
  rewind(keys);

  otrng_result result = otrng_global_state_private_key_v4_read_from(
      state, keys, read_client_id_for_privf);
  otrng_assert_is_success(result);
  fclose(keys);

  otrng_keypair_s *keypair = otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", charlie_account));

  char *buffer = NULL;
  size_t s = 0;
  otrng_symmetric_key_serialize(&buffer, &s, keypair->sym);

  const char *expected = "RQ8MfhJljp+d1KUybu73Hj+Bve8lYTxE1wL5WDLyy+"
                         "pLryYcPUYGIODpKqfEtrRH2d6fgbpBGmhA";
  otrng_assert_cmpmem(expected, buffer, s);

  free(buffer);
  otrng_global_state_free(state);
}

static void test_global_state_shared_prekey_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};

  otrng_global_state_s *state = otrng_global_state_new(NULL);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", alice_account), alice_sym);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", bob_account), bob_sym);

  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", alice_account)));
  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", bob_account)));
  otrng_assert(!otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", charlie_account)));

  /* Generate file */
  FILE *keys = tmpfile();

  fputs("charlie@xmpp\n"
        "mgRi+jOWSHludTU/v0QE/"
        "6W88WmxUmKMh1QpRbrEw4LESkL0mnOgZBbqpInVFJGy3v2aKbBFj4c0\n",
        keys);
  rewind(keys);

  otrng_result result = otrng_global_state_shared_prekey_read_from(
      state, keys, read_client_id_for_privf);
  otrng_assert_is_success(result);
  fclose(keys);

  otrng_client_s *client =
      get_client(state, create_client_id("otr", charlie_account));

  char *buffer = NULL;
  size_t s = 0;
  otrng_symmetric_key_serialize(&buffer, &s, client->shared_prekey_pair->sym);

  const char *expected =
      "mgRi+jOWSHludTU/v0QE/"
      "6W88WmxUmKMh1QpRbrEw4LESkL0mnOgZBbqpInVFJGy3v2aKbBFj4c0";

  otrng_assert_cmpmem(expected, buffer, s);

  free(buffer);
  otrng_global_state_free(state);
}

static void test_global_state_client_profile_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};
  const uint8_t alice_fsym[ED448_PRIVATE_BYTES] = {3};
  const uint8_t bob_fsym[ED448_PRIVATE_BYTES] = {5};

  otrng_global_state_s *state = otrng_global_state_new(NULL);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", alice_account), alice_sym);
  otrng_public_key *fk = create_forging_key_from(alice_fsym);
  otrng_global_state_add_forging_key(
      state, create_client_id("otr", alice_account), fk);
  free(fk);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", bob_account), bob_sym);
  fk = create_forging_key_from(bob_fsym);
  otrng_global_state_add_forging_key(state,
                                     create_client_id("otr", bob_account), fk);
  free(fk);

  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", alice_account)));
  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", bob_account)));
  otrng_assert(!otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", charlie_account)));

  /* Generate file */
  FILE *client_profile = tmpfile();

  fputs("charlie@xmpp\n"
        "AAAABQABAAAABAACABAFcsFMsTB3RLkvO"
        "Df5ljmruyD/xHHYnZ1UU0nccA4BJ0kfBhMU+viahccHYL0BiKVmnRpDk/CDS4AAAwASmJc"
        "x7rsKG6WmkEPIwSUWsWi+oSN0ZUsE6LPThZO6NwsHGky+PyCO4eIOl31h5R/8yn"
        "+HFQwYpfwAAAQAAAACNAAABQAAAA"
        "AAAAAADUwrQkA131HHDGqpPpkVYz"
        "K6wxkiey41VEP627vvMiat5eTSRT"
        "qy/mGfdgACg1PqeNp5RNxqlR+AvE"
        "c7I9d71XiJykzb/w40+F8R1PD+qZ"
        "PeXjol7p0sWSVfr+d1xw9sk6aL0r"
        "dspG3NtxBaAIodSgcA\n",
        client_profile);
  rewind(client_profile);

  otrng_result result = otrng_global_state_client_profile_read_from(
      state, client_profile, read_client_id_for_privf);
  otrng_assert_is_success(result);
  fclose(client_profile);

  otrng_client_s *client =
      get_client(state, create_client_id("otr", charlie_account));

  otrng_assert(client->client_profile);

  uint8_t *buffer = NULL;
  size_t s = 0;
  otrng_client_profile_serialize(&buffer, &s, client->client_profile);
  char *encoded = otrng_base64_encode(buffer, s);
  const char *expected =
      "AAAABQABAAAABAACABAFcsFMsTB3RLkvO"
      "Df5ljmruyD/xHHYnZ1UU0nccA4BJ0kfBhMU+viahccHYL0BiKVmnRpDk/CDS4AAAwASmJc"
      "x7rsKG6WmkEPIwSUWsWi+oSN0ZUsE6LPThZO6NwsHGky+PyCO4eIOl31h5R/8yn"
      "+HFQwYpfwAAAQAAAABNAAFAAAAAA"
      "AAAAANTCtCQDXfUccMaqk+mRVjMr"
      "rDGSJ7LjVUQ/rbu+8yJq3l5NJFOr"
      "L+YZ92AAKDU+p42nlE3GqVH4C8Rz"
      "sj13vVeInKTNv/DjT4XxHU8P6pk9"
      "5eOiXunSxZJV+v53XHD2yTpovSt2"
      "ykbc23EFoAih1KBwA=";

  otrng_assert_cmpmem(expected, encoded, s);

  free(encoded);
  free(buffer);
  otrng_global_state_free(state);
}

static void test_global_state_prekey_profile_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};
  const uint8_t alice_fsym[ED448_PRIVATE_BYTES] = {3};
  const uint8_t bob_fsym[ED448_PRIVATE_BYTES] = {5};

  otrng_global_state_s *state = otrng_global_state_new(NULL);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", alice_account), alice_sym);
  otrng_public_key *fk = create_forging_key_from(alice_fsym);
  otrng_global_state_add_forging_key(
      state, create_client_id("otr", alice_account), fk);
  free(fk);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", bob_account), bob_sym);
  fk = create_forging_key_from(bob_fsym);
  otrng_global_state_add_forging_key(state,
                                     create_client_id("otr", bob_account), fk);
  free(fk);

  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", alice_account)));
  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", bob_account)));
  otrng_assert(!otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", charlie_account)));

  /* Generate file */
  FILE *prekey_profile = tmpfile();

  fputs("charlie@xmpp\n"
        "26FP8QAAAABbxy5lABFQAQ3a/"
        "s1vlz8xF+vPV82xSwmEA65IyR3ZaR6NzZNNAznBrXXb7YjvMuYtTtKnp+"
        "LZfUSYFcjoZACAqnA8V5fDvuuCFFMINr6rKZihf4wTVOKO+hO+"
        "rMWi7dsYeLu3eee7fZ9LsHUuriHxadL6mW0J6QAPeo2n75TnDUt1aVpjCK0Mrut0hTstbD"
        "oyyEVaVNh2Rx87o30YStXn92fDNCBsGHU+F2xv/ZQ2OQA=\n",
        prekey_profile);
  rewind(prekey_profile);

  otrng_result result = otrng_global_state_prekey_profile_read_from(
      state, prekey_profile, read_client_id_for_privf);
  otrng_assert_is_success(result);
  fclose(prekey_profile);

  otrng_client_s *client =
      get_client(state, create_client_id("otr", charlie_account));

  otrng_assert(client->prekey_profile);

  uint8_t *buffer = NULL;
  size_t s = 0;
  otrng_prekey_profile_serialize(&buffer, &s, client->prekey_profile);
  char *encoded = otrng_base64_encode(buffer, s);
  const char *expected =
      "26FP8QAAAABbxy5lABFQAQ3a/"
      "s1vlz8xF+vPV82xSwmEA65IyR3ZaR6NzZNNAznBrXXb7YjvMuYtTtKnp+"
      "LZfUSYFcjoZACAqnA8V5fDvuuCFFMINr6rKZihf4wTVOKO+hO+"
      "rMWi7dsYeLu3eee7fZ9LsHUuriHxadL6mW0J6QAPeo2n75TnDUt1aVpjCK0Mrut0hTstbDoy"
      "yEVaVNh2Rx87o30YStXn92fDNCBsGHU+F2xv/ZQ2OQA=";

  otrng_assert_cmpmem(expected, encoded, s);

  free(encoded);
  free(buffer);
  otrng_global_state_free(state);
}

static void test_global_state_prekey_message_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};

  otrng_global_state_s *state = otrng_global_state_new(NULL);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", alice_account), alice_sym);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", bob_account), bob_sym);

  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", alice_account)));
  otrng_assert(otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", bob_account)));
  otrng_assert(!otrng_global_state_get_private_key_v4(
      state, create_client_id("otr", charlie_account)));

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

  otrng_result result = otrng_global_state_prekeys_read_from(
      state, prekey, read_client_id_for_privf);
  otrng_assert_is_success(result);

  fclose(prekey);

  otrng_client_s *client =
      get_client(state, create_client_id("otr", charlie_account));

  otrng_assert(client->our_prekeys);

  uint32_t message_id = 4047093956;
  const otrng_stored_prekeys_s *stored_prekey = NULL;
  stored_prekey = otrng_client_get_my_prekeys_by_id(message_id, client);

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

  otrng_global_state_free(state);
}

static void test_instance_tag_api(void) {
  const char *alice_protocol = "otr";
  unsigned int instance_tag = 0x9abcdef0;

  otrng_client_s *alice =
      otrng_client_new(create_client_id("otr", alice_account));
  alice->global_state = otrng_global_state_new(test_callbacks);

  FILE *instagFILEp = tmpfile();

  fprintf(instagFILEp, "%s\t%s\t%08x\n", alice_account, alice_protocol,
          instance_tag);
  rewind(instagFILEp);
  otrng_client_instance_tag_read_from(alice, instagFILEp);
  fclose(instagFILEp);

  unsigned int alice_instag = otrng_client_get_instance_tag(alice);
  otrng_assert(alice_instag);

  char sone[9];
  snprintf(sone, sizeof(sone), "%08x", alice_instag);

  g_assert_cmpstr(sone, ==, "9abcdef0");

  otrng_global_state_free(alice->global_state);
  otrng_client_free(alice);
}

void units_messaging_add_tests() {
  g_test_add_func("/global_state/key_management",
                  test_global_state_key_management);
  g_test_add_func("/global_state/shared_prekey_management",
                  test_global_state_shared_prekey_management);
  g_test_add_func("/global_state/client_profile",
                  test_global_state_client_profile_management);
  g_test_add_func("/global_state/prekey_profile",
                  test_global_state_prekey_profile_management);
  g_test_add_func("/global_state/prekey_message_management",
                  test_global_state_prekey_message_management);

  g_test_add_func("/api/instance_tag", test_instance_tag_api);
}
