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
  otrng_free(line);

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

static otrng_client_callbacks_s empty_callbacks[1] = {{
    .create_client_profile = &create_client_profile_cb_empty,
    .create_prekey_profile = &create_prekey_profile_cb_empty,
    .get_shared_session_state = &get_shared_session_state_cb_empty,
    .create_privkey_v3 = &create_privkey_v3_cb_empty,
    .create_privkey_v4 = &create_privkey_v4_cb_empty,
    .create_forging_key = &create_forging_key_cb_empty,
    .store_expired_client_profile = &write_expired_client_profile_cb_empty,
    .store_expired_prekey_profile = &write_expired_prekey_profile_cb_empty,
    .display_error_message = &display_error_message_cb_empty,
    .load_privkey_v4 = &load_privkey_v4_cb_empty,
    .load_client_profile = &load_client_profile_cb_empty,
    .load_prekey_profile = &load_prekey_profile_cb_empty,
}};

static void test_global_state_key_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};

  otrng_global_state_s *state =
      otrng_global_state_new(empty_callbacks, otrng_false);
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

  otrng_secure_free(buffer);
  otrng_global_state_free(state);
}

static void test_global_state_client_profile_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};
  const uint8_t alice_fsym[ED448_PRIVATE_BYTES] = {3};
  const uint8_t bob_fsym[ED448_PRIVATE_BYTES] = {5};

  otrng_global_state_s *state =
      otrng_global_state_new(empty_callbacks, otrng_false);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", alice_account), alice_sym);
  otrng_public_key *fk = create_forging_key_from(alice_fsym);
  otrng_global_state_add_forging_key(
      state, create_client_id("otr", alice_account), fk);
  otrng_free(fk);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", bob_account), bob_sym);
  fk = create_forging_key_from(bob_fsym);
  otrng_global_state_add_forging_key(state,
                                     create_client_id("otr", bob_account), fk);
  otrng_free(fk);

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
        "dspG3NtxBaAIodSgcAXDA=\n",
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
  otrng_assert(
      otrng_client_profile_serialize(&buffer, &s, client->client_profile));
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

  otrng_free(encoded);
  otrng_free(buffer);
  otrng_global_state_free(state);
}

static void test_global_state_prekey_profile_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};
  const uint8_t alice_fsym[ED448_PRIVATE_BYTES] = {3};
  const uint8_t bob_fsym[ED448_PRIVATE_BYTES] = {5};

  otrng_global_state_s *state =
      otrng_global_state_new(empty_callbacks, otrng_false);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", alice_account), alice_sym);
  otrng_public_key *fk = create_forging_key_from(alice_fsym);
  otrng_global_state_add_forging_key(
      state, create_client_id("otr", alice_account), fk);
  otrng_free(fk);
  otrng_global_state_add_private_key_v4(
      state, create_client_id("otr", bob_account), bob_sym);
  fk = create_forging_key_from(bob_fsym);
  otrng_global_state_add_forging_key(state,
                                     create_client_id("otr", bob_account), fk);
  otrng_free(fk);

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
        "oyyEVaVNh2Rx87o30YStXn92fDNCBsGHU+F2xv/ZQ2OQAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
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
      "26FP8QAAAABbxy5lABFbOv4Dh"
      "4pJsoIy1PGkQq694Qn4B6zvff2af2W5Yv5S1lRzEsrOz/BDN1CPnSUpqP"
      "FmkWmyHDLEgACAqnA8V5fDvuuCFFMINr6rKZihf4wTVOKO+hO+"
      "rMWi7dsYeLu3eee7fZ9LsHUuriHxadL6mW0J6QAPeo2n75TnDUt1aVpjCK0Mrut0hTstbD"
      "oyyEVaVNh2Rx87o30YStXn92fDNCBsGHU+F2xv/ZQ2OQA=";

  otrng_assert_cmpmem(expected, encoded, s);

  otrng_free(encoded);
  otrng_free(buffer);
  otrng_global_state_free(state);
}

static void test_global_state_prekey_message_management(void) {
  const uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  const uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};

  otrng_global_state_s *state =
      otrng_global_state_new(empty_callbacks, otrng_false);
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
        "AAQPMZClCAAQCg8RzPlh43FIy2YW+g3KqIb5SXpx74ECFHpaxUHoQdWNFbRRw1NPsk/"
        "XMWaOF73EjiQn68qGu4NgjYAAAAGA1LDfpCMT4A2bkDLdJRW0kTvTPfQl6kfEgpQPzmSW9"
        "1ckbby7atStSbBtDKlI8jkIm/UChVzY4ZKM7MAgbiDB1m5I78Ivd1cNE/"
        "F0kiX6yx5y8xgHPeb5P/"
        "38ilijUn7Zpy+"
        "egdeOOcu9iEIG8VRNQe6DDf7GmKLQs1l12Y6tPWkvk8e6s8YcS3PM5dv3TFakcNflgaA3G"
        "6dJIG3OVvLJmQq5TivJqY6GY/"
        "9Or6CknzQYNUoJKRb2Nq7i79BAFL+8ShnERztTjdx9e4tBuKLJ7DSV/"
        "K085L8U6yEzFrFAQ2YzUbbb+"
        "YqWcsvdEgDe7kgYYXzBzt0n8Qx9BSMOPaPgTK1oJiYIj9gLOrCvUBh+"
        "USF9xLg50IkkfHTvQvtj6Sn9R55+Qd6mILJtsUdDqx0BnKlxrmaECA4iN+ZRWOx/"
        "VVXJoc7RgJo3t7v4ZNwvW5rMmYs1HqhYw+8m6CxqoNBevLaH34NddDE4XIyEjl/"
        "oczP20BLkS3LRfBRQ/"
        "Ph6tZ6cAK7U+bAOYMLOSj56rTmmJ0OMP+mzZRHoRQGqJ4L25g1Ts9VycLZe4JB+/"
        "EAOEYUuIcwUokQ57rAtAAAAUD0w1jRPz5OrBWG3W2BgE+Y7N+"
        "ilor5uLIMoohICSNFfXaTRS1bb7X9LN+cZ8heh49rGUv1GUO8OZQPB2NFbjo/"
        "QBrbvY6UwIExSumhKAvBn\n",
        prekey);
  rewind(prekey);

  otrng_result result = otrng_global_state_prekeys_read_from(
      state, prekey, read_client_id_for_privf);
  otrng_assert_is_success(result);
  fclose(prekey);

  otrng_client_s *client =
      get_client(state, create_client_id("otr", charlie_account));

  otrng_assert(client->our_prekeys);

  uint32_t message_id = 831563016;
  const prekey_message_s *stored_prekey = NULL;
  stored_prekey = otrng_client_get_prekey_by_id(message_id, client);

  uint8_t ecdh_secret_k[ED448_SCALAR_BYTES] = {0};
  otrng_ec_scalar_encode(ecdh_secret_k, stored_prekey->y->priv);

  char *ecdh_symkey = otrng_base64_encode(ecdh_secret_k, ED448_SCALAR_BYTES);

  const char *expected_ecdh =
      "rtT5sA5gws5KPnqtOaYnQ4w/"
      "6bNlEehFAaongvbmDVOz1XJwtl7gkH78QA4RhS4hzBSiRDnusC0=";
  otrng_assert_cmpmem(expected_ecdh, ecdh_symkey, 76);

  otrng_free(ecdh_symkey);

  uint8_t dh_secret_k[DH_KEY_SIZE] = {0};
  size_t dh_secret_k_len = 0;
  otrng_dh_mpi_serialize(dh_secret_k, DH_KEY_SIZE, &dh_secret_k_len,
                         stored_prekey->b->priv);

  char *dh_symkey = otrng_base64_encode(dh_secret_k, dh_secret_k_len);

  const char *expected_dh =
      "PTDWNE/Pk6sFYbdbYGAT5js36KWivm4sgyiiEgJI0V9dpNFLVtvtf0s35xnyF6Hj2sZS/"
      "UZQ7w5lA8HY0VuOj9AGtu9jpTAgTFK6aEoC8Gc=";
  otrng_assert_cmpmem(expected_dh, dh_symkey, 108);

  otrng_free(dh_symkey);

  otrng_global_state_free(state);
}

static void test_instance_tag_api(void) {
  const char *alice_protocol = "otr";
  unsigned int instance_tag = 0x9abcdef0;

  otrng_client_s *alice =
      otrng_client_new(create_client_id("otr", alice_account));
  alice->global_state = otrng_global_state_new(test_callbacks, otrng_false);

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
  g_test_add_func("/global_state/client_profile",
                  test_global_state_client_profile_management);
  g_test_add_func("/global_state/prekey_profile",
                  test_global_state_prekey_profile_management);
  g_test_add_func("/global_state/prekey_message_management",
                  test_global_state_prekey_message_management);

  g_test_add_func("/api/instance_tag", test_instance_tag_api);
}
