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
#include <string.h>

#include "test_helpers.h"

#include "test_fixtures.h"

#include "otrng.h"

static void test_otrng_builds_query_message(otrng_fixture_s *otrng_fixture,
                                            gconstpointer data) {
  const char *message = "And some random invitation text.";

  char *query_message = NULL;
  (void)data;
  otrng_assert_is_success(
      otrng_build_query_message(&query_message, message, otrng_fixture->otr));

  const char *expected_qm = "?OTRv4? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);

  otrng_free(query_message);
}

static void test_otrng_builds_query_message_v34(otrng_fixture_s *otrng_fixture,
                                                gconstpointer data) {
  const char *message = "And some random invitation text.";

  char *query_message = NULL;
  (void)data;
  otrng_assert_is_success(
      otrng_build_query_message(&query_message, message, otrng_fixture->v34));

  const char *expected_qm = "?OTRv43? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);

  otrng_free(query_message);
}

static void test_otrng_builds_whitespace_tag(otrng_fixture_s *otrng_fixture,
                                             gconstpointer data) {
  const char *expected_tag =
      " \t  \t\t\t\t \t \t \t    \t\t \t  And some random invitation text.";
  const char *message = "And some random invitation text.";

  char *whitespace_tag = NULL;
  (void)data;
  otrng_assert_is_success(
      otrng_build_whitespace_tag(&whitespace_tag, message, otrng_fixture->otr));
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);
  otrng_free(whitespace_tag);
}

static void test_otrng_builds_whitespace_tag_v34(otrng_fixture_s *otrng_fixture,
                                                 gconstpointer data) {
  const char *expected_tag =
      " \t  \t\t\t\t \t \t \t    \t\t \t    \t\t  \t\tAnd "
      "some random invitation text";
  const char *message = "And some random invitation text";

  char *whitespace_tag = NULL;
  (void)data;
  otrng_assert_is_success(
      otrng_build_whitespace_tag(&whitespace_tag, message, otrng_fixture->v34));
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);
  otrng_free(whitespace_tag);
}

static void test_otrng_receives_plaintext_without_ws_tag_on_start(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {
  (void)data;
  otrng_response_s *response = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response, "Some random text.", otrng_fixture->otr));

  g_assert_cmpstr(response->to_display, ==, "Some random text.");

  otrng_response_free(response);
}

static void test_otrng_receives_plaintext_without_ws_tag_not_on_start(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {
  (void)data;
  otrng_fixture->otr->state = OTRNG_STATE_WAITING_AUTH_I;

  otrng_response_s *response = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response, "Some random text.", otrng_fixture->otr));

  g_assert_cmpstr(response->to_display, ==, "Some random text.");

  otrng_response_free(response);
}

static void
test_otrng_receives_plaintext_with_ws_tag(otrng_fixture_s *otrng_fixture,
                                          gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  const string_p message =
      " \t  \t\t\t\t \t \t \t    \t\t \t  And some random invitation text.";

  otrng_result res =
      otrng_receive_message(response, message, otrng_fixture->otr);
  (void)data;
  otrng_assert_is_success(res);
  g_assert_cmpstr(response->to_display, ==, "And some random invitation text.");
  otrng_assert(response->to_send);
  g_assert_cmpint(otrng_fixture->otr->state, ==, OTRNG_STATE_WAITING_AUTH_R);
  g_assert_cmpint(otrng_fixture->otr->running_version, ==, 4);

  otrng_response_free(response);
}

static void test_otrng_receives_plaintext_with_ws_tag_after_text(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  const string_p message =
      "Some random invitation text. \t  \t\t\t\t \t \t \t    \t\t \t  ";

  (void)data;
  otrng_assert_is_success(
      otrng_receive_message(response, message, otrng_fixture->otr));
  g_assert_cmpstr(response->to_display, ==, "Some random invitation text.");
  otrng_assert(response->to_send);
  g_assert_cmpint(otrng_fixture->otr->state, ==, OTRNG_STATE_WAITING_AUTH_R);
  g_assert_cmpint(otrng_fixture->otr->running_version, ==, 4);

  otrng_response_free(response);
}

static void
test_otrng_receives_plaintext_with_ws_tag_v3(otrng_fixture_s *otrng_fixture,
                                             gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  const string_p message =
      " \t  \t\t\t\t \t \t \t    \t\t  \t\tAnd some random invitation text.";
  (void)data;
  otrng_assert_is_success(
      otrng_receive_message(response, message, otrng_fixture->v3));

  g_assert_cmpstr(response->to_display, ==, "And some random invitation text.");
  g_assert_cmpint(otrng_fixture->otr->state, ==, OTRNG_STATE_START);
  g_assert_cmpint(otrng_fixture->v3->running_version, ==, 3);

  otrng_response_free(response);
}

static void test_otrng_receives_query_message(otrng_fixture_s *otrng_fixture,
                                              gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  (void)data;
  otrng_assert_is_success(otrng_receive_message(
      response, "?OTRv4? And some random invitation text.",
      otrng_fixture->otr));

  otrng_assert(response->to_send);
  g_assert_cmpint(otrng_fixture->otr->state, ==, OTRNG_STATE_WAITING_AUTH_R);
  g_assert_cmpint(otrng_fixture->otr->running_version, ==, 4);

  otrng_response_free(response);
}

static void test_otrng_receives_query_message_v3(otrng_fixture_s *otrng_fixture,
                                                 gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  (void)data;
  otrng_assert_is_success(otrng_receive_message(
      response, "?OTRv3? And some random invitation text.", otrng_fixture->v3));

  g_assert_cmpint(otrng_fixture->v3->running_version, ==, 3);

  otrng_response_free(response);
}

static void test_otrng_receives_identity_message_invalid_on_start(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {
  const char *identity_message = "?OTR:";
  otrng_response_s *response = otrng_response_new();
  (void)data;
  otrng_assert_is_success(
      otrng_receive_message(response, identity_message, otrng_fixture->otr));

  g_assert_cmpint(otrng_fixture->otr->state, ==, OTRNG_STATE_START);
  g_assert_cmpint(otrng_fixture->otr->running_version, ==, 4);
  otrng_assert(!response->to_display);
  otrng_assert(!response->to_send);

  otrng_response_free(response);
}

static void test_otrng_destroy() {
  otrng_client_s *client = otrng_client_new(ALICE_IDENTITY);

  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V4,
                           .type = OTRNG_POLICY_DEFAULT};
  otrng_s *otr = otrng_new(client, policy);

  otrng_destroy(otr);

  otrng_assert(otr->keys == NULL);
  otrng_assert(otr->their_client_profile == NULL);
  otrng_assert(otr->v3_conn == NULL);

  otrng_free(otr);
  otrng_client_free(client);
}

static void test_otrng_build_prekey_ensemble() {
  uint8_t long_term_priv[ED448_PRIVATE_BYTES] = {0xA};
  uint8_t forging_priv[ED448_PRIVATE_BYTES] = {
      2}; // non-random forging key on purpose
  otrng_keypair_s *kforging = otrng_keypair_new();
  otrng_assert_is_success(otrng_keypair_generate(kforging, forging_priv));

  otrng_client_s *client = otrng_client_new(ALICE_IDENTITY);
  client->global_state = otrng_global_state_new(test_callbacks, otrng_false);

  otrng_assert_is_success(
      otrng_client_add_private_key_v4(client, long_term_priv));
  otrng_assert_is_success(otrng_client_add_forging_key(client, kforging->pub));
  otrng_keypair_free(kforging);
  otrng_assert_is_success(otrng_client_add_instance_tag(client, 0x100A0F));

  otrng_keypair_s *keypair = otrng_client_get_keypair_v4(client);
  otrng_client_profile_s *profile = otrng_client_profile_build(
      0x100A0F, "34", keypair, *otrng_client_get_forging_key(client),
      otrng_client_get_client_profile_exp_time(client));
  otrng_client_add_client_profile(client, profile);
  otrng_client_profile_free(profile);

  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V4,
                           .type = OTRNG_POLICY_DEFAULT};
  otrng_s *otr = otrng_new(client, policy);

  // TODO: @sanitizer add a client profile
  prekey_ensemble_s *ensemble = otrng_build_prekey_ensemble(otr);
  otrng_assert(ensemble);
  otrng_assert_is_success(otrng_prekey_ensemble_validate(ensemble));

  // Sends the same stored clients
  otrng_assert_client_profile_eq(ensemble->client_profile,
                                 client->client_profile);
  otrng_assert_prekey_profile_eq(ensemble->prekey_profile,
                                 client->prekey_profile);

  // Stores the same prekey message sent
  // TODO: Assert the instance tag
  // TODO: Assert the private part
  prekey_message_s *stored = client->our_prekeys->data;
  otrng_assert(stored);
  otrng_assert_ec_public_key_eq(ensemble->message->Y, stored->y->pub);
  otrng_assert_dh_public_key_eq(ensemble->message->B, stored->b->pub);

  otrng_prekey_ensemble_free(ensemble);
  otrng_conn_free(otr);
  otrng_global_state_free(client->global_state);
  otrng_client_free(client);
}

static void test_otrng_invokes_shared_session_state_callbacks(void) {
  otrng_client_s *client = otrng_client_new(ALICE_IDENTITY);
  otrng_s *protocol = set_up(client, 1);

  otrng_shared_session_state_s session;
  session = otrng_get_shared_session_state(protocol);

  otrng_assert_cmpmem(session.identifier1, "alice",
                      strlen(session.identifier1));
  otrng_assert_cmpmem(session.identifier2, "bob", strlen(session.identifier2));
  otrng_assert(session.password == NULL);

  otrng_free(session.identifier1);
  otrng_free(session.identifier2);

  otrng_conn_free(protocol);
  otrng_global_state_free(client->global_state);
}

static void test_otrng_generates_shared_session_state_string(void) {
  otrng_shared_session_state_s state1[1];
  state1->identifier1 = otrng_xstrdup("alice");
  state1->identifier2 = otrng_xstrdup("bob");
  state1->password = NULL;

  char *state1_str = otrng_generate_session_state_string(state1);
  otrng_assert(state1_str);
  otrng_assert_cmpmem(state1_str, "alicebob", strlen("alicebob"));

  otrng_free(state1_str);
  otrng_free(state1->identifier1);
  otrng_free(state1->identifier2);

  otrng_shared_session_state_s state2[1];
  state2->identifier1 = otrng_xstrdup("bob");
  state2->identifier2 = otrng_xstrdup("alice");
  state2->password = NULL;

  char *state2_str = otrng_generate_session_state_string(state2);
  otrng_assert(state2_str);
  otrng_assert_cmpmem(state2_str, "alicebob", strlen("alicebob"));

  otrng_free(state2_str);
  otrng_free(state2->identifier1);
  otrng_free(state2->identifier2);

  otrng_shared_session_state_s state3[1];
  state3->identifier1 = otrng_xstrdup("bob");
  state3->identifier2 = otrng_xstrdup("alice");
  state3->password = otrng_xstrdup("passwd");

  char *state3_str = otrng_generate_session_state_string(state3);
  otrng_assert(state3_str);
  otrng_assert_cmpmem(state3_str, "alicebobpasswd", strlen("alicebobpasswd"));

  otrng_free(state3_str);
  otrng_free(state3->identifier1);
  otrng_free(state3->identifier2);
  otrng_free(state3->password);

  char *state4_str = otrng_generate_session_state_string(NULL);
  otrng_assert(state4_str == NULL);

  otrng_shared_session_state_s state4[1];
  state4->identifier1 = otrng_xstrdup("bob");
  state4->identifier2 = NULL;
  state4->password = NULL;

  otrng_assert(otrng_generate_session_state_string(state4) == NULL);
  otrng_free(state4->identifier1);

  otrng_shared_session_state_s state5[1];
  state5->identifier1 = NULL;
  state5->identifier2 = otrng_xstrdup("bob");
  state5->password = NULL;

  otrng_assert(otrng_generate_session_state_string(state5) == NULL);
  otrng_free(state5->identifier2);
}

// TODO: move this to functionals?
void test_start_with_whitespace_tag(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  set_up_client(alice_client, 1);
  set_up_client(bob_client, 2);

  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V34,
                           .type = OTRNG_POLICY_OPPORTUNISTIC};

  otrng_s *alice = otrng_new(alice_client, policy);
  otrng_s *bob = otrng_new(bob_client, policy);

  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();
  char *whitespace_tag = NULL;
  const char *message = "Add some random";

  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert(bob->state == OTRNG_STATE_START);

  /* Alice sends a Whitespace tag */
  otrng_assert_is_success(
      otrng_build_whitespace_tag(&whitespace_tag, message, alice));
  otrng_assert(alice->state == OTRNG_STATE_START);

  /* Bob receives a Whitespace tag */
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, whitespace_tag, bob));
  otrng_free(whitespace_tag);

  const char *expected_tag = "Add some random";
  otrng_assert(bob->state == OTRNG_STATE_WAITING_AUTH_R);
  g_assert_cmpstr(response_to_alice->to_display, ==, expected_tag);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAQ1", response_to_alice->to_send, 9);

  free(response_to_alice->to_display);

  /* Alice receives an Identity Message */
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, response_to_alice->to_send, alice));
  otrng_free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  /* Alice has Bob's ephemeral keys */
  otrng_assert_ec_public_key_eq(alice->keys->their_ecdh,
                                bob->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(alice->keys->their_dh, bob->keys->our_dh->pub);
  otrng_assert_not_zero(alice->keys->ssid, sizeof(alice->keys->ssid));
  otrng_assert_not_zero(alice->keys->shared_secret, sizeof(k_shared_secret));

  /* Alice replies with an Auth-R message */
  otrng_assert(alice->state == OTRNG_STATE_WAITING_AUTH_I);
  otrng_assert(response_to_bob->to_display == NULL);
  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAQ2", response_to_bob->to_send, 9);

  /* Bob receives an Auth-R message */
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, response_to_bob->to_send, bob));
  otrng_free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  /* Bob has Alice's ephemeral keys */
  otrng_assert_ec_public_key_eq(bob->keys->their_ecdh,
                                alice->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(bob->keys->their_dh, alice->keys->our_dh->pub);
  otrng_assert_not_zero(bob->keys->ssid, sizeof(alice->keys->ssid));
  otrng_assert_zero(bob->keys->shared_secret, sizeof(k_shared_secret));
  otrng_assert_not_zero(bob->keys->current->root_key, sizeof(k_root));

  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);

  /* Bob replies with an Auth-I message */
  otrng_assert(bob->state == OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE);
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAQ3", response_to_alice->to_send, 9);

  /* The double ratchet is initialized */
  otrng_assert(bob->keys->current);

  /* Alice receives an Auth-I message */
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, response_to_alice->to_send, alice));
  otrng_free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  /* The double ratchet is initialized */
  otrng_assert(alice->keys->current);

  /* Both participants have the same shared secret */
  otrng_assert_root_key_eq(alice->keys->shared_secret,
                           bob->keys->shared_secret);

  /* Alice replies with initial data message Dake Data Message */
  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9);
  otrng_assert(response_to_bob->to_display == NULL);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);

  /* Bob receives the initial data message */
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, response_to_bob->to_send, bob));
  otrng_free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  otrng_assert(bob->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(response_to_alice->to_send == NULL);
  otrng_assert(response_to_alice->to_display == NULL);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  otrng_response_free(response_to_alice);
  otrng_response_free(response_to_bob);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_conn_free_all(alice, bob);
}

void test_send_with_padding(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  size_t granularity = 256;
  otrng_client_set_padding(granularity, alice_client);

  otrng_s *alice = set_up(alice_client, 1);
  otrng_s *bob = set_up(bob_client, 2);

  /* DAKE has finished */
  do_dake_fixture(alice, bob);

  string_p to_send_1 = NULL;
  otrng_result result;

  /* Alice sends a data message */
  result = otrng_send_message(&to_send_1, "hi", NULL, 0, alice);
  assert_message_sent(result, to_send_1);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  g_assert_cmpint(1094, ==,
                  strlen(to_send_1)); /* without padding this is 748 */

  free(to_send_1);
  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_conn_free_all(alice, bob);
}

void units_otrng_add_tests(void) {
  (void)test_otrng_receives_identity_message_invalid_on_start; // this function
                                                               // is unused

  g_test_add("/otrng/builds_query_message", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_builds_query_message,
             otrng_fixture_teardown);
  g_test_add("/otrng/builds_query_message_v34", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_builds_query_message_v34,
             otrng_fixture_teardown);
  g_test_add("/otrng/builds_whitespace_tag", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_builds_whitespace_tag,
             otrng_fixture_teardown);
  g_test_add("/otrng/builds_whitespace_tag_v34", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_builds_whitespace_tag_v34,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_without_ws_tag_on_start",
             otrng_fixture_s, NULL, otrng_fixture_set_up,
             test_otrng_receives_plaintext_without_ws_tag_on_start,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_without_ws_tag_not_on_start",
             otrng_fixture_s, NULL, otrng_fixture_set_up,
             test_otrng_receives_plaintext_without_ws_tag_not_on_start,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_with_ws_tag", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_receives_plaintext_with_ws_tag,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_with_ws_tag_after_text",
             otrng_fixture_s, NULL, otrng_fixture_set_up,
             test_otrng_receives_plaintext_with_ws_tag_after_text,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_with_ws_tag_v3", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_receives_plaintext_with_ws_tag_v3,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_query_message", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_receives_query_message,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_query_message_v3", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_receives_query_message_v3,
             otrng_fixture_teardown);
  g_test_add_func("/otrng/destroy", test_otrng_destroy);

  g_test_add_func("/otrng/shared_session_state/serializes",
                  test_otrng_generates_shared_session_state_string);
  g_test_add_func("/otrng/callbacks/shared_session_state",
                  test_otrng_invokes_shared_session_state_callbacks);
  g_test_add_func("/otrng/build_prekey_ensemble",
                  test_otrng_build_prekey_ensemble);
  g_test_add_func("/otrng/start_with_whitespace_tag",
                  test_start_with_whitespace_tag);
  g_test_add_func("/otrng/send_with_padding", test_send_with_padding);
}
