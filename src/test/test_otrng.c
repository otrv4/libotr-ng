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

#include <glib.h>
#include <string.h>

#include "../otrng.h"

void test_otrng_builds_query_message(otrng_fixture_s *otrng_fixture,
                                     gconstpointer data) {
  char *message = "And some random invitation text.";

  char *query_message = NULL;
  otrng_assert_is_success(
      otrng_build_query_message(&query_message, message, otrng_fixture->otr));

  char *expected_qm = "?OTRv4? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);

  free(query_message);
}

void test_otrng_builds_query_message_v34(otrng_fixture_s *otrng_fixture,
                                         gconstpointer data) {
  char *message = "And some random invitation text.";

  char *query_message = NULL;
  otrng_assert_is_success(
      otrng_build_query_message(&query_message, message, otrng_fixture->v34));

  char *expected_qm = "?OTRv43? And some random invitation text.";
  g_assert_cmpstr(query_message, ==, expected_qm);

  free(query_message);
}

void test_otrng_builds_whitespace_tag(otrng_fixture_s *otrng_fixture,
                                      gconstpointer data) {
  char *expected_tag =
      " \t  \t\t\t\t \t \t \t    \t\t \t  And some random invitation text.";
  char *message = "And some random invitation text.";

  char *whitespace_tag = NULL;
  otrng_assert_is_success(
      otrng_build_whitespace_tag(&whitespace_tag, message, otrng_fixture->otr));
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);
  free(whitespace_tag);
}

void test_otrng_builds_whitespace_tag_v34(otrng_fixture_s *otrng_fixture,
                                          gconstpointer data) {
  char *expected_tag = " \t  \t\t\t\t \t \t \t    \t\t \t    \t\t  \t\tAnd "
                       "some random invitation text";
  char *message = "And some random invitation text";

  char *whitespace_tag = NULL;
  otrng_assert_is_success(
      otrng_build_whitespace_tag(&whitespace_tag, message, otrng_fixture->v34));
  g_assert_cmpstr(whitespace_tag, ==, expected_tag);
  free(whitespace_tag);
}

void test_otrng_receives_plaintext_without_ws_tag_on_start(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  otrng_notif notif = NOTIF_NONE;
  otrng_assert_is_success(otrng_receive_message(
      response, notif, "Some random text.", otrng_fixture->otr));

  g_assert_cmpstr(response->to_display, ==, "Some random text.");

  otrng_response_free(response);
}

void test_otrng_receives_plaintext_without_ws_tag_not_on_start(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {
  otrng_fixture->otr->state = OTRNG_STATE_WAITING_AUTH_I;
  otrng_notif notif = NOTIF_NONE;

  otrng_response_s *response = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(
      response, notif, "Some random text.", otrng_fixture->otr));

  g_assert_cmpstr(response->to_display, ==, "Some random text.");
  g_assert_cmpint(response->warning, ==, OTRNG_WARN_RECEIVED_UNENCRYPTED);

  otrng_response_free(response);
}

void test_otrng_receives_plaintext_with_ws_tag(otrng_fixture_s *otrng_fixture,
                                               gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  string_p message =
      " \t  \t\t\t\t \t \t \t    \t\t \t  And some random invitation text.";
  otrng_notif notif = NOTIF_NONE;

  otrng_assert_is_success(
      otrng_receive_message(response, notif, message, otrng_fixture->otr));
  g_assert_cmpstr(response->to_display, ==, "And some random invitation text.");
  otrng_assert(response->to_send);
  g_assert_cmpint(otrng_fixture->otr->state, ==, OTRNG_STATE_WAITING_AUTH_R);
  g_assert_cmpint(otrng_fixture->otr->running_version, ==, OTRNG_VERSION_4);

  otrng_response_free(response);
}

void test_otrng_receives_plaintext_with_ws_tag_after_text(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  string_p message =
      "Some random invitation text. \t  \t\t\t\t \t \t \t    \t\t \t  ";
  otrng_notif notif = NOTIF_NONE;

  otrng_assert_is_success(
      otrng_receive_message(response, notif, message, otrng_fixture->otr));
  g_assert_cmpstr(response->to_display, ==, "Some random invitation text.");
  otrng_assert(response->to_send);
  g_assert_cmpint(otrng_fixture->otr->state, ==, OTRNG_STATE_WAITING_AUTH_R);
  g_assert_cmpint(otrng_fixture->otr->running_version, ==, OTRNG_VERSION_4);

  otrng_response_free(response);
}

void test_otrng_receives_plaintext_with_ws_tag_v3(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  string_p message =
      " \t  \t\t\t\t \t \t \t    \t\t  \t\tAnd some random invitation text.";
  otrng_notif notif = NOTIF_NONE;
  otrng_assert_is_success(
      otrng_receive_message(response, notif, message, otrng_fixture->v3));

  // g_assert_cmpstr(response->to_display, ==, "And some random invitation
  // text.");
  // g_assert_cmpint(otrng_fixture->otr->state, ==,
  // OTRNG_STATE_AKE_IN_PROGRESS);
  g_assert_cmpint(otrng_fixture->v3->running_version, ==, OTRNG_VERSION_3);

  otrng_response_free(response);
}

void test_otrng_receives_query_message(otrng_fixture_s *otrng_fixture,
                                       gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  otrng_notif notif = NOTIF_NONE;
  otrng_assert_is_success(otrng_receive_message(
      response, notif, "?OTRv4? And some random invitation text.",
      otrng_fixture->otr));

  otrng_assert(response->to_send);
  g_assert_cmpint(otrng_fixture->otr->state, ==, OTRNG_STATE_WAITING_AUTH_R);
  g_assert_cmpint(otrng_fixture->otr->running_version, ==, OTRNG_VERSION_4);

  otrng_response_free(response);
}

void test_otrng_receives_query_message_v3(otrng_fixture_s *otrng_fixture,
                                          gconstpointer data) {
  otrng_response_s *response = otrng_response_new();
  otrng_notif notif = NOTIF_NONE;
  otrng_assert_is_success(otrng_receive_message(
      response, notif, "?OTRv3? And some random invitation text.",
      otrng_fixture->v3));

  g_assert_cmpint(otrng_fixture->v3->running_version, ==, OTRNG_VERSION_3);

  otrng_response_free(response);
}

void test_otrng_receives_identity_message_invalid_on_start(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {
  char *identity_message = "?OTR:";
  otrng_notif notif = NOTIF_NONE;
  otrng_response_s *response = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(
      response, notif, identity_message, otrng_fixture->otr));

  g_assert_cmpint(otrng_fixture->otr->state, ==, OTRNG_STATE_START);
  g_assert_cmpint(otrng_fixture->otr->running_version, ==, OTRNG_VERSION_4);
  otrng_assert(!response->to_display);
  otrng_assert(!response->to_send);

  otrng_response_free(response);
}

void test_otrng_receives_identity_message_validates_instance_tag(
    otrng_fixture_s *otrng_fixture, gconstpointer data) {

  char *message = "And some random invitation text.";
  otrng_notif notif = NOTIF_NONE;

  // builds a query message
  char *query_message = NULL;
  otrng_build_query_message(&query_message, message, otrng_fixture->otr);

  // build an identity message
  otrng_response_s *id_msg = otrng_response_new();
  otrng_fixture->otr->their_instance_tag = 1;
  otrng_receive_message(id_msg, notif, query_message, otrng_fixture->otr);
  free(query_message);
  query_message = NULL;

  // receive the identity message with non-zero their instance tag
  otrng_response_s *auth_msg = otrng_response_new();
  char *to_send = otrng_strdup(id_msg->to_send);
  otrng_receive_message(auth_msg, notif, to_send, otrng_fixture->otr);
  otrng_assert(!auth_msg->to_send);

  free(to_send);
  otrng_response_free(id_msg);
  otrng_response_free(auth_msg);
}

void test_otrng_destroy() {
  otrng_client_state_s *state = otrng_client_state_new(NULL);

  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V4};
  otrng_s *otr = otrng_new(state, policy);

  otrng_destroy(otr);

  otrng_assert(otr->conversation == NULL);
  otrng_assert(otr->keys == NULL);
  otrng_assert(otr->their_client_profile == NULL);
  otrng_assert(otr->v3_conn == NULL);

  free(otr);
  otrng_client_state_free(state);
}

void test_otrng_build_prekey_ensemble() {
  uint8_t long_term_priv[ED448_PRIVATE_BYTES] = {0xA};
  uint8_t shared_prekey_priv[ED448_PRIVATE_BYTES] = {0XF};

  otrng_client_state_s *state = otrng_client_state_new(NULL);
  otrng_client_state_add_private_key_v4(state, long_term_priv);
  otrng_client_state_add_shared_prekey_v4(state, shared_prekey_priv);
  otrng_client_state_add_instance_tag(state, 0x100A0F);

  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V4};
  otrng_s *otr = otrng_new(state, policy);

  prekey_ensemble_s *ensemble = otrng_build_prekey_ensemble(otr);
  otrng_assert(ensemble);
  otrng_assert_is_success(otrng_prekey_ensemble_validate(ensemble));

  // Sends the same stored clients
  otrng_assert_client_profile_eq(ensemble->client_profile,
                                 state->client_profile);
  otrng_assert_prekey_profile_eq(ensemble->prekey_profile,
                                 state->prekey_profile);

  // Stores the same prekey message sent
  // TODO: Assert the instance tag
  // TODO: Assert the private part
  otrng_stored_prekeys_s *stored = state->our_prekeys->data;
  otrng_assert(stored);
  otrng_assert_ec_public_key_eq(ensemble->message->Y, stored->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(ensemble->message->B, stored->our_dh->pub);

  otrng_prekey_ensemble_free(ensemble);
  otrng_free(otr);
  otrng_client_state_free(state);
}

static otrng_shared_session_state_s *
test_get_shared_session_state_cb(const otrng_client_conversation_s *conv) {
  // TODO: assert if the callback receives the conv it should

  otrng_shared_session_state_s *ret =
      malloc(sizeof(otrng_shared_session_state_s));

  ret->identifier1 = otrng_strdup("alice");
  ret->identifier2 = otrng_strdup("bob");
  ret->password = NULL;

  return ret;
}

void test_otrng_invokes_shared_session_state_callbacks(void) {
  otrng_client_state_s *state = otrng_client_state_new(NULL);

  otrng_client_callbacks_p callbacks = {{NULL, // create_privkey
                                         NULL, // create_shared_prekey
                                         NULL, // gone_secure
                                         NULL, // gone_insecure
                                         NULL, // fingerprint_seen
                                         NULL, // fingerprint_seen_v3
                                         NULL, // smp_ask_for_secret
                                         NULL, // smp_ask_for_answer
                                         NULL, // smp_update
                                         NULL, // received_extra_symm_key
                                         &test_get_shared_session_state_cb}};

  state->callbacks = callbacks;

  otrng_s *protocol = set_up(state, ALICE_IDENTITY, 1);

  otrng_shared_session_state_s *session = NULL;

  session = otrng_get_shared_session_state(protocol);
  otrng_assert(session != NULL);
  otrng_assert_cmpmem(session->identifier1, "alice",
                      strlen(session->identifier1));
  otrng_assert_cmpmem(session->identifier2, "bob",
                      strlen(session->identifier2));
  otrng_assert(session->password == NULL);

  free(session->identifier1);
  free(session->identifier2);
  free(session);
  otrng_user_state_free_all(state->user_state);
  otrng_client_state_free_all(state);
  otrng_free_all(protocol);
}

void test_otrng_invokes_null_shared_session_state_callbacks(void) {
  otrng_client_state_s *state = otrng_client_state_new(NULL);
  otrng_s *protocol = set_up(state, ALICE_IDENTITY, 1);
  otrng_shared_session_state_s *session = NULL;

  state->callbacks = NULL;
  session = otrng_get_shared_session_state(protocol);
  otrng_assert(session == NULL);

  otrng_client_callbacks_p callbacks = {{
      NULL, // create_privkey
      NULL, // create_shared_prekey
      NULL, // gone_secure
      NULL, // gone_insecure
      NULL, // fingerprint_seen
      NULL, // fingerprint_seen_v3
      NULL, // smp_ask_for_secret
      NULL, // smp_ask_for_answer
      NULL, // smp_update
      NULL, // received_extra_symm_key
      NULL, // get_shared_session_state
  }};

  state->callbacks = callbacks;
  session = otrng_get_shared_session_state(protocol);
  otrng_assert(session == NULL);

  otrng_user_state_free_all(state->user_state);
  otrng_client_state_free_all(state);
  otrng_free_all(protocol);
}

void test_otrng_generates_shared_session_state_string(void) {
  otrng_shared_session_state_s state1[1];
  state1->identifier1 = otrng_strdup("alice");
  state1->identifier2 = otrng_strdup("bob");
  state1->password = NULL;

  char *state1_str = otrng_generate_session_state_string(state1);
  otrng_assert(state1_str);
  otrng_assert_cmpmem(state1_str, "alicebob", strlen("alicebob"));

  free(state1_str);
  free(state1->identifier1);
  free(state1->identifier2);

  otrng_shared_session_state_s state2[1];
  state2->identifier1 = otrng_strdup("bob");
  state2->identifier2 = otrng_strdup("alice");
  state2->password = NULL;

  char *state2_str = otrng_generate_session_state_string(state2);
  otrng_assert(state2_str);
  otrng_assert_cmpmem(state2_str, "alicebob", strlen("alicebob"));

  free(state2_str);
  free(state2->identifier1);
  free(state2->identifier2);

  otrng_shared_session_state_s state3[1];
  state3->identifier1 = otrng_strdup("bob");
  state3->identifier2 = otrng_strdup("alice");
  state3->password = otrng_strdup("passwd");

  char *state3_str = otrng_generate_session_state_string(state3);
  otrng_assert(state3_str);
  otrng_assert_cmpmem(state3_str, "alicebobpasswd", strlen("alicebobpasswd"));

  free(state3_str);
  free(state3->identifier1);
  free(state3->identifier2);
  free(state3->password);

  char *state4_str = otrng_generate_session_state_string(NULL);
  otrng_assert(state4_str == NULL);

  otrng_shared_session_state_s state4[1];
  state4->identifier1 = otrng_strdup("bob");
  state4->identifier2 = NULL;
  state4->password = NULL;

  otrng_assert(otrng_generate_session_state_string(state4) == NULL);
  free(state4->identifier1);

  otrng_shared_session_state_s state5[1];
  state5->identifier1 = NULL;
  state5->identifier2 = otrng_strdup("bob");
  state5->password = NULL;

  otrng_assert(otrng_generate_session_state_string(state5) == NULL);
  free(state5->identifier2);
}
