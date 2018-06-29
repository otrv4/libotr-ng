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

#include <libotr/privkey.h>
#include <string.h>

#include "../list.h"
#include "../otrng.h"
#include "../str.h"

#define assert_msg_sent(result, to_send)                                       \
  do {                                                                         \
    const otrng_err _result = (result);                                        \
    const char *_to_send = (to_send);                                          \
    otrng_assert_is_success(_result);                                          \
    otrng_assert(_to_send);                                                    \
    otrng_assert_cmpmem("?OTR:AAQD", _to_send, 9);                             \
  } while (0)

#define assert_msg_rec(result, message, response)                              \
  do {                                                                         \
    const otrng_err _result = (result);                                        \
    const char *_message = (message);                                          \
    const otrng_response_s *_response = (response);                            \
    otrng_assert_is_success(_result);                                          \
    otrng_assert_cmpmem(_message, _response->to_display,                       \
                        strlen(_message) + 1);                                 \
    otrng_assert(_response->to_send == NULL);                                  \
  } while (0)

#define assert_rec_msg_in_state(result, respond_to, sender, otr_state,         \
                                send_response)                                 \
  do {                                                                         \
    const otrng_err _result = (result);                                        \
    const otrng_response_s *_respond_to = (respond_to);                        \
    const otrng_s *_sender = (sender);                                         \
    const otrng_state _otr_state = (otr_state);                                \
    const bool _send_response = (send_response);                               \
    otrng_assert_is_success(_result);                                          \
    otrng_assert(!_respond_to->to_display);                                    \
    otrng_assert(_sender->state == _otr_state);                                \
    if (_send_response) {                                                      \
      otrng_assert(_respond_to->to_send);                                      \
    } else {                                                                   \
      otrng_assert(!_respond_to->to_send);                                     \
    }                                                                          \
  } while (0)

static void free_message_and_response(otrng_response_s *response,
                                      string_p *message) {
  otrng_response_free(response);
  free(*message);
  *message = NULL;
}

static int test_should_not_heartbeat(int last_sent) { return 0; }

static int test_should_heartbeat(int last_sent) { return 1; }

static otrng_shared_session_state_s
get_shared_session_state_cb(const otrng_client_conversation_s *conv) {
  otrng_shared_session_state_s ret = {
      .identifier1 = otrng_strdup("alice"),
      .identifier2 = otrng_strdup("bob"),
      .password = NULL,
  };

  return ret;
}

static otrng_client_callbacks_p test_callbacks = {{
    NULL,                         // create_privkey
    NULL,                         // create_shared_prekey
    NULL,                         // gone_secure
    NULL,                         // gone_insecure
    NULL,                         // fingerprint_seen
    NULL,                         // fingerprint_seen_v3
    NULL,                         // smp_ask_for_secret
    NULL,                         // smp_ask_for_answer
    NULL,                         // smp_update
    NULL,                         // received_extra_symm_key
    &get_shared_session_state_cb, // get_shared_session_state
}};

static void set_up_client_state(otrng_client_state_s *state,
                                const char *account_name, int byte) {
  state->account_name = otrng_strdup(account_name);
  state->protocol_name = otrng_strdup("otr");
  state->user_state = otrl_userstate_create();
  state->callbacks = test_callbacks;

  uint8_t long_term_priv[ED448_PRIVATE_BYTES] = {byte + 0xA};
  uint8_t shared_prekey_priv[ED448_PRIVATE_BYTES] = {byte + 0XF};

  otrng_client_state_add_private_key_v4(state, long_term_priv);
  otrng_client_state_add_shared_prekey_v4(state, shared_prekey_priv);
  otrng_client_state_add_instance_tag(state, 0x100 + byte);

  state->should_heartbeat = test_should_not_heartbeat;
}

static otrng_s *set_up(otrng_client_state_s *client_state,
                       const char *account_name, int byte) {
  set_up_client_state(client_state, account_name, byte);
  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V3 | OTRNG_ALLOW_V4};

  return otrng_new(client_state, policy);
}

void test_api_interactive_conversation(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

  otrng_client_state_set_padding(256, alice_client_state);
  otrng_client_state_set_padding(256, bob_client_state);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  int message_id;
  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  otrng_notif notif = NOTIF_NONE;

  string_p to_send = NULL;
  otrng_err result;

  for (message_id = 1; message_id < 4; message_id++) {
    // Alice sends a data message
    result = otrng_send_message(&to_send, "hi", notif, NULL, 0, alice);
    assert_msg_sent(result, to_send);
    otrng_assert(!alice->keys->old_mac_keys);

    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, message_id);
    g_assert_cmpint(alice->keys->k, ==, 0);
    g_assert_cmpint(alice->keys->pn, ==, 0);

    // Alice should not delete priv keys
    otrng_assert_not_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);
    otrng_assert(alice->keys->our_dh->priv);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    result = otrng_receive_message(response_to_alice, notif, to_send, bob);
    assert_msg_rec(result, "hi", response_to_alice);
    otrng_assert(bob->keys->old_mac_keys);

    free_message_and_response(response_to_alice, &to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, message_id);
    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, 0);
    g_assert_cmpint(bob->keys->k, ==, message_id);
    g_assert_cmpint(bob->keys->pn, ==, 0);

    // Bob's priv key should be deleted
    otrng_assert_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);
    otrng_assert(!bob->keys->our_dh->priv);
  }

  // Next message Bob sends is a new DH ratchet
  for (message_id = 1; message_id < 4; message_id++) {
    // Bob sends a data message
    result = otrng_send_message(&to_send, "hello", notif, NULL, 0, bob);
    assert_msg_sent(result, to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

    g_assert_cmpint(bob->keys->i, ==, 2);
    g_assert_cmpint(bob->keys->j, ==, message_id);
    g_assert_cmpint(bob->keys->k, ==, 3);
    g_assert_cmpint(bob->keys->pn, ==, 0);

    // Bob should have a new ECDH priv key but no DH
    otrng_assert_not_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);
    otrng_assert(!bob->keys->our_dh->priv);

    // Alice receives a data message
    response_to_bob = otrng_response_new();
    result = otrng_receive_message(response_to_bob, notif, to_send, alice);
    assert_msg_rec(result, "hello", response_to_bob);
    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, message_id);

    free_message_and_response(response_to_bob, &to_send);

    g_assert_cmpint(alice->keys->i, ==, 2);
    g_assert_cmpint(alice->keys->j, ==, 0);
    g_assert_cmpint(alice->keys->k, ==, message_id);
    g_assert_cmpint(alice->keys->pn, ==, 3);

    // Alice should delete the ECDH priv key but not the DH priv key
    otrng_assert_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);
    otrng_assert(alice->keys->our_dh->priv);
  }

  const size_t secret_len = 2;
  uint8_t secret_data[2] = {0x08, 0x05};

  // Bob sends a message with TLV
  result = otrng_smp_start(&to_send, NULL, 0, secret_data, secret_len, bob);
  assert_msg_sent(result, to_send);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  // Alice receives a data message with TLV
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_bob, notif, to_send, alice));
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 4);

  // Check TLVs
  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->data->type, ==, OTRNG_TLV_SMP_MSG_1);
  g_assert_cmpint(response_to_bob->tlvs->data->len, ==, 342);

  // Check Padding
  otrng_assert(response_to_bob->tlvs->next);
  g_assert_cmpint(response_to_bob->tlvs->next->data->type, ==,
                  OTRNG_TLV_PADDING);

  free_message_and_response(response_to_bob, &to_send);

  // Bob closes the encrypted conversation
  otrng_close(&to_send, bob);
  otrng_assert(bob->state == OTRNG_STATE_START);

  // Alice receives a disconnected TLV from Bob
  response_to_bob = otrng_response_new();
  otrng_receive_message(response_to_bob, notif, to_send, alice);

  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->data->type, ==,
                  OTRNG_TLV_DISCONNECTED);
  otrng_assert(alice->state == OTRNG_STATE_FINISHED);

  free_message_and_response(response_to_bob, &to_send);
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

/* Specifies the behavior of the API for offline messages */
void test_otrng_send_offline_message() {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

  otrng_notif notif = NOTIF_NONE;

  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  prekey_ensemble_s *ensemble = otrng_build_prekey_ensemble(bob);
  otrng_assert(ensemble);
  otrng_assert_is_success(otrng_prekey_ensemble_validate(ensemble));

  g_assert_cmpint(bob->their_prekeys_id, ==, 0);
  otrng_assert(bob->running_version == 0);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  char *to_bob = NULL;
  otrng_assert_is_success(otrng_send_offline_message(&to_bob, ensemble, alice));
  otrng_prekey_ensemble_free(ensemble);

  otrng_assert(to_bob);
  otrng_assert_cmpmem("?OTR:AASN", to_bob, 9);

  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(alice->running_version == 4);

  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives an offline message
  otrng_response_s *resp = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(resp, notif, to_bob, bob));
  free(to_bob);

  otrng_assert(!resp->to_display);
  otrng_assert(!resp->to_send);
  otrng_response_free_all(resp);

  g_assert_cmpint(bob->their_prekeys_id, ==, 0);
  otrng_assert(bob->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(bob->running_version == 4);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  otrng_assert_ec_public_key_eq(bob->keys->their_ecdh,
                                alice->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(bob->keys->their_dh, alice->keys->our_dh->pub);

  // Both have the same shared shared secret/root key
  otrng_assert_root_key_eq(alice->keys->current->root_key,
                           bob->keys->current->root_key);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;

  // Bob sends a data message
  int message_id;
  string_p to_send = NULL;
  otrng_err result;

  for (message_id = 1; message_id < 4; message_id++) {
    result = otrng_send_message(&to_send, "hi", notif, NULL, 0, alice);
    assert_msg_sent(result, to_send);
    otrng_assert(!alice->keys->old_mac_keys);

    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, message_id);
    g_assert_cmpint(alice->keys->k, ==, 0);
    g_assert_cmpint(alice->keys->pn, ==, 0);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    result = otrng_receive_message(response_to_alice, notif, to_send, bob);
    assert_msg_rec(result, "hi", response_to_alice);
    otrng_assert(bob->keys->old_mac_keys);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, message_id);

    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, 0);
    g_assert_cmpint(bob->keys->k, ==, message_id);
    g_assert_cmpint(bob->keys->pn, ==, 0);

    free_message_and_response(response_to_alice, &to_send);
  }

  for (message_id = 1; message_id < 4; message_id++) {
    // Alice sends a data message
    result = otrng_send_message(&to_send, "hello", notif, NULL, 0, bob);
    assert_msg_sent(result, to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);
    g_assert_cmpint(bob->keys->i, ==, 2);
    g_assert_cmpint(bob->keys->j, ==, message_id);
    g_assert_cmpint(bob->keys->k, ==, 3);
    g_assert_cmpint(bob->keys->pn, ==, 0);

    // Bob receives a data message
    response_to_bob = otrng_response_new();
    result = otrng_receive_message(response_to_bob, notif, to_send, alice);
    assert_msg_rec(result, "hello", response_to_bob);
    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, message_id);

    g_assert_cmpint(alice->keys->i, ==, 2);
    g_assert_cmpint(alice->keys->j, ==, 0);
    g_assert_cmpint(alice->keys->k, ==, message_id);
    g_assert_cmpint(alice->keys->pn, ==, 3);

    free_message_and_response(response_to_bob, &to_send);
  }

  const size_t secret_len = 2;
  uint8_t secret_data[2] = {0x08, 0x05};

  // Bob sends a message with TLV
  result = otrng_smp_start(&to_send, NULL, 0, secret_data, secret_len, bob);
  assert_msg_sent(result, to_send);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  // Alice receives a data message with TLV
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_bob, notif, to_send, alice));
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 4);

  // Check TLVS
  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->data->type, ==, OTRNG_TLV_SMP_MSG_1);
  g_assert_cmpint(response_to_bob->tlvs->data->len, ==, 342);

  free_message_and_response(response_to_bob, &to_send);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_conversation_errors_1(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

  // DAKE HAS FINISHED
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;
  otrng_response_s *response_to_bob = NULL;
  otrng_notif notif = NOTIF_NONE;

  string_p to_send = NULL;
  otrng_err result;

  // Alice sends a data message
  result = otrng_send_message(&to_send, "hi", notif, NULL, 0, alice);

  assert_msg_sent(result, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // To trigger the error message
  bob->state = OTRNG_STATE_START;

  // Bob receives a data message in the incorrect state
  response_to_alice = otrng_response_new();
  otrng_assert_is_error(
      otrng_receive_message(response_to_alice, notif, to_send, bob));

  const string_p err_code =
      "?OTR Error: ERROR_2: OTRNG_ERR_MSG_NOT_PRIVATE_STATE";
  otrng_assert_cmpmem(err_code, response_to_alice->to_send, strlen(err_code));

  otrng_assert(response_to_alice->to_send != NULL);
  otrng_assert(!bob->keys->old_mac_keys);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  response_to_bob = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, notif, response_to_alice->to_send, alice));
  const string_p err_human = "Not in private state message";

  otrng_assert(response_to_bob);
  otrng_assert_cmpmem(err_human, response_to_bob->to_display,
                      strlen(err_human));

  otrng_response_free(response_to_alice);
  otrng_response_free(response_to_bob);
  free(to_send);
  to_send = NULL;

  // Alice sends another data message
  result = otrng_send_message(&to_send, "hi", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  bob->state = OTRNG_STATE_ENCRYPTED_MESSAGES;
  bob->keys->j = 15;

  // Bob receives a non valid data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send, bob);

  // otrng_assert(result == MSG_NOT_VALID);
  otrng_assert(response_to_alice->to_send == NULL);
  otrng_assert(response_to_alice->warning == OTRNG_WARN_RECEIVED_NOT_VALID);

  free_message_and_response(response_to_alice, &to_send);
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_conversation_errors_2(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_s *alice = set_up(alice_client_state, BOB_IDENTITY, 2);

  otrng_response_s *response = otrng_response_new();
  otrng_notif notif = NOTIF_NONE;

  otrng_assert(alice->state == OTRNG_STATE_START);

  const char *malformed =
      "?OTR:AAQIAAAAAAAAAAAAAAEBAAABAgAQXaS4pTGfRolFC5WuliYvxJJcwqpOQeeO4/"
      "1zoKokDoUE/"
      "OnFdvBBv09zDtDvneIbzfs56QHpWGuAAAAAAzM0AAAAAABbSMuiJZfVAhREsc6c6WG7NSVNN"
      "F58mInKArRia8avA5ZazE7HUNkZ8BWPsouNbLoTYTxViDtavlEpHfCAOqsXGRwAO0H/"
      "kQNgRJr2ZWTF1AEs1BHP7r+tu/muOUx/7wqh/"
      "itf9au4j3LO5b1AMCV5tIIpmQcAAAAAAIyDWg5gjDdOL+yYsZs1QdRaNWf6Bb+"
      "t3R6XAd3kv+AFibvTomYi/OL8j3eM65prcjSOMIDJMbxigAAAAYAPNegWVf5E9/"
      "rOgH48feVb3m3EP3L0Ln6lgNdcxATBI6AmqvJwYaTwrDGnhOggj6PUC/USidH/"
      "pUQ2Ht7QnSVqFEgxCttt/"
      "oRtcd7oiso9wYEgcMQrToZLF3URJEQUFC6TzyCkPPOcoSGCAkJvqpgwp6xCHza7qvFGvlsE4"
      "RUNj5/09SU0GDIvZkROwmMa14OlHu0Zb84ttyicohcxGmOdTi/c4XPVu5NO2vc/j/"
      "Px28qWCFy8ZdUdKN1QFhrtU/y2K0jcFsvifJmc1puBjoQvbg51s/"
      "M9+LNDJhJUN4OUMybqTpnztt2+Jl8FFV+Wg8f6E52gM4rODoc4NWatDc+t9p+"
      "SiqbSKueci04yIue+5N057t7TT0nh9WEZnom3gbwkmS6b4yz/"
      "xSssNlgx1+Tnk3oXiJO+SO8znlZ6lkxmhZgrqG1u8abBO9YG6DC4gz9s3sBCJDA+"
      "eF08cb9C7RwGpebYgJMNZ3PgwVy6s6H5yoD0c2PcqF50hspJu+2oA1A=.";

  // Alice receives malformed Identity message
  otrng_assert_is_error(
      otrng_receive_message(response, notif, malformed, alice));
  const string_p err_code = "?OTR Error: ERROR_4: OTRNG_ERR_MALFORMED";
  otrng_assert_cmpmem(err_code, response->to_send, strlen(err_code));

  // TODO: everything from here should be a separate test:
  // For example, otrng_test_receive_error_message.

  // Alice receives an error message
  // otrng_assert_is_success(otrng_receive_message(
  //    response_to_bob, notif, response_to_alice->to_send, alice));

  // otrng_assert(response_to_bob);
  // const string_p err_human = "Malformed message";
  // otrng_assert_cmpmem(err_human, response_to_bob->to_display,
  //                    strlen(err_human));

  // free(response_to_alice->to_send);
  // response_to_alice->to_send = NULL;

  otrng_response_free(response);

  otrng_user_state_free_all(alice_client_state->user_state);
  otrng_client_state_free_all(alice_client_state);
  otrng_free_all(alice);
}

static void do_ake_v3(otrng_s *alice, otrng_s *bob) {
  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();
  otrng_notif notif = NOTIF_NONE;

  // Alice sends query message
  string_p query_message = NULL;
  otrng_assert_is_success(otrng_build_query_message(&query_message, "", alice));
  otrng_assert_cmpmem("?OTRv3", query_message, 6);

  // Bob receives query message
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, notif, query_message, bob));
  free(query_message);
  query_message = NULL;

  // Should reply with a DH-Commit
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAMC", response_to_alice->to_send, 9);

  // Alice receives DH-Commit
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, notif, response_to_alice->to_send, alice));
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Should reply with a DH Key
  otrng_assert(response_to_bob->to_display == NULL);
  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAMK", response_to_bob->to_send, 9);

  // Bob receives a DH Key
  otrng_assert_is_success(otrng_receive_message(response_to_alice, notif,
                                                response_to_bob->to_send, bob));
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  // Bob should reply with a Reveal Sig
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAMR", response_to_alice->to_send, 9);

  // Alice receives Reveal Sig
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, notif, response_to_alice->to_send, alice));
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Should reply with a Sig
  otrng_assert(response_to_bob->to_display == NULL);
  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAMS", response_to_bob->to_send, 9);

  // Alice should be encrypted
  g_assert_cmpint(OTRL_MSGSTATE_ENCRYPTED, ==, alice->v3_conn->ctx->msgstate);

  // Bob receives a Sig
  otrng_assert_is_success(otrng_receive_message(response_to_alice, notif,
                                                response_to_bob->to_send, bob));
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  // Bob should NOT reply
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(!response_to_alice->to_send);

  // Alice should be encrypted
  g_assert_cmpint(OTRL_MSGSTATE_ENCRYPTED, ==, bob->v3_conn->ctx->msgstate);

  otrng_response_free_all(response_to_alice, response_to_bob);
}

void test_api_conversation_v3(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  set_up_client_state(alice_client_state, ALICE_IDENTITY, 1);

  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);
  set_up_client_state(bob_client_state, BOB_IDENTITY, 2);

  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V3};
  otrng_s *alice = otrng_new(alice_client_state, policy);
  otrng_s *bob = otrng_new(bob_client_state, policy);

  // Set up v3 context
  alice->v3_conn = otrng_v3_conn_new(alice_client_state, "bob");
  bob->v3_conn = otrng_v3_conn_new(bob_client_state, "alice");

  // Generate long term private key.
  FILE *tmpFILEp;
  tmpFILEp = tmpfile();
  otrng_assert(!otrl_privkey_generate_FILEp(
      alice_client_state->user_state, tmpFILEp,
      alice_client_state->account_name, alice_client_state->protocol_name));
  fclose(tmpFILEp);

  tmpFILEp = tmpfile();
  otrng_assert(!otrl_privkey_generate_FILEp(
      bob_client_state->user_state, tmpFILEp, bob_client_state->account_name,
      bob_client_state->protocol_name));
  fclose(tmpFILEp);

  // Generate instance tag
  otrng_client_state_add_instance_tag(alice_client_state, 0x100 + 1);
  otrng_client_state_add_instance_tag(bob_client_state, 0x100 + 2);

  // AKE HAS FINISHED.
  do_ake_v3(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  string_p to_send = NULL;
  otrng_notif notif = NOTIF_NONE;

  // Alice sends a data message
  otrng_assert_is_success(
      otrng_send_message(&to_send, "hi", notif, NULL, 0, alice));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, notif, to_send, bob));

  otrng_assert(response_to_alice->to_display);
  otrng_assert_cmpmem("hi", response_to_alice->to_display, 3);
  otrng_assert(!response_to_alice->to_send);
  free_message_and_response(response_to_alice, &to_send);

  // Bob sends a data message
  otrng_assert_is_success(
      otrng_send_message(&to_send, "hi", notif, NULL, 0, bob));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_bob, notif, to_send, alice));

  otrng_assert(response_to_bob->to_display);
  otrng_assert_cmpmem("hi", response_to_bob->to_display, 3);
  otrng_assert(!response_to_bob->to_send);
  free_message_and_response(response_to_bob, &to_send);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_free_all(alice, bob);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
}

void test_api_multiple_clients(void) {
  int send_response = 1;
  otrng_err result;

  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_phone_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_pc_state = otrng_client_state_new(NULL);

  // The account name should be the same. The account can be logged
  // on different clients. Instance tags are used for that. This
  // account name can be used as phi.
  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob_phone = set_up(bob_phone_state, BOB_IDENTITY, 2);
  otrng_s *bob_pc = set_up(bob_pc_state, BOB_IDENTITY, 3);

  otrng_response_s *pc_to_alice = otrng_response_new();
  otrng_response_s *phone_to_alice = otrng_response_new();
  otrng_response_s *alice_to_pc = otrng_response_new();
  otrng_response_s *alice_to_phone = otrng_response_new();
  otrng_notif notif = NOTIF_NONE;

  string_p query_message = NULL;

  // Alice sends a query message
  otrng_assert_is_success(
      otrng_build_query_message(&query_message, "?OTRv4", alice));
  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert_cmpmem("?OTRv4", query_message, 6);

  // PC receives query msg and sends identity msg
  result = otrng_receive_message(pc_to_alice, notif, query_message, bob_pc);
  assert_rec_msg_in_state(result, pc_to_alice, bob_pc,
                          OTRNG_STATE_WAITING_AUTH_R, send_response);

  // PHONE receives query msg and sends identity msg
  result =
      otrng_receive_message(phone_to_alice, notif, query_message, bob_phone);
  assert_rec_msg_in_state(result, phone_to_alice, bob_phone,
                          OTRNG_STATE_WAITING_AUTH_R, send_response);

  free(query_message);

  // ALICE receives Identity msg from PC and sends AUTH-R
  result =
      otrng_receive_message(alice_to_pc, notif, pc_to_alice->to_send, alice);
  assert_rec_msg_in_state(result, alice_to_pc, alice,
                          OTRNG_STATE_WAITING_AUTH_I, send_response);
  otrng_response_free(pc_to_alice);

  // ALICE receives Identity msg from PHONE (on state
  // OTRNG_STATE_WAITING_AUTH_I) and sends AUTH-R. ALICE will replace keys and
  // profile info from PC with info from PHONE.
  result = otrng_receive_message(alice_to_phone, notif, phone_to_alice->to_send,
                                 alice);
  assert_rec_msg_in_state(result, alice_to_phone, alice,
                          OTRNG_STATE_WAITING_AUTH_I, send_response);
  otrng_response_free(phone_to_alice);

  // PC receives Auth-R succesfully and sends an Auth-I
  pc_to_alice = otrng_response_new();
  result =
      otrng_receive_message(pc_to_alice, notif, alice_to_pc->to_send, bob_pc);
  assert_rec_msg_in_state(result, pc_to_alice, bob_pc,
                          OTRNG_STATE_ENCRYPTED_MESSAGES, send_response);

  // PC generates the first keys after Auth-R has been received
  otrng_assert(bob_pc->keys->our_dh->pub);
  otrng_assert(bob_pc->keys->our_dh->priv);
  otrng_assert_not_zero(bob_pc->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob_pc->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // PHONE receives Auth-R with PC instance tag - Ignores
  phone_to_alice = otrng_response_new();
  result = otrng_receive_message(phone_to_alice, notif, alice_to_pc->to_send,
                                 bob_phone);
  assert_rec_msg_in_state(result, phone_to_alice, bob_phone,
                          OTRNG_STATE_WAITING_AUTH_R, !send_response);
  otrng_response_free_all(phone_to_alice, alice_to_pc);

  otrng_assert(bob_phone->keys->our_dh->pub);
  otrng_assert(bob_phone->keys->our_dh->priv);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // ALICE receives Auth-I from PC - Authentication fails
  alice_to_pc = otrng_response_new();
  result =
      otrng_receive_message(alice_to_pc, notif, pc_to_alice->to_send, alice);

  assert_rec_msg_in_state(!result, alice_to_pc, alice,
                          OTRNG_STATE_WAITING_AUTH_I, !send_response);

  otrng_response_free_all(pc_to_alice, alice_to_pc);

  // PC receives Auth-R again - ignores
  pc_to_alice = otrng_response_new();
  result = otrng_receive_message(pc_to_alice, notif, alice_to_phone->to_send,
                                 bob_pc);
  assert_rec_msg_in_state(result, pc_to_alice, bob_pc,
                          OTRNG_STATE_ENCRYPTED_MESSAGES, !send_response);
  otrng_response_free(pc_to_alice);

  // PHONE receives correct Auth-R message and sends Auth-I
  phone_to_alice = otrng_response_new();
  result = otrng_receive_message(phone_to_alice, notif, alice_to_phone->to_send,
                                 bob_phone);
  assert_rec_msg_in_state(result, phone_to_alice, bob_phone,
                          OTRNG_STATE_ENCRYPTED_MESSAGES, send_response);
  otrng_response_free(alice_to_phone);

  // PHONE generates the first keys after Auth-R has been received
  otrng_assert(bob_phone->keys->our_dh->pub);
  otrng_assert(bob_phone->keys->our_dh->priv);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // ALICE receives Auth-I from PHONE
  alice_to_phone = otrng_response_new();
  result = otrng_receive_message(alice_to_phone, notif, phone_to_alice->to_send,
                                 alice);
  assert_rec_msg_in_state(result, alice_to_phone, alice,
                          OTRNG_STATE_ENCRYPTED_MESSAGES, !send_response);

  // ALICE and PHONE have the same shared secret
  otrng_assert_root_key_eq(alice->keys->current->root_key,
                           bob_phone->keys->current->root_key);

  otrng_response_free_all(phone_to_alice, alice_to_phone);
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_phone_state->user_state,
                            bob_pc_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_pc_state,
                              bob_phone_state);
  otrng_free_all(alice, bob_pc, bob_phone);
}

void test_api_smp(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state_expect, ==, '1');
  g_assert_cmpint(bob->smp->state_expect, ==, '1');

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  string_p to_send = NULL;
  const char *secret = "secret";
  otrng_notif notif = NOTIF_NONE;

  // Alice sends SMP1
  otrng_assert_is_success(otrng_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                                          strlen(secret), alice));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1
  g_assert_cmpint(alice->smp->state_expect, ==, '2');

  // Bob receives SMP1
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, notif, to_send, bob));
  otrng_assert(!response_to_alice->to_send);

  free_message_and_response(response_to_alice, &to_send);

  // This will be called by Bob when the OTRNG_SMPEVENT_ASK_FOR_SECRET is
  // triggered.
  otrng_assert_is_success(
      otrng_smp_continue(&to_send, (uint8_t *)secret, strlen(secret), bob));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP2
  g_assert_cmpint(bob->smp->state_expect, ==, '3');

  // Alice receives SMP2
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_bob, notif, to_send, alice));

  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9); // SMP3

  free(to_send);
  to_send = NULL;

  // Bob receives SMP3
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(response_to_alice, notif,
                                                response_to_bob->to_send, bob));
  otrng_response_free(response_to_bob);

  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAQD", response_to_alice->to_send, 9); // SMP4
  g_assert_cmpint(alice->smp->state_expect, ==, '4');

  // Alice receives SMP4
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, notif, response_to_alice->to_send, alice));
  otrng_response_free(response_to_alice);

  g_assert_cmpint(bob->smp->state_expect, ==, '1');
  g_assert_cmpint(alice->smp->state_expect, ==, '1');

  otrng_assert(!response_to_bob->to_send);

  otrng_response_free(response_to_bob);
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_smp_abort(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state_expect, ==, '1');
  g_assert_cmpint(bob->smp->state_expect, ==, '1');

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  string_p to_send = NULL;
  const char *secret = "secret";
  otrng_notif notif = NOTIF_NONE;

  // Alice sends SMP1
  otrng_assert_is_success(otrng_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                                          strlen(secret), alice));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1
  g_assert_cmpint(alice->smp->state_expect, ==, '2');

  // Bob receives SMP1
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, notif, to_send, bob));

  otrng_assert(!response_to_alice->to_send);
  free_message_and_response(response_to_alice, &to_send);

  // Bob sends SMP Abort
  otrng_assert_is_success(otrng_smp_abort(&to_send, bob));
  g_assert_cmpint(bob->smp->state_expect, ==, '1');

  // Alice receives SMP ABORT
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_bob, notif, to_send, alice));

  otrng_assert(!response_to_bob->to_send);
  g_assert_cmpint(alice->smp->state_expect, ==, '1');

  free_message_and_response(response_to_bob, &to_send);

  // Bob restarts and sends SMP 1
  otrng_assert_is_success(otrng_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                                          strlen(secret), bob));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1
  g_assert_cmpint(bob->smp->state_expect, ==, '2');

  free(to_send);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_extra_sym_key(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;

  // Alice sends a data message
  string_p to_send = NULL;
  otrng_notif notif = NOTIF_NONE;
  otrng_err result;

  result = otrng_send_message(&to_send, "hi", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  // This is a follow up message.
  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);

  free_message_and_response(response_to_alice, &to_send);

  uint16_t tlv_len = 6;
  uint8_t tlv_data[6] = {0x08, 0x05, 0x09, 0x00, 0x02, 0x04};
  // Bob sends a message with TLV
  int use = 134547712;
  uint8_t usedata[2] = {0x02, 0x04};
  uint16_t usedatalen = 2;
  result = otrng_send_symkey_message(&to_send, use, usedata, usedatalen,
                                     bob->keys->extra_symmetric_key, bob);
  assert_msg_sent(result, to_send);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  // Alice receives a data message with TLV
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_bob, notif, to_send, alice));
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 1);

  // Check TLVS
  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->data->type, ==, OTRNG_TLV_SYM_KEY);
  g_assert_cmpint(response_to_bob->tlvs->data->len, ==, tlv_len);
  otrng_assert_cmpmem(response_to_bob->tlvs->data->data, tlv_data, tlv_len);

  otrng_assert(!response_to_bob->tlvs->next);

  free_message_and_response(response_to_bob, &to_send);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_heartbeat_messages(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

  alice_client_state->should_heartbeat = test_should_heartbeat;
  bob_client_state->should_heartbeat = test_should_heartbeat;

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;
  otrng_response_s *response_to_bob = NULL;

  // Alice sends a data message
  string_p to_send = NULL;
  otrng_notif notif = NOTIF_NONE;
  otrng_err result;

  result = otrng_send_message(&to_send, "hi", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  alice->last_sent = time(NULL) - 60;

  // This is a follow up message.
  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // Bob receives a data message
  // Bob sends a heartbeat message
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, notif, to_send, bob));
  otrng_assert(!bob->keys->old_mac_keys);
  otrng_assert_cmpmem("hi", response_to_alice->to_display, strlen("hi") + 1);
  otrng_assert(response_to_alice->to_send != NULL);
  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 1);

  free(to_send);

  // Alice receives the heatbeat message. Let's force this.
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, notif, response_to_alice->to_send, alice));
  otrng_assert(alice->keys->old_mac_keys);
  otrng_assert(!response_to_bob->to_display);
  otrng_assert(!response_to_bob->to_send);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->ignore_msg, ==, 1);

  otrng_response_free(response_to_alice);
  otrng_response_free(response_to_bob);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}
