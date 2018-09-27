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

#ifndef S_SPLINT_S
#include <libotr/b64.h>
#include <libotr/privkey.h>
#endif

#include <string.h>
#include <glib.h>

#include "test_helpers.h"
#include "test_fixtures.h"
#include "list.h"
#include "otrng.h"
#include "str.h"


static otrng_bool test_should_heartbeat(int last_sent) {
  (void)last_sent;
  return otrng_true;
}

static void test_api_interactive_conversation(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  otrng_client_set_padding(256, alice_client);
  otrng_client_set_padding(256, bob_client);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  int message_id;
  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  otrng_warning warn = OTRNG_WARN_NONE;

  string_p to_send = NULL;
  otrng_result result;

  for (message_id = 1; message_id < 4; message_id++) {
    // Alice sends a data message
    result = otrng_send_message(&to_send, "hi", &warn, NULL, 0, alice);
    assert_msg_sent(result, to_send);
    otrng_assert(!alice->keys->old_mac_keys);

    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, message_id + 1);
    g_assert_cmpint(alice->keys->k, ==, 0);
    g_assert_cmpint(alice->keys->pn, ==, 0);

    // Alice should not delete priv keys
    otrng_assert_not_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);
    otrng_assert(alice->keys->our_dh->priv);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    result = otrng_receive_message(response_to_alice, &warn, to_send, bob);
    assert_msg_rec(result, "hi", response_to_alice);
    otrng_assert(bob->keys->old_mac_keys);

    free_message_and_response(response_to_alice, &to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==,
                    message_id + 1);
    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, 0);
    g_assert_cmpint(bob->keys->k, ==, message_id + 1);
    g_assert_cmpint(bob->keys->pn, ==, 0);

    // Bob's priv key should be deleted
    otrng_assert_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);
    otrng_assert(!bob->keys->our_dh->priv);
  }

  // Next message Bob sends is a new DH ratchet
  for (message_id = 1; message_id < 4; message_id++) {
    // Bob sends a data message
    result = otrng_send_message(&to_send, "hello", &warn, NULL, 0, bob);
    assert_msg_sent(result, to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

    g_assert_cmpint(bob->keys->i, ==, 2);
    g_assert_cmpint(bob->keys->j, ==, message_id);
    g_assert_cmpint(bob->keys->k, ==, 4);
    g_assert_cmpint(bob->keys->pn, ==, 0);

    // Bob should have a new ECDH priv key but no DH
    otrng_assert_not_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);
    otrng_assert(!bob->keys->our_dh->priv);

    // Alice receives a data message
    response_to_bob = otrng_response_new();
    result = otrng_receive_message(response_to_bob, &warn, to_send, alice);
    assert_msg_rec(result, "hello", response_to_bob);
    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, message_id);

    free_message_and_response(response_to_bob, &to_send);

    g_assert_cmpint(alice->keys->i, ==, 2);
    g_assert_cmpint(alice->keys->j, ==, 0);
    g_assert_cmpint(alice->keys->k, ==, message_id);
    g_assert_cmpint(alice->keys->pn, ==, 4);

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
      otrng_receive_message(response_to_bob, &warn, to_send, alice));
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
  otrng_receive_message(response_to_bob, &warn, to_send, alice);

  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->data->type, ==,
                  OTRNG_TLV_DISCONNECTED);
  otrng_assert(alice->state == OTRNG_STATE_FINISHED);

  free_message_and_response(response_to_bob, &to_send);
  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

/* Specifies the behavior of the API for offline messages */
static void test_otrng_send_offline_message() {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  otrng_warning warn = OTRNG_WARN_NONE;

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
  // TODO: @non_interactive should this validation happen outside?
  otrng_assert_is_success(otrng_prekey_ensemble_validate(ensemble));

  g_assert_cmpint(bob->their_prekeys_id, ==, 0);
  otrng_assert(bob->running_version == 0);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  char *to_bob = NULL;
  otrng_assert_is_success(
      otrng_send_non_interactive_auth(&to_bob, ensemble, alice));
  otrng_prekey_ensemble_free(ensemble);

  otrng_assert(to_bob);
  otrng_assert_cmpmem("?OTR:AAQN", to_bob, 9);

  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(alice->running_version == 4);

  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives an offline message
  otrng_response_s *response = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(response, &warn, to_bob, bob));
  free(to_bob);

  otrng_assert(!response->to_display);
  otrng_assert(!response->to_send);
  otrng_response_free_all(response);

  g_assert_cmpint(bob->their_prekeys_id, ==, 0);
  otrng_assert(bob->state == OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE);
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
  otrng_result result;

  for (message_id = 1; message_id < 4; message_id++) {
    result = otrng_send_message(&to_send, "hi", &warn, NULL, 0, alice);
    assert_msg_sent(result, to_send);
    otrng_assert(!alice->keys->old_mac_keys);

    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, message_id);
    g_assert_cmpint(alice->keys->k, ==, 0);
    g_assert_cmpint(alice->keys->pn, ==, 0);

    // Alice receives a data message
    response_to_alice = otrng_response_new();
    result = otrng_receive_message(response_to_alice, &warn, to_send, bob);
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
    result = otrng_send_message(&to_send, "hello", &warn, NULL, 0, bob);
    assert_msg_sent(result, to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);
    g_assert_cmpint(bob->keys->i, ==, 2);
    g_assert_cmpint(bob->keys->j, ==, message_id);
    g_assert_cmpint(bob->keys->k, ==, 3);
    g_assert_cmpint(bob->keys->pn, ==, 0);

    // Bob receives a data message
    response_to_bob = otrng_response_new();
    result = otrng_receive_message(response_to_bob, &warn, to_send, alice);
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
      otrng_receive_message(response_to_bob, &warn, to_send, alice));
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 4);

  // Check TLVS
  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->data->type, ==, OTRNG_TLV_SMP_MSG_1);
  g_assert_cmpint(response_to_bob->tlvs->data->len, ==, 342);

  free_message_and_response(response_to_bob, &to_send);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

static void test_otrng_incorrect_offline_dake() {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  otrng_warning warn = OTRNG_WARN_NONE;

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
  // TODO: @non_interactive should this validation happen outside?
  otrng_assert_is_success(otrng_prekey_ensemble_validate(ensemble));

  g_assert_cmpint(bob->their_prekeys_id, ==, 0);
  otrng_assert(bob->running_version == 0);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  char *to_bob = NULL;
  otrng_assert_is_success(
      otrng_send_non_interactive_auth(&to_bob, ensemble, alice));
  otrng_prekey_ensemble_free(ensemble);

  otrng_assert(to_bob);
  otrng_assert_cmpmem("?OTR:AAQN", to_bob, 9);
  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(alice->running_version == 4);

  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives an offline message
  otrng_response_s *response = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(response, &warn, to_bob, bob));
  free(to_bob);

  otrng_assert(!response->to_display);
  otrng_assert(!response->to_send);
  otrng_response_free_all(response);

  g_assert_cmpint(bob->their_prekeys_id, ==, 0);
  otrng_assert(bob->state == OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE);
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

  string_p to_send = NULL;
  otrng_result result;

  // Alice is unable to send a data msg
  result = otrng_send_message(&to_send, "hi", &warn, NULL, 0, bob);
  otrng_assert_is_error(result);
  otrng_assert(!to_send);
  g_assert_cmpint(warn, ==, OTRNG_WARN_SEND_NOT_ENCRYPTED);

  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

static void test_api_conversation_errors_1(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  // DAKE HAS FINISHED
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;
  otrng_response_s *response_to_bob = NULL;
  otrng_warning warn = OTRNG_WARN_NONE;

  string_p to_send = NULL;
  otrng_result result;

  // Alice sends a data message
  result = otrng_send_message(&to_send, "hi", &warn, NULL, 0, alice);

  assert_msg_sent(result, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);

  // To trigger the error message
  bob->state = OTRNG_STATE_START;

  // Bob receives a data message in the incorrect state
  response_to_alice = otrng_response_new();
  otrng_assert_is_error(
      otrng_receive_message(response_to_alice, &warn, to_send, bob));

  const string_p err_code =
      "?OTR Error: ERROR_2: OTRNG_ERR_MSG_NOT_PRIVATE_STATE";
  otrng_assert_cmpmem(err_code, response_to_alice->to_send, strlen(err_code));

  otrng_assert(response_to_alice->to_send != NULL);
  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);

  response_to_bob = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, &warn, response_to_alice->to_send, alice));

  const string_p err_human = "Not in private state message";
  otrng_assert(response_to_bob);
  otrng_assert_cmpmem(err_human, response_to_bob->to_display,
                      strlen(err_human));

  otrng_response_free(response_to_alice);
  otrng_response_free(response_to_bob);
  free(to_send);
  to_send = NULL;

  // Alice sends another data message
  result = otrng_send_message(&to_send, "hi", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  // Restore Bob's state
  bob->state = OTRNG_STATE_ENCRYPTED_MESSAGES;

  // Corrupt message
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  otrl_base64_otr_decode(to_send, &decoded, &dec_len);
  free(to_send);

  decoded[dec_len - 1] = decoded[dec_len - 1] + 3;
  to_send = otrl_base64_otr_encode(decoded, dec_len);
  free(decoded);

  // Bob receives a non valid data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send, bob);

  // otrng_assert(result == MSG_NOT_VALID);
  otrng_assert(response_to_alice->to_send == NULL);
  otrng_assert(response_to_alice->warning == OTRNG_WARN_RECEIVED_NOT_VALID);

  free_message_and_response(response_to_alice, &to_send);
  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

static void test_api_conversation_errors_2(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();
  otrng_warning warn = OTRNG_WARN_NONE;

  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert(bob->state == OTRNG_STATE_START);

  const char *malformed =
      "?OTR:AAQ1AAAAAAAAAAAAAAEBAAABAgAQXaS4pTGfRolFC5WuliYvxJJcwqpOQeeO4/"
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
      otrng_receive_message(response_to_alice, &warn, malformed, alice));
  const string_p err_code = "?OTR Error: ERROR_4: OTRNG_ERR_MALFORMED";
  otrng_assert_cmpmem(err_code, response_to_alice->to_send, strlen(err_code));

  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, &warn, response_to_alice->to_send, alice));

  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Bob receives an error message
  otrng_assert(response_to_bob);
  const string_p err_human = "Malformed message";
  otrng_assert_cmpmem(err_human, response_to_bob->to_display,
                      strlen(err_human));

  otrng_response_free(response_to_alice);
  otrng_response_free(response_to_bob);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

static void do_ake_v3(otrng_s *alice, otrng_s *bob) {
  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();
  otrng_warning warn = OTRNG_WARN_NONE;

  // Alice sends query message
  string_p query_message = NULL;
  otrng_assert_is_success(otrng_build_query_message(&query_message, "", alice));
  otrng_assert_cmpmem("?OTRv3", query_message, 6);

  // Bob receives query message
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, &warn, query_message, bob));
  free(query_message);
  query_message = NULL;

  // Should reply with a DH-Commit
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAMC", response_to_alice->to_send, 9);

  // Alice receives DH-Commit
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, &warn, response_to_alice->to_send, alice));
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Should reply with a DH Key
  otrng_assert(response_to_bob->to_display == NULL);
  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAMK", response_to_bob->to_send, 9);

  // Bob receives a DH Key
  otrng_assert_is_success(otrng_receive_message(response_to_alice, &warn,
                                                response_to_bob->to_send, bob));
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  // Bob should reply with a Reveal Sig
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAMR", response_to_alice->to_send, 9);

  // Alice receives Reveal Sig
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, &warn, response_to_alice->to_send, alice));
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Should reply with a Sig
  otrng_assert(response_to_bob->to_display == NULL);
  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAMS", response_to_bob->to_send, 9);

  // Alice should be encrypted
  g_assert_cmpint(OTRL_MSGSTATE_ENCRYPTED, ==, alice->v3_conn->ctx->msgstate);

  // Bob receives a Sig
  otrng_assert_is_success(otrng_receive_message(response_to_alice, &warn,
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

static void test_api_conversation_v3(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  set_up_client(alice_client, ALICE_ACCOUNT, 1);
  set_up_client(bob_client, BOB_ACCOUNT, 2);

  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V3};
  otrng_s *alice = otrng_new(alice_client, policy);
  otrng_s *bob = otrng_new(bob_client, policy);

  // Set up v3 context
  // TODO: This initialization should be automatic
  alice->v3_conn = otrng_v3_conn_new(alice_client, "bob");
  bob->v3_conn = otrng_v3_conn_new(bob_client, "alice");
  alice->v3_conn->opdata = alice;
  bob->v3_conn->opdata = bob;

  // Generate long term private key.
  // TODO: use callback?
  FILE *tmpFILEp = tmpfile();
  otrng_assert_is_success(
      otrng_client_private_key_v3_write_FILEp(alice_client, tmpFILEp));
  fclose(tmpFILEp);

  tmpFILEp = tmpfile();

  otrng_assert_is_success(
      otrng_client_private_key_v3_write_FILEp(bob_client, tmpFILEp));
  fclose(tmpFILEp);

  // Generate instance tag
  // TODO: use callback?
  otrng_client_add_instance_tag(alice_client, 0x100 + 1);
  otrng_client_add_instance_tag(bob_client, 0x100 + 2);

  // AKE HAS FINISHED.
  do_ake_v3(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  string_p to_send = NULL;
  otrng_warning warn = OTRNG_WARN_NONE;

  // Alice sends a data message
  otrng_assert_is_success(
      otrng_send_message(&to_send, "hi", &warn, NULL, 0, alice));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, &warn, to_send, bob));

  otrng_assert(response_to_alice->to_display);
  otrng_assert_cmpmem("hi", response_to_alice->to_display, 3);
  otrng_assert(!response_to_alice->to_send);
  free_message_and_response(response_to_alice, &to_send);

  // Bob sends a data message
  otrng_assert_is_success(
      otrng_send_message(&to_send, "hi", &warn, NULL, 0, bob));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_bob, &warn, to_send, alice));

  otrng_assert(response_to_bob->to_display);
  otrng_assert_cmpmem("hi", response_to_bob->to_display, 3);
  otrng_assert(!response_to_bob->to_send);
  free_message_and_response(response_to_bob, &to_send);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_free_all(alice, bob);
  otrng_client_free_all(alice_client, bob_client);
}

static void test_api_multiple_clients(void) {
  otrng_bool send_response = otrng_true;
  otrng_result result;

  // TODO: The next comment is WRONG.
  // There should be 2 separate protocols, one for each instance tag
  // Alice has seen for Bob.
  // We will postpone fixing this test until we implement this behavior.
  return;

  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_phone_state = otrng_client_new(BOB_IDENTITY);
  otrng_client_s *bob_pc_state = otrng_client_new(BOB_IDENTITY);

  // The account name should be the same. The account can be logged
  // on different clients. Instance tags are used for that. This
  // account name can be used as phi.
  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob_phone = set_up(bob_phone_state, BOB_ACCOUNT, 2);
  otrng_s *bob_pc = set_up(bob_pc_state, BOB_ACCOUNT, 3);

  otrng_response_s *pc_to_alice = otrng_response_new();
  otrng_response_s *phone_to_alice = otrng_response_new();
  otrng_response_s *alice_to_pc = otrng_response_new();
  otrng_response_s *alice_to_phone = otrng_response_new();
  otrng_warning warn = OTRNG_WARN_NONE;

  string_p query_message = NULL;

  // Alice sends a query message
  otrng_assert_is_success(
      otrng_build_query_message(&query_message, "?OTRv4", alice));
  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert_cmpmem("?OTRv4", query_message, 6);

  // PC receives query msg and sends identity msg
  result = otrng_receive_message(pc_to_alice, &warn, query_message, bob_pc);
  assert_rec_msg_in_state(result, pc_to_alice, bob_pc,
                          OTRNG_STATE_WAITING_AUTH_R, send_response);

  // PHONE receives query msg and sends identity msg
  result =
      otrng_receive_message(phone_to_alice, &warn, query_message, bob_phone);
  assert_rec_msg_in_state(result, phone_to_alice, bob_phone,
                          OTRNG_STATE_WAITING_AUTH_R, send_response);

  free(query_message);

  // ALICE receives Identity msg from PC and sends AUTH-R
  result =
      otrng_receive_message(alice_to_pc, &warn, pc_to_alice->to_send, alice);
  assert_rec_msg_in_state(result, alice_to_pc, alice,
                          OTRNG_STATE_WAITING_AUTH_I, send_response);
  otrng_response_free(pc_to_alice);

  // ALICE receives Identity msg from PHONE (on state
  // OTRNG_STATE_WAITING_AUTH_I) and sends AUTH-R. ALICE will replace keys and
  // profile info from PC with info from PHONE.
  result = otrng_receive_message(alice_to_phone, &warn, phone_to_alice->to_send,
                                 alice);
  assert_rec_msg_in_state(result, alice_to_phone, alice,
                          OTRNG_STATE_WAITING_AUTH_I, send_response);
  otrng_response_free(phone_to_alice);

  // PC receives Auth-R succesfully and sends an Auth-I
  pc_to_alice = otrng_response_new();
  result =
      otrng_receive_message(pc_to_alice, &warn, alice_to_pc->to_send, bob_pc);
  assert_rec_msg_in_state(result, pc_to_alice, bob_pc,
                          OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE, send_response);

  // PC generates the first keys after Auth-R has been received
  otrng_assert(bob_pc->keys->our_dh->pub);
  otrng_assert(bob_pc->keys->our_dh->priv);
  otrng_assert_not_zero(bob_pc->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob_pc->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // PHONE receives Auth-R with PC instance tag - Ignores
  phone_to_alice = otrng_response_new();
  result = otrng_receive_message(phone_to_alice, &warn, alice_to_pc->to_send,
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
      otrng_receive_message(alice_to_pc, &warn, pc_to_alice->to_send, alice);

  assert_rec_msg_in_state(result, alice_to_pc, alice,
                          OTRNG_STATE_WAITING_AUTH_I, !send_response);

  otrng_response_free_all(pc_to_alice, alice_to_pc);

  // PC receives Auth-R again - ignores
  pc_to_alice = otrng_response_new();
  result = otrng_receive_message(pc_to_alice, &warn, alice_to_phone->to_send,
                                 bob_pc);
  assert_rec_msg_in_state(result, pc_to_alice, bob_pc,
                          OTRNG_STATE_ENCRYPTED_MESSAGES, !send_response);
  otrng_response_free(pc_to_alice);

  // PHONE receives correct Auth-R message and sends Auth-I
  phone_to_alice = otrng_response_new();
  result = otrng_receive_message(phone_to_alice, &warn, alice_to_phone->to_send,
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
  result = otrng_receive_message(alice_to_phone, &warn, phone_to_alice->to_send,
                                 alice);
  assert_rec_msg_in_state(result, alice_to_phone, alice,
                          OTRNG_STATE_ENCRYPTED_MESSAGES, !send_response);

  // ALICE and PHONE have the same shared secret
  otrng_assert_root_key_eq(alice->keys->current->root_key,
                           bob_phone->keys->current->root_key);
  otrng_response_free_all(phone_to_alice, alice_to_phone);
  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_phone_state->global_state);
  otrng_global_state_free(bob_pc_state->global_state);
  otrng_client_free_all(alice_client, bob_pc_state, bob_phone_state);
  otrng_free_all(alice, bob_pc, bob_phone);
}

static void test_api_smp(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state_expect, ==, '1');
  g_assert_cmpint(bob->smp->state_expect, ==, '1');

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  string_p to_send = NULL;
  const char *secret = "secret";
  otrng_warning warn = OTRNG_WARN_NONE;

  // Alice sends SMP1
  otrng_assert_is_success(otrng_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                                          strlen(secret), alice));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1
  g_assert_cmpint(alice->smp->state_expect, ==, '2');

  // Bob receives SMP1
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, &warn, to_send, bob));
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
      otrng_receive_message(response_to_bob, &warn, to_send, alice));

  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9); // SMP3

  free(to_send);
  to_send = NULL;

  // Bob receives SMP3
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(response_to_alice, &warn,
                                                response_to_bob->to_send, bob));
  otrng_response_free(response_to_bob);

  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAQD", response_to_alice->to_send, 9); // SMP4
  g_assert_cmpint(alice->smp->state_expect, ==, '4');

  // Alice receives SMP4
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, &warn, response_to_alice->to_send, alice));
  otrng_response_free(response_to_alice);

  g_assert_cmpint(bob->smp->state_expect, ==, '1');
  g_assert_cmpint(alice->smp->state_expect, ==, '1');

  otrng_assert(!response_to_bob->to_send);

  otrng_response_free(response_to_bob);
  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

static void test_api_smp_abort(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state_expect, ==, '1');
  g_assert_cmpint(bob->smp->state_expect, ==, '1');

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  string_p to_send = NULL;
  const char *secret = "secret";
  otrng_warning warn = OTRNG_WARN_NONE;

  // Alice sends SMP1
  otrng_assert_is_success(otrng_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                                          strlen(secret), alice));
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1
  g_assert_cmpint(alice->smp->state_expect, ==, '2');

  // Bob receives SMP1
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, &warn, to_send, bob));

  otrng_assert(!response_to_alice->to_send);
  free_message_and_response(response_to_alice, &to_send);

  // Bob sends SMP Abort
  otrng_assert_is_success(otrng_smp_abort(&to_send, bob));
  g_assert_cmpint(bob->smp->state_expect, ==, '1');

  // Alice receives SMP ABORT
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_bob, &warn, to_send, alice));

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

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

static void test_api_extra_sym_key(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;

  // Alice sends a data message
  string_p to_send = NULL;
  otrng_warning warn = OTRNG_WARN_NONE;
  otrng_result result;

  result = otrng_send_message(&to_send, "hi", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  // This is a follow up message.
  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);

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
      otrng_receive_message(response_to_bob, &warn, to_send, alice));
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 1);

  // Check TLVS
  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->data->type, ==, OTRNG_TLV_SYM_KEY);
  g_assert_cmpint(response_to_bob->tlvs->data->len, ==, tlv_len);
  otrng_assert_cmpmem(response_to_bob->tlvs->data->data, tlv_data, tlv_len);

  otrng_assert(!response_to_bob->tlvs->next);

  free_message_and_response(response_to_bob, &to_send);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

static void test_heartbeat_messages(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  alice_client->should_heartbeat = test_should_not_heartbeat;
  bob_client->should_heartbeat = test_should_heartbeat;

  // DAKE HAS FINISHED
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;
  otrng_response_s *response_to_bob = NULL;

  // Alice sends a data message
  string_p to_send = NULL;
  otrng_warning warn = OTRNG_WARN_NONE;
  otrng_result result;

  result = otrng_send_message(&to_send, "hi", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  // bob->last_sent = time(NULL) - 60;

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);

  // Bob receives a data message
  // Bob sends a heartbeat message
  response_to_alice = otrng_response_new();
  otrng_assert_is_success(
      otrng_receive_message(response_to_alice, &warn, to_send, bob));
  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  otrng_assert_cmpmem("hi", response_to_alice->to_display, strlen("hi") + 1);
  otrng_assert(response_to_alice->to_send != NULL);
  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 2);

  free(to_send);

  // Alice receives the heatbeat message. Let's force this.
  response_to_bob = otrng_response_new();
  otrng_assert_is_success(otrng_receive_message(
      response_to_bob, &warn, response_to_alice->to_send, alice));
  otrng_assert(alice->keys->old_mac_keys);
  otrng_assert(!response_to_bob->to_display);
  otrng_assert(!response_to_bob->to_send);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);

  otrng_response_free(response_to_alice);
  otrng_response_free(response_to_bob);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

void functionals_api_add_tests(void) {
  /* // API are supposed to test the public API. */
  /* // They go to the end because they are integration tests, and we only
   * should */
  /* // care about them after all the unit tests are working. */
  /* // TODO: @refactoring There is TOO MUCH /api tests. They are TOO BIG and
   * hard */
  /* // to understand (by nature, I think). Let's reconsider what should be
   * here. */

  g_test_add_func("/api/interactive_conversation/v4",
                  test_api_interactive_conversation);
  g_test_add_func("/api/send_offline_message",
  test_otrng_send_offline_message);
  g_test_add_func("/api/incorrect_offline_dake",
                  test_otrng_incorrect_offline_dake);

  g_test_add_func("/api/multiple_clients", test_api_multiple_clients);
  g_test_add_func("/api/conversation_errors_1",
  test_api_conversation_errors_1);
  g_test_add_func("/api/conversation_errors_2",
  test_api_conversation_errors_2);
  g_test_add_func("/api/conversation/v3", test_api_conversation_v3);
  g_test_add_func("/api/smp", test_api_smp);
  g_test_add_func("/api/smp_abort", test_api_smp_abort);
  /* g_test_add_func("/api/messaging", test_api_messaging); */
  g_test_add_func("/api/extra_symm_key", test_api_extra_sym_key);
  g_test_add_func("/api/heartbeat_messages", test_heartbeat_messages);
}
