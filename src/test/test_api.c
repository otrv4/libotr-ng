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

#include <libotr/b64.h> // TODO: we shouldn't be exposing this
#include <libotr/privkey.h>
#include <string.h>

#include "../list.h"
#include "../otrng.h"
#include "../str.h"

#define assert_msg_sent(result, to_send)                                       \
  do {                                                                         \
    const otrng_err _result = (result);                                        \
    const char *_to_send = (to_send);                                          \
    otrng_assert(_result == SUCCESS);                                          \
    otrng_assert(_to_send);                                                    \
    otrng_assert_cmpmem("?OTR:AAQD", _to_send, 9);                             \
  } while (0)

#define assert_msg_rec(result, message, response)                              \
  do {                                                                         \
    const otrng_err _result = (result);                                        \
    const char *_message = (message);                                          \
    const otrng_response_s *_response = (response);                            \
    otrng_assert(_result == SUCCESS);                                          \
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
    otrng_assert(_result == SUCCESS);                                          \
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

static void set_up_client_state(otrng_client_state_s *state,
                                const char *account_name, const char *phi,
                                int byte) {
  state->account_name = otrng_strdup(account_name);
  state->protocol_name = otrng_strdup("otr");
  state->user_state = otrl_userstate_create();

  uint8_t long_term_priv[ED448_PRIVATE_BYTES] = {byte + 0xA};
  uint8_t shared_prekey_priv[ED448_PRIVATE_BYTES] = {byte + 0XF};

  otrng_client_state_add_private_key_v4(state, long_term_priv);
  otrng_client_state_add_shared_prekey_v4(state, shared_prekey_priv);
  otrng_client_state_add_instance_tag(state, 0x100 + byte);

  // on client this will probably be the jid and the
  // receipient jid for the party
  state->phi = otrng_strdup(phi);
  state->pad = false;
  // TODO: here we need the heartbeat for tests
}

static otrng_s *set_up(otrng_client_state_s *client_state,
                       const char *account_name, const char *phi, int byte) {
  set_up_client_state(client_state, account_name, phi, byte);
  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V3 | OTRNG_ALLOW_V4};

  return otrng_new(client_state, policy);
}

void test_api_interactive_conversation(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  bob_client_state->pad = true;
  alice_client_state->pad = true;

  // DAKE has finished
  do_dake_fixture(alice, bob);

  int message_id;
  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;

  string_p to_send = NULL;
  otrng_err result;

  for (message_id = 1; message_id < 4; message_id++) {
    tlv_list_s *tlvs = NULL;
    // Alice sends a data message
    result = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice);
    assert_msg_sent(result, to_send);
    otrng_assert(tlvs);
    otrng_assert(!alice->keys->old_mac_keys);
    otrng_tlv_list_free(tlvs);

    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, message_id);
    g_assert_cmpint(alice->keys->k, ==, 0);
    g_assert_cmpint(alice->keys->pn, ==, 0);

    // Alice should not delete priv keys
    otrng_assert_not_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);
    otrng_assert(alice->keys->our_dh->priv);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    result = otrng_receive_message(response_to_alice, to_send, bob);
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
    tlv_list_s *tlvs = NULL;
    result = otrng_prepare_to_send_message(&to_send, "hello", &tlvs, 0, bob);
    otrng_tlv_list_free(tlvs);
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
    otrng_err result = otrng_receive_message(response_to_bob, to_send, alice);
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
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);
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
  otrng_receive_message(response_to_bob, to_send, alice);

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

void test_otrng_send_offline_message() {
  /* Specifies the behavior of the API for offline messages */
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  prekey_ensemble_s *ensemble = otrng_build_prekey_ensemble(1, bob);
  otrng_assert(ensemble);
  otrng_assert(SUCCESS == otrng_prekey_ensemble_validate(ensemble));

  g_assert_cmpint(bob->their_prekeys_id, ==, 0);
  otrng_assert(bob->running_version == OTRNG_VERSION_NONE);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  char *to_bob = NULL;
  otrng_assert(SUCCESS ==
               otrng_send_offline_message(&to_bob, ensemble, "hi", alice));
  otrng_prekey_ensemble_free(ensemble);

  otrng_assert(to_bob);
  otrng_assert_cmpmem("?OTR:AASN", to_bob, 9);

  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(alice->running_version == OTRNG_VERSION_4);

  // There is an attached encrypted message sent
  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives an offline message
  otrng_response_s *resp = otrng_response_new();
  otrng_assert(SUCCESS == otrng_receive_message(resp, to_bob, bob));
  free(to_bob);

  otrng_assert(resp->to_display);
  otrng_assert_cmpmem(resp->to_display, "hi", 3);
  otrng_assert(!resp->to_send);
  otrng_response_free_all(resp);

  g_assert_cmpint(bob->their_prekeys_id, ==, 0);
  otrng_assert(bob->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(bob->running_version == OTRNG_VERSION_4);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  otrng_assert_ec_public_key_eq(bob->keys->their_ecdh,
                                alice->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(bob->keys->their_dh, alice->keys->our_dh->pub);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_non_interactive_conversation(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();

  otrng_server_s *server = malloc(sizeof(otrng_server_s));
  server->prekey_message = NULL;

  // Alice uploads a prekey message to the server
  otrng_assert(otrng_start_non_interactive_dake(server, alice) == SUCCESS);

  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert(server->prekey_message != NULL);

  // Bob asks server for prekey message
  // Server replies with prekey message
  otrng_reply_with_prekey_msg_from_server(server, response_to_bob);
  otrng_assert(bob->state == OTRNG_STATE_START);
  otrng_assert(response_to_bob != NULL);

  otrng_assert_cmpmem("?OTR:AAQP", response_to_bob->to_send, 9);

  // Bob receives Alice's profiles from the server
  // (they will come from the ensemble, but I don't want to change the API
  // used here at the moment)
  bob->their_client_profile = malloc(sizeof(client_profile_s));
  otrng_client_profile_copy(
      bob->their_client_profile,
      otrng_client_state_get_or_create_client_profile(alice_client_state));

  bob->their_prekey_profile = malloc(sizeof(otrng_prekey_profile_s));
  otrng_prekey_profile_copy(
      bob->their_prekey_profile,
      otrng_client_state_get_or_create_prekey_profile(alice_client_state));

  // Bob receives prekey message
  otrng_assert(otrng_receive_message(response_to_alice,
                                     response_to_bob->to_send, bob) == SUCCESS);
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  otrng_assert(bob->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  otrng_assert(otrng_send_non_interactive_auth_msg(&response_to_alice->to_send,
                                                   "", bob) == SUCCESS);
  // There is no attached encrypted message
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Should send a non interactive auth
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AASN", response_to_alice->to_send, 9);

  // Alice receives a non interactive auth
  otrng_assert(otrng_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == SUCCESS);
  otrng_assert(response_to_alice->to_display == NULL);

  otrng_response_free_all(response_to_alice, response_to_bob);
  free(server);
  server = NULL;

  otrng_assert_ec_public_key_eq(alice->keys->their_ecdh,
                                bob->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(alice->keys->their_dh, bob->keys->our_dh->pub);
  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(alice->keys->current);
  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Both have the same shared secret/root key
  otrng_assert_root_key_eq(alice->keys->current->root_key,
                           bob->keys->current->root_key);

  // Bob sends a data message
  int message_id;
  string_p to_send = NULL;
  otrng_err result;

  // TODO: this is usually set up by the query or whitespace,
  // this will be defined on the prekey server spec.
  bob->running_version = OTRNG_VERSION_4;
  alice->running_version = OTRNG_VERSION_4;

  for (message_id = 1; message_id < 4; message_id++) {
    tlv_list_s *tlvs = NULL;
    result = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice);
    otrng_tlv_list_free(tlvs);
    assert_msg_sent(result, to_send);
    otrng_assert(!alice->keys->old_mac_keys);

    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, message_id);
    g_assert_cmpint(alice->keys->k, ==, 0);
    g_assert_cmpint(alice->keys->pn, ==, 0);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    otrng_err result = otrng_receive_message(response_to_alice, to_send, bob);
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
    // Bob sends a data message
    tlv_list_s *tlvs = NULL;
    result = otrng_prepare_to_send_message(&to_send, "hello", &tlvs, 0, bob);
    otrng_tlv_list_free(tlvs);
    assert_msg_sent(result, to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);
    g_assert_cmpint(bob->keys->i, ==, 2);
    g_assert_cmpint(bob->keys->j, ==, message_id);
    g_assert_cmpint(bob->keys->k, ==, 3);
    g_assert_cmpint(bob->keys->pn, ==, 0);

    // Alice receives a data message
    response_to_bob = otrng_response_new();
    otrng_err result = otrng_receive_message(response_to_bob, to_send, alice);
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
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);
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

void test_api_non_interactive_conversation_with_enc_msg_1(void) {

  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();

  otrng_server_s *server = malloc(sizeof(otrng_server_s));
  server->prekey_message = NULL;

  // Alice uploads prekey message to server
  otrng_assert(otrng_start_non_interactive_dake(server, alice) == SUCCESS);

  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert(server->prekey_message != NULL);

  // Bob asks server for prekey message
  // Server replies with prekey message
  otrng_reply_with_prekey_msg_from_server(server, response_to_bob);
  otrng_assert(bob->state == OTRNG_STATE_START);
  otrng_assert(response_to_bob != NULL);

  otrng_assert_cmpmem("?OTR:AAQP", response_to_bob->to_send, 9);

  // Bob receives Alice's profiles from the server
  // (they will come from the ensemble, but I don't want to change the API
  // used here at the moment)
  bob->their_client_profile = malloc(sizeof(client_profile_s));
  otrng_client_profile_copy(
      bob->their_client_profile,
      otrng_client_state_get_or_create_client_profile(alice_client_state));

  bob->their_prekey_profile = malloc(sizeof(otrng_prekey_profile_s));
  otrng_prekey_profile_copy(
      bob->their_prekey_profile,
      otrng_client_state_get_or_create_prekey_profile(alice_client_state));

  // Bob receives prekey message
  otrng_assert(otrng_receive_message(response_to_alice,
                                     response_to_bob->to_send, bob) == SUCCESS);

  otrng_assert(bob->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(bob->keys->current);

  otrng_assert(otrng_send_non_interactive_auth_msg(&response_to_alice->to_send,
                                                   "hi", bob) == SUCCESS);

  // Should send an non-interactive auth message
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AASN", response_to_alice->to_send, 9);

  // There is an attached encrypted message
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives an non-interactive auth message
  otrng_assert(otrng_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == SUCCESS);

  otrng_assert_ec_public_key_eq(alice->keys->their_ecdh,
                                bob->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(alice->keys->their_dh, bob->keys->our_dh->pub);
  otrng_assert_cmpmem("hi", response_to_bob->to_display, 3);

  otrng_response_free_all(response_to_alice, response_to_bob);

  free(server->prekey_message);
  server->prekey_message = NULL;
  free(server);
  server = NULL;

  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(alice->keys->current);
  otrng_assert(alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Both have the same shared secret
  otrng_assert_root_key_eq(alice->keys->current->root_key,
                           bob->keys->current->root_key);

  int message_id;
  string_p to_send = NULL;
  otrng_err result;

  // TODO: this is usually set up by the querry or whitespace,
  // this will be defined on the prekey server spec.
  bob->running_version = OTRNG_VERSION_4;
  alice->running_version = OTRNG_VERSION_4;

  for (message_id = 1; message_id < 4; message_id++) {
    tlv_list_s *tlvs = NULL;
    // Alice sends a data message
    result = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice);
    otrng_tlv_list_free(tlvs);
    assert_msg_sent(result, to_send);
    otrng_assert(!alice->keys->old_mac_keys);

    g_assert_cmpint(alice->keys->i, ==, 2);
    g_assert_cmpint(alice->keys->j, ==, message_id);
    g_assert_cmpint(alice->keys->k, ==, 1);
    g_assert_cmpint(alice->keys->pn, ==, 0);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    result = otrng_receive_message(response_to_alice, to_send, bob);
    assert_msg_rec(result, "hi", response_to_alice);
    otrng_assert(bob->keys->old_mac_keys);

    free_message_and_response(response_to_alice, &to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, message_id);

    g_assert_cmpint(bob->keys->i, ==, 2);
    g_assert_cmpint(bob->keys->j, ==, 0);
    g_assert_cmpint(bob->keys->k, ==, message_id);
    g_assert_cmpint(bob->keys->pn, ==, 1);
  }

  for (message_id = 1; message_id < 4; message_id++) {
    // Bob sends a data message
    tlv_list_s *tlvs = NULL;
    result = otrng_prepare_to_send_message(&to_send, "hello", &tlvs, 0, bob);
    otrng_tlv_list_free(tlvs);
    assert_msg_sent(result, to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);
    g_assert_cmpint(bob->keys->i, ==, 3);
    g_assert_cmpint(bob->keys->j, ==, message_id);
    g_assert_cmpint(bob->keys->k, ==, 3);
    g_assert_cmpint(bob->keys->pn, ==, 1);

    // Alice receives a data message
    response_to_bob = otrng_response_new();
    otrng_err result = otrng_receive_message(response_to_bob, to_send, alice);
    assert_msg_rec(result, "hello", response_to_bob);
    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, message_id);

    free_message_and_response(response_to_bob, &to_send);

    g_assert_cmpint(alice->keys->i, ==, 3);
    g_assert_cmpint(alice->keys->j, ==, 0);
    g_assert_cmpint(alice->keys->k, ==, message_id);
    g_assert_cmpint(alice->keys->pn, ==, 3);
  }

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_non_interactive_conversation_with_enc_msg_2(void) {

  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();

  otrng_server_s *server = malloc(sizeof(otrng_server_s));
  server->prekey_message = NULL;

  // Alice uploads prekey message to server
  otrng_assert(otrng_start_non_interactive_dake(server, alice) == SUCCESS);

  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert(server->prekey_message != NULL);

  // Bob asks server for prekey message
  // Server replies with prekey message
  otrng_reply_with_prekey_msg_from_server(server, response_to_bob);
  otrng_assert(bob->state == OTRNG_STATE_START);
  otrng_assert(response_to_bob != NULL);

  otrng_assert_cmpmem("?OTR:AAQP", response_to_bob->to_send, 9);

  // Bob receives Alice's profiles from the server
  // (they will come from the ensemble, but I don't want to change the API
  // used here at the moment)
  bob->their_client_profile = malloc(sizeof(client_profile_s));
  otrng_client_profile_copy(
      bob->their_client_profile,
      otrng_client_state_get_or_create_client_profile(alice_client_state));

  bob->their_prekey_profile = malloc(sizeof(otrng_prekey_profile_s));
  otrng_prekey_profile_copy(
      bob->their_prekey_profile,
      otrng_client_state_get_or_create_prekey_profile(alice_client_state));

  // Bob receives prekey message
  otrng_assert(otrng_receive_message(response_to_alice,
                                     response_to_bob->to_send, bob) == SUCCESS);

  otrng_assert(bob->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(bob->keys->current);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  otrng_assert(otrng_send_non_interactive_auth_msg(&response_to_alice->to_send,
                                                   "hi", bob) == SUCCESS);

  // Should send an non-interactive auth message
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AASN", response_to_alice->to_send, 9);

  // Alice receives an non-interactive auth message
  otrng_assert(otrng_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == SUCCESS);

  otrng_assert_ec_public_key_eq(alice->keys->their_ecdh,
                                bob->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(alice->keys->their_dh, bob->keys->our_dh->pub);
  otrng_assert_cmpmem("hi", response_to_bob->to_display, 3);

  otrng_response_free_all(response_to_alice, response_to_bob);

  free(server->prekey_message);
  server->prekey_message = NULL;
  free(server);
  server = NULL;

  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(alice->keys->current);
  otrng_assert(alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Both have the same shared secret/root key
  otrng_assert_root_key_eq(alice->keys->current->root_key,
                           bob->keys->current->root_key);

  int message_id;
  string_p to_send = NULL;
  otrng_err result;

  // TODO: this is usually set up by the querry or whitespace,
  // this will be defined on the prekey server spec.
  bob->running_version = OTRNG_VERSION_4;
  alice->running_version = OTRNG_VERSION_4;

  // A new DH ratchet does not happen
  for (message_id = 1; message_id < 4; message_id++) {
    tlv_list_s *tlvs = NULL;
    // Bob sends a data message
    result = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, bob);
    otrng_tlv_list_free(tlvs);
    assert_msg_sent(result, to_send);
    otrng_assert(!bob->keys->old_mac_keys);

    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, message_id + 1);
    g_assert_cmpint(bob->keys->k, ==, 0);
    g_assert_cmpint(bob->keys->pn, ==, 0);

    // Alice receives a data message
    response_to_bob = otrng_response_new();
    otrng_err result = otrng_receive_message(response_to_bob, to_send, alice);
    assert_msg_rec(result, "hi", response_to_bob);
    otrng_assert(alice->keys->old_mac_keys);

    free_message_and_response(response_to_bob, &to_send);

    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==,
                    message_id + 1);

    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, 0);
    g_assert_cmpint(alice->keys->k, ==, message_id + 1);
    g_assert_cmpint(alice->keys->pn, ==, 0);
  }

  for (message_id = 1; message_id < 4; message_id++) {
    // Alice sends a data message
    tlv_list_s *tlvs = NULL;
    result = otrng_prepare_to_send_message(&to_send, "hello", &tlvs, 0, alice);
    otrng_tlv_list_free(tlvs);
    assert_msg_sent(result, to_send);

    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 0);

    // New ratchet hapenned
    g_assert_cmpint(alice->keys->i, ==, 2);
    g_assert_cmpint(alice->keys->j, ==, message_id);
    g_assert_cmpint(alice->keys->k, ==, 4);
    g_assert_cmpint(alice->keys->pn, ==, 0);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    otrng_err result = otrng_receive_message(response_to_alice, to_send, bob);
    assert_msg_rec(result, "hello", response_to_alice);
    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, message_id);

    free_message_and_response(response_to_alice, &to_send);

    g_assert_cmpint(bob->keys->i, ==, 2);
    g_assert_cmpint(bob->keys->j, ==, 0);
    g_assert_cmpint(bob->keys->k, ==, message_id);
    g_assert_cmpint(bob->keys->pn, ==, 4);
  }

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_same_ratchet_out_of_order(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  bob_client_state->pad = true;
  alice_client_state->pad = true;

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;

  string_p to_send_1 = NULL;
  string_p to_send_2 = NULL;
  string_p to_send_3 = NULL;
  string_p to_send_4 = NULL;
  otrng_err result;
  tlv_list_s *tlvs = NULL;

  // Alice sends a data message
  result = otrng_prepare_to_send_message(&to_send_1, "hi", &tlvs, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  tlvs = NULL;
  result = otrng_prepare_to_send_message(&to_send_2, "how are you?", &tlvs, 0,
                                         alice);
  assert_msg_sent(result, to_send_2);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  tlvs = NULL;
  result =
      otrng_prepare_to_send_message(&to_send_3, "it's me", &tlvs, 0, alice);
  assert_msg_sent(result, to_send_3);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 3);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  tlvs = NULL;
  result = otrng_prepare_to_send_message(&to_send_4, "ok?", &tlvs, 0, alice);
  assert_msg_sent(result, to_send_4);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 4);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_4, bob);
  assert_msg_rec(result, "ok?", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_4);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 4);
  g_assert_cmpint(bob->keys->pn, ==, 0);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 2);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_3, bob);
  assert_msg_rec(result, "it's me", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_3);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 3);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 4);
  g_assert_cmpint(bob->keys->pn, ==, 0);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 1);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_2, bob);
  assert_msg_rec(result, "how are you?", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 4);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 4);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_new_sending_ratchet_in_order(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  bob_client_state->pad = true;
  alice_client_state->pad = true;

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;
  otrng_response_s *response_to_bob = NULL;

  string_p to_send_1 = NULL;
  string_p to_send_2 = NULL;
  string_p to_send_3 = NULL;
  string_p to_send_4 = NULL;
  string_p to_send_5 = NULL;
  otrng_err result;
  tlv_list_s *tlvs = NULL;

  // Alice sends a data message
  result = otrng_prepare_to_send_message(&to_send_1, "hi", &tlvs, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  tlvs = NULL;
  result = otrng_prepare_to_send_message(&to_send_2, "how are you?", &tlvs, 0,
                                         alice);
  assert_msg_sent(result, to_send_2);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  tlvs = NULL;
  result =
      otrng_prepare_to_send_message(&to_send_3, "it's me", &tlvs, 0, alice);
  assert_msg_sent(result, to_send_3);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 3);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives 2 data messages
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_2, bob);
  assert_msg_rec(result, "how are you?", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob sends a data message
  tlvs = NULL;
  result = otrng_prepare_to_send_message(&to_send_4, "oh, hi", &tlvs, 0, bob);
  otrng_tlv_list_free(tlvs);
  assert_msg_sent(result, to_send_4);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob receives the previous data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_3, bob);
  assert_msg_rec(result, "it's me", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_3);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(
      bob->keys->i, ==,
      2); // TODO: this is odd but the ratchet has indeed move forward
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 3);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, to_send_4, alice);
  assert_msg_rec(result, "oh, hi", response_to_bob);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 1);

  free_message_and_response(response_to_bob, &to_send_4);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 3);

  // Bob sends another data message
  tlvs = NULL;
  result = otrng_prepare_to_send_message(&to_send_5, "I'm good", &tlvs, 0, bob);
  otrng_tlv_list_free(tlvs);
  assert_msg_sent(result, to_send_5);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 2);
  g_assert_cmpint(bob->keys->k, ==, 3);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives the data message
  response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, to_send_5, alice);
  assert_msg_rec(result, "I'm good", response_to_bob);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 2);

  free_message_and_response(response_to_bob, &to_send_5);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 2);
  g_assert_cmpint(alice->keys->pn, ==, 3);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_new_ratchet_out_of_order(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  bob_client_state->pad = true;
  alice_client_state->pad = true;

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;
  otrng_response_s *response_to_bob = NULL;

  string_p to_send_1 = NULL;
  string_p to_send_2 = NULL;
  string_p to_send_3 = NULL;
  string_p to_send_4 = NULL;
  string_p to_send_5 = NULL;
  otrng_err result;

  tlv_list_s *tlvs = NULL;

  // Alice sends a data message
  result = otrng_prepare_to_send_message(&to_send_1, "hi", &tlvs, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  tlvs = NULL;
  result = otrng_prepare_to_send_message(&to_send_2, "how are you?", &tlvs, 0,
                                         alice);
  assert_msg_sent(result, to_send_2);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  tlvs = NULL;
  result =
      otrng_prepare_to_send_message(&to_send_3, "it's me", &tlvs, 0, alice);
  assert_msg_sent(result, to_send_3);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);
  otrng_tlv_list_free(tlvs);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 3);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives 2 data messages
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_2, bob);
  assert_msg_rec(result, "how are you?", response_to_alice);

  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 0);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob sends a data message
  tlvs = NULL;
  result = otrng_prepare_to_send_message(&to_send_4, "oh, hi", &tlvs, 0, bob);
  otrng_tlv_list_free(tlvs);
  assert_msg_sent(result, to_send_4);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, to_send_4, alice);
  assert_msg_rec(result, "oh, hi", response_to_bob);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 1);

  free_message_and_response(response_to_bob, &to_send_4);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 3);

  // Alice sends a data message
  tlvs = NULL;
  result = otrng_prepare_to_send_message(&to_send_5, "good", &tlvs, 0, alice);
  otrng_tlv_list_free(tlvs);
  assert_msg_sent(result, to_send_5);

  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 0);

  g_assert_cmpint(alice->keys->i, ==, 3);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 3);

  // Bob receives the data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_5, bob);
  assert_msg_rec(result, "good", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_5);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 3);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 1);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 1);

  // Bob receives the previous data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send_3, bob);
  assert_msg_rec(result, "it's me", response_to_alice);

  free_message_and_response(response_to_alice, &to_send_3);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 0);
  g_assert_cmpint(
      bob->keys->i, ==,
      3); // TODO: this is odd but the ratchet has indeed move forward
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1); // TODO: check this
  g_assert_cmpint(bob->keys->pn, ==, 1);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_conversation_errors_1(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  bob_client_state->pad = true;
  alice_client_state->pad = true;

  // DAKE HAS FINISHED
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;
  otrng_response_s *response_to_bob = NULL;

  string_p to_send = NULL;
  tlv_list_s *tlvs = NULL;
  otrng_err result;

  // Alice sends a data message
  result = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice);

  assert_msg_sent(result, to_send);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // To trigger the error message
  bob->state = OTRNG_STATE_START;

  // Bob receives a data message in the incorrect state
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send, bob);

  string_p err_code = "?OTR Error: ERROR_2: OTRNG_ERR_MSG_NOT_PRIVATE_STATE";
  otrng_assert_cmpmem(err_code, response_to_alice->to_send, strlen(err_code));

  otrng_assert_error(result);
  otrng_assert(response_to_alice->to_send != NULL);
  otrng_assert(!bob->keys->old_mac_keys);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  response_to_bob = otrng_response_new();
  result =
      otrng_receive_message(response_to_bob, response_to_alice->to_send, alice);
  string_p err_human = "Not in private state message";

  otrng_assert_success(result);
  otrng_assert(response_to_bob);
  otrng_assert_cmpmem(err_human, response_to_bob->to_display,
                      strlen(err_human));

  otrng_response_free(response_to_alice);
  otrng_response_free(response_to_bob);
  free(to_send);
  to_send = NULL;

  // Alice sends another data message
  result = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice);
  assert_msg_sent(result, to_send);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);

  bob->state = OTRNG_STATE_ENCRYPTED_MESSAGES;
  bob->keys->j = 15;

  // Bob receives a non valid data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send, bob);

  otrng_assert(result == MSG_NOT_VALID);
  otrng_assert(response_to_alice->to_send == NULL);
  otrng_assert(response_to_alice->warning == OTRNG_WARN_RECEIVED_NOT_VALID);

  otrng_tlv_list_free(tlvs);

  free_message_and_response(response_to_alice, &to_send);
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_conversation_errors_2(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  alice_client_state->account_name = otrng_strdup(ALICE_IDENTITY);
  alice_client_state->protocol_name = otrng_strdup("otr");
  alice_client_state->user_state = otrl_userstate_create();

  uint8_t sym_key[ED448_PRIVATE_BYTES] = {0x01};
  otrng_client_state_add_private_key_v4(alice_client_state, sym_key);
  otrng_client_state_add_shared_prekey_v4(alice_client_state, sym_key);
  otrng_client_state_add_instance_tag(alice_client_state, 0x00);
  alice_client_state->phi = otrng_strdup(PHI);
  alice_client_state->pad = false;
  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V3 | OTRNG_ALLOW_V4};

  otrng_s *alice = otrng_new(alice_client_state, policy);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();
  string_p query_message = NULL;

  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert(bob->state == OTRNG_STATE_START);

  // Alice sends a query message
  otrng_assert(otrng_build_query_message(&query_message, "", alice) == SUCCESS);
  otrng_assert(alice->state == OTRNG_STATE_START);
  otrng_assert_cmpmem("?OTRv4", query_message, 6);

  // Bob receives a query message
  otrng_assert(otrng_receive_message(response_to_alice, query_message, bob) ==
               SUCCESS);
  free(query_message);
  query_message = NULL;

  // Bob replies with an identity message
  otrng_assert(bob->state == OTRNG_STATE_WAITING_AUTH_R);
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAQI", response_to_alice->to_send, 9);

  // Alice receives an identity message
  otrng_assert(otrng_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == SUCCESS);
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Alice replies with an auth-r message
  otrng_assert(alice->state == OTRNG_STATE_WAITING_AUTH_I);
  otrng_assert(response_to_bob->to_display == NULL);
  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AASR", response_to_bob->to_send, 9);

  otrng_err result;
  // Bob receives an auth-r message
  result =
      otrng_receive_message(response_to_alice, response_to_bob->to_send, bob);
  otrng_assert(!result);
  string_p err_code = "?OTR Error: ERROR_4: OTRNG_ERR_MALFORMED";
  otrng_assert_cmpmem(err_code, response_to_alice->to_send, strlen(err_code));

  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  // Alice receives an error message
  otrng_assert(otrng_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == SUCCESS);

  otrng_assert(response_to_bob);
  string_p err_human = "Malformed message";
  otrng_assert_cmpmem(err_human, response_to_bob->to_display,
                      strlen(err_human));

  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  otrng_response_free(response_to_alice);
  response_to_alice = NULL;

  otrng_response_free(response_to_bob);
  response_to_bob = NULL;

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

static void do_ake_v3(otrng_s *alice, otrng_s *bob) {
  otrng_response_s *response_to_bob = otrng_response_new();
  otrng_response_s *response_to_alice = otrng_response_new();

  // Alice sends query message
  string_p query_message = NULL;
  otrng_assert(otrng_build_query_message(&query_message, "", alice) == SUCCESS);
  otrng_assert_cmpmem("?OTRv3", query_message, 6);

  // Bob receives query message
  otrng_assert(otrng_receive_message(response_to_alice, query_message, bob) ==
               SUCCESS);
  free(query_message);
  query_message = NULL;

  // Should reply with a DH-Commit
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAMC", response_to_alice->to_send, 9);

  // Alice receives DH-Commit
  otrng_assert(otrng_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == SUCCESS);
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Should reply with a DH Key
  otrng_assert(response_to_bob->to_display == NULL);
  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAMK", response_to_bob->to_send, 9);

  // Bob receives a DH Key
  otrng_assert(otrng_receive_message(response_to_alice,
                                     response_to_bob->to_send, bob) == SUCCESS);
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  // Bob should reply with a Reveal Sig
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAMR", response_to_alice->to_send, 9);

  // Alice receives Reveal Sig
  otrng_assert(otrng_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == SUCCESS);
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Should reply with a Sig
  otrng_assert(response_to_bob->to_display == NULL);
  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAMS", response_to_bob->to_send, 9);

  // Alice should be encrypted
  g_assert_cmpint(OTRL_MSGSTATE_ENCRYPTED, ==, alice->v3_conn->ctx->msgstate);

  // Bob receives a Sig
  otrng_assert(otrng_receive_message(response_to_alice,
                                     response_to_bob->to_send, bob) == SUCCESS);
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
  tlv_list_s *tlvs = NULL;

  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  set_up_client_state(alice_client_state, ALICE_IDENTITY, PHI, 1);

  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);
  set_up_client_state(bob_client_state, BOB_IDENTITY, PHI, 2);

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

  // Alice sends a data message
  otrng_assert(otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice) ==
               SUCCESS);
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_alice, to_send, bob) ==
               SUCCESS);

  otrng_assert(response_to_alice->to_display);
  otrng_assert_cmpmem("hi", response_to_alice->to_display, 3);
  otrng_assert(!response_to_alice->to_send);
  free_message_and_response(response_to_alice, &to_send);

  // Bob sends a data message
  otrng_assert(otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, bob) ==
               SUCCESS);
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);

  otrng_assert(response_to_bob->to_display);
  otrng_assert_cmpmem("hi", response_to_bob->to_display, 3);
  otrng_assert(!response_to_bob->to_send);
  free_message_and_response(response_to_bob, &to_send);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_free_all(alice, bob);
  otrng_client_state_free_all(alice_client_state, bob_client_state);

  otrng_tlv_list_free(tlvs);
}

void test_api_multiple_clients(void) {

  bool send_response = true;
  otrng_err result;

  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_phone_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_pc_state = otrng_client_state_new(NULL);

  // The account name should be the same. The account can be logged
  // on different clients. Instance tags are used for that. This
  // account name can be used as phi.
  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob_phone = set_up(bob_phone_state, BOB_IDENTITY, PHI, 2);
  otrng_s *bob_pc = set_up(bob_pc_state, BOB_IDENTITY, PHI, 3);

  otrng_response_s *pc_to_alice = otrng_response_new();
  otrng_response_s *phone_to_alice = otrng_response_new();
  otrng_response_s *alice_to_pc = otrng_response_new();
  otrng_response_s *alice_to_phone = otrng_response_new();

  // PC receives query msg and sends identity msg
  result = otrng_receive_message(pc_to_alice, "?OTRv4?", bob_pc);
  assert_rec_msg_in_state(result, pc_to_alice, bob_pc,
                          OTRNG_STATE_WAITING_AUTH_R, send_response);

  // PHONE receives query msg and sends identity msg
  result = otrng_receive_message(phone_to_alice, "?OTRv4?", bob_phone);
  assert_rec_msg_in_state(result, phone_to_alice, bob_phone,
                          OTRNG_STATE_WAITING_AUTH_R, send_response);

  // ALICE receives Identity msg from PC and sends AUTH-R
  result = otrng_receive_message(alice_to_pc, pc_to_alice->to_send, alice);
  assert_rec_msg_in_state(result, alice_to_pc, alice,
                          OTRNG_STATE_WAITING_AUTH_I, send_response);
  otrng_response_free(pc_to_alice);

  // ALICE receives Identity msg from PHONE (on state
  // OTRNG_STATE_WAITING_AUTH_I) and sends AUTH-R. ALICE will replace keys and
  // profile info from PC with info from PHONE.
  result =
      otrng_receive_message(alice_to_phone, phone_to_alice->to_send, alice);
  assert_rec_msg_in_state(result, alice_to_phone, alice,
                          OTRNG_STATE_WAITING_AUTH_I, send_response);
  otrng_response_free(phone_to_alice);

  // PC receives AUTH-R succesfully
  pc_to_alice = otrng_response_new();
  result = otrng_receive_message(pc_to_alice, alice_to_pc->to_send, bob_pc);
  assert_rec_msg_in_state(result, pc_to_alice, bob_pc,
                          OTRNG_STATE_ENCRYPTED_MESSAGES, send_response);

  // PC generates the first keys after AUTH-R has been received
  otrng_assert(bob_pc->keys->our_dh->pub);
  otrng_assert(bob_pc->keys->our_dh->priv);
  otrng_assert_not_zero(bob_pc->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob_pc->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // PHONE receives AUTH-R with PC instance tag - Ignores
  phone_to_alice = otrng_response_new();
  result =
      otrng_receive_message(phone_to_alice, alice_to_pc->to_send, bob_phone);
  assert_rec_msg_in_state(result, phone_to_alice, bob_phone,
                          OTRNG_STATE_WAITING_AUTH_R, !send_response);
  otrng_response_free_all(phone_to_alice, alice_to_pc);

  otrng_assert(bob_phone->keys->our_dh->pub);
  otrng_assert(bob_phone->keys->our_dh->priv);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // ALICE receives AUTH-I from PC - Authentication fails
  alice_to_pc = otrng_response_new();
  result = otrng_receive_message(alice_to_pc, pc_to_alice->to_send, alice);

  assert_rec_msg_in_state(!result, alice_to_pc, alice,
                          OTRNG_STATE_WAITING_AUTH_I, !send_response);

  otrng_response_free_all(pc_to_alice, alice_to_pc);

  // PC receives AUTH-R again - ignores
  pc_to_alice = otrng_response_new();
  result = otrng_receive_message(pc_to_alice, alice_to_phone->to_send, bob_pc);
  assert_rec_msg_in_state(result, pc_to_alice, bob_pc,
                          OTRNG_STATE_ENCRYPTED_MESSAGES, !send_response);
  otrng_response_free(pc_to_alice);

  // PHONE receives correct AUTH-R message and sends AUTH-I
  phone_to_alice = otrng_response_new();
  result =
      otrng_receive_message(phone_to_alice, alice_to_phone->to_send, bob_phone);
  assert_rec_msg_in_state(result, phone_to_alice, bob_phone,
                          OTRNG_STATE_ENCRYPTED_MESSAGES, send_response);
  otrng_response_free(alice_to_phone);

  // PHONE generates the first keys after AUTH-R has been received
  otrng_assert(bob_phone->keys->our_dh->pub);
  otrng_assert(bob_phone->keys->our_dh->priv);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // ALICE receives AUTH-I from PHONE
  alice_to_phone = otrng_response_new();
  result =
      otrng_receive_message(alice_to_phone, phone_to_alice->to_send, alice);
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

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  string_p to_send = NULL;
  const char *secret = "secret";

  // Alice sends SMP1
  otrng_assert(otrng_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                               strlen(secret), alice) == SUCCESS);
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT2);

  // Bob receives SMP1
  response_to_alice = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_alice, to_send, bob) ==
               SUCCESS);

  otrng_assert(!response_to_alice->to_send);

  free_message_and_response(response_to_alice, &to_send);

  // This will be called by bob when the OTRNG_SMPEVENT_ASK_FOR_SECRET is
  // triggered.
  otrng_assert(otrng_smp_continue(&to_send, (uint8_t *)secret, strlen(secret),
                                  bob) == SUCCESS);
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP2
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT3);

  // Alice receives SMP2
  response_to_bob = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);

  otrng_assert(response_to_bob->to_send);
  otrng_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9); // SMP3

  free(to_send);
  to_send = NULL;

  // Bob receives SMP3
  response_to_alice = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_alice,
                                     response_to_bob->to_send, bob) == SUCCESS);
  otrng_response_free(response_to_bob);

  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AAQD", response_to_alice->to_send, 9); // SMP4
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT4);

  // Alice receives SMP4
  response_to_bob = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == SUCCESS);
  otrng_response_free(response_to_alice);
  response_to_alice = NULL;

  // TODO: Should be in the correct state
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

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;
  string_p to_send = NULL;
  const char *secret = "secret";

  // Alice sends SMP1
  otrng_assert(otrng_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                               strlen(secret), alice) == SUCCESS);
  otrng_assert(to_send);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT2);

  // Bob receives SMP1
  response_to_alice = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_alice, to_send, bob) ==
               SUCCESS);

  otrng_assert(!response_to_alice->to_send);
  free_message_and_response(response_to_alice, &to_send);

  // From here
  // Bob sends SMP Abort. TODO: check it does not trigger anything else
  otrng_assert(otrng_smp_abort(&to_send, bob) == SUCCESS);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  // Alice receives SMP ABORT, send SMP_ABORT
  // TODO: Alice probably should not send and abort at this point
  response_to_bob = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);

  otrng_assert(response_to_bob->to_send);

  otrng_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9);
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);

  free_message_and_response(response_to_bob, &to_send);

  // TODO: Alice can restart here the smp. This will mem leak though
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

void test_api_extra_sym_key(void) {
  tlv_list_s *tlvs = NULL;
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 2);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_bob = NULL;
  otrng_response_s *response_to_alice = NULL;

  // Alice sends a data message
  string_p to_send = NULL;

  otrng_err result;

  result = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice);
  assert_msg_sent(result, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  // This is a follow up message.
  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);

  // Next message Bob sends is a new "ratchet"
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);

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
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);
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

  otrng_tlv_list_free(tlvs);
}

void test_unreadable_flag() {

  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 3);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  string_p to_send = NULL;
  otrng_err result;

  // Alice sends a data message with text
  result = otrng_prepare_to_send_message(&to_send, "hello", NULL, 0, alice);
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  otrl_base64_otr_decode(to_send, &decoded, &dec_len);

  assert_msg_sent(result, to_send);
  const int flag_position = 11;
  otrng_assert(decoded[flag_position] == 0);

  free(to_send);
  to_send = NULL;
  free(decoded);
  decoded = NULL;

  // Alice sends a heartbeat message
  result = otrng_prepare_to_send_message(&to_send, "", NULL, 0, alice);
  // TODO: why are we exporting this?
  otrl_base64_otr_decode(to_send, &decoded, &dec_len);

  assert_msg_sent(result, to_send);
  otrng_assert(decoded[flag_position] == MSGFLAGS_IGNORE_UNREADABLE);
  free(decoded);
  decoded = NULL;

  // Bob receives a heartbeat message
  otrng_response_s *response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send, bob);

  // TODO: these assertions are not working
  // otrng_assert(result == SUCCESS);
  otrng_assert(!response_to_alice->to_display);
  otrng_assert(!response_to_alice->to_send);

  free_message_and_response(response_to_alice, &to_send);

  alice_client_state->pad = true;

  tlv_list_s *tlvs = NULL;

  // Alice sends a heartbeat message with padding
  result = otrng_prepare_to_send_message(&to_send, "", &tlvs, 0, alice);
  otrl_base64_otr_decode(to_send, &decoded, &dec_len);

  assert_msg_sent(result, to_send);
  otrng_assert(decoded[flag_position] == MSGFLAGS_IGNORE_UNREADABLE);
  otrng_tlv_list_free(tlvs);
  free(decoded);
  decoded = NULL;

  // Bob receives a heartbeat message with padding
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send, bob);

  // TODO: these assertions are not working
  // otrng_assert(err);
  otrng_assert(!response_to_alice->to_display);
  otrng_assert(!response_to_alice->to_send);

  free_message_and_response(response_to_alice, &to_send);

  // Alice sends an smp message with padding
  const char *secret = "secret";
  otrng_assert(otrng_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                               strlen(secret), alice) == SUCCESS);
  otrng_assert(to_send);
  otrl_base64_otr_decode(to_send, &decoded, &dec_len);
  otrng_assert_cmpmem("?OTR:AAQD", to_send, 9);

  // SMP should have the IGNORE_UNREADABLE flag set
  otrng_assert(decoded[flag_position] == MSGFLAGS_IGNORE_UNREADABLE);

  free(decoded);
  decoded = NULL;
  free(to_send);
  to_send = NULL;

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

// TODO: this randomly fails
void test_heartbeat_messages() {

  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, PHI, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, PHI, 3);

  // set heartbeat wait time
  alice_client_state->heartbeat->time = 300;
  bob_client_state->heartbeat->time = 100;

  // DAKE has finished
  do_dake_fixture(alice, bob);

  string_p to_send = NULL;
  otrng_err result;
  time_t hundred_seconds_ago = time(0) - 100;

  // set last_msg_sent time in the past
  alice_client_state->heartbeat->last_msg_sent = hundred_seconds_ago;

  // Alice sends a data message with text
  result = otrng_prepare_to_send_message(&to_send, "hello", NULL, 0, alice);

  assert_msg_sent(result, to_send);
  // TODO: it fails here
  otrng_assert(alice_client_state->heartbeat->last_msg_sent == time(NULL));

  // Bob receives the msg
  otrng_response_s *response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, to_send, bob);

  assert_msg_rec(result, "hello", response_to_alice);
  free_message_and_response(response_to_alice, &to_send);

  // 100 seconds have passed
  alice_client_state->heartbeat->last_msg_sent = hundred_seconds_ago;
  bob_client_state->heartbeat->last_msg_sent = hundred_seconds_ago;

  // Alice doesn't send a heartbeat
  result = otrng_heartbeat_checker(&to_send, alice);
  otrng_assert(result == SUCCESS);
  otrng_assert(to_send == NULL);
  otrng_assert(alice_client_state->heartbeat->last_msg_sent ==
               hundred_seconds_ago);

  // Bob sends a heartbeat
  result = otrng_heartbeat_checker(&to_send, bob);
  otrng_assert(result == SUCCESS);
  otrng_assert(to_send != NULL);
  otrng_assert(bob_client_state->heartbeat->last_msg_sent == time(0));

  // Alice receives the heartbeat
  otrng_response_s *response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, to_send, bob);

  otrng_assert(result == SUCCESS);
  otrng_assert(!response_to_bob->to_display);
  otrng_assert(!response_to_bob->to_send);

  free_message_and_response(response_to_bob, &to_send);
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}
