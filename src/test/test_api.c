#include <libotr/b64.h>
#include <libotr/privkey.h>
#include <string.h>

#include "../list.h"
#include "../otrng.h"
#include "../str.h"

#define assert_msg_sent(err, to_send)                                          \
  do {                                                                         \
    otrng_assert(err == SUCCESS);                                              \
    otrng_assert(to_send);                                                     \
    otrng_assert_cmpmem("?OTR:AAQD", to_send, 9);                              \
  } while (0);

#define assert_msg_rec(err, message, response)                                 \
  do {                                                                         \
    otrng_assert(err == SUCCESS);                                              \
    otrng_assert_cmpmem(message, response->to_display, strlen(message) + 1);   \
    otrng_assert(response->to_send == NULL);                                   \
  } while (0);

#define assert_rec_msg_inc_state(result, respond_to, sender, otr_state,        \
                                 send_response)                                \
  do {                                                                         \
    otrng_assert((result) == SUCCESS);                                         \
    otrng_assert(!respond_to->to_display);                                     \
    otrng_assert(sender->state == otr_state);                                  \
    if (send_response) {                                                       \
      otrng_assert(respond_to->to_send);                                       \
    } else {                                                                   \
      otrng_assert(!respond_to->to_send);                                      \
    }                                                                          \
  } while (0);

static void free_message_and_response(otrng_response_t *response,
                                      string_t *message) {
  otrng_response_free(response);
  free(*message);
  *message = NULL;
}

static void set_up_client_state(otrng_client_state_t *state,
                                const char *account_name, const char *phi,
                                int byte) {
  state->userstate = otrl_userstate_create();
  state->account_name = otrng_strdup(account_name);
  state->protocol_name = otrng_strdup("otr");
  // on client this will probably be the jid and the
  // receipient jid for the party
  state->phi = otrng_strdup(phi);
  state->pad = false;

  uint8_t sym_key[ED448_PRIVATE_BYTES] = {byte};
  otrng_client_state_add_private_key_v4(state, sym_key);
  otrng_client_state_add_shared_prekey_v4(state, sym_key);
  otrng_client_state_add_instance_tag(state, 0x100 + byte);
}

// TODO: a cliente state is not part of a otr creation
static otrng_t *set_up_otr(otrng_client_state_t *state,
                           const char *account_name, const char *phi,
                           int byte) {
  set_up_client_state(state, account_name, phi, byte);

  otrng_policy_t policy = {.allows = OTRNG_ALLOW_V3 | OTRNG_ALLOW_V4};

  return otrng_new(state, policy);
}

void test_api_interactive_conversation(void) {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  bob_state->pad = true;
  alice_state->pad = true;

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  int message_id;
  otrng_response_t *response_to_bob = NULL;
  otrng_response_t *response_to_alice = NULL;

  // Alice sends a data message
  string_t to_send = NULL;
  tlv_t *tlvs = NULL;
  otrng_err_t err;

  for (message_id = 2; message_id < 5; message_id++) {
    err = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice);
    assert_msg_sent(err, to_send);
    otrng_assert(tlvs);
    otrng_assert(!alice->keys->old_mac_keys);

    // This is a follow up message.
    g_assert_cmpint(alice->keys->i, ==, 0);
    g_assert_cmpint(alice->keys->j, ==, message_id);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    otrng_err_t err = otrng_receive_message(response_to_alice, to_send, bob);
    assert_msg_rec(err, "hi", response_to_alice);
    otrng_assert(bob->keys->old_mac_keys);

    free_message_and_response(response_to_alice, &to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==,
                    message_id - 1);

    // Next message Bob sends is a new "ratchet"
    g_assert_cmpint(bob->keys->i, ==, 0);
    g_assert_cmpint(bob->keys->j, ==, 0);
  }

  for (message_id = 1; message_id < 4; message_id++) {
    // Bob sends a data message
    err = otrng_prepare_to_send_message(&to_send, "hello", &tlvs, 0, bob);
    assert_msg_sent(err, to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

    // New ratchet hapenned
    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, message_id);

    // Alice receives a data message
    response_to_bob = otrng_response_new();
    otrng_err_t err = otrng_receive_message(response_to_bob, to_send, alice);
    assert_msg_rec(err, "hello", response_to_bob);
    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, message_id);

    free_message_and_response(response_to_bob, &to_send);

    // Alice follows the ratchet 1 (and prepares to a new "ratchet")
    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, 0);
  }

  otrng_tlv_free(tlvs);

  uint16_t tlv_len = 2;
  uint8_t tlv_data[2] = {0x08, 0x05};
  tlvs = otrng_tlv_new(OTRNG_TLV_SMP_MSG_1, tlv_len, tlv_data);
  otrng_assert(tlvs);

  // Bob sends a message with TLV
  err = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, bob);
  assert_msg_sent(err, to_send);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);
  otrng_tlv_free(tlvs);

  // Alice receives a data message with TLV
  response_to_bob = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 4);

  // Check TLVS
  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->type, ==, OTRNG_TLV_SMP_MSG_1);
  g_assert_cmpint(response_to_bob->tlvs->len, ==, tlv_len);
  otrng_assert_cmpmem(response_to_bob->tlvs->data, tlv_data, tlv_len);

  // Check Padding
  otrng_assert(response_to_bob->tlvs->next);
  g_assert_cmpint(response_to_bob->tlvs->next->type, ==, OTRNG_TLV_PADDING);
  g_assert_cmpint(response_to_bob->tlvs->next->len, ==, 249);

  free_message_and_response(response_to_bob, &to_send);
  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);

  OTRNG_FREE;
}

// TODO: the way that i and j is being handled is not competly correct
// apparently. Including this test for reference
void test_api_interactive_conversation_bob(void) {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  bob_state->pad = true;
  alice_state->pad = true;

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  int message_id;
  otrng_response_t *response_to_bob = NULL;
  otrng_response_t *response_to_alice = NULL;

  // Bob sends a data message
  string_t to_send = NULL;
  tlv_t *tlvs = NULL;
  otrng_err_t err;

  for (message_id = 2; message_id < 5; message_id++) {
    err = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, bob);
    assert_msg_sent(err, to_send);
    otrng_assert(tlvs);
    otrng_assert(!bob->keys->old_mac_keys);

    // This is a follow up message.
    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, message_id);

    // Alice receives a data message
    response_to_alice = otrng_response_new();
    otrng_err_t err = otrng_receive_message(response_to_alice, to_send, alice);
    assert_msg_rec(err, "hi", response_to_alice);
    otrng_assert(alice->keys->old_mac_keys);

    free_message_and_response(response_to_alice, &to_send);

    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==,
                    message_id - 1);

    // Next message Bob sends is a new "ratchet"
    g_assert_cmpint(alice->keys->i, ==, 0);
    g_assert_cmpint(alice->keys->j, ==, 0);
  }

  otrng_tlv_free(tlvs);

  free_message_and_response(response_to_bob, &to_send);
  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);

  OTRNG_FREE;
}

void test_api_non_interactive_conversation(void) {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  otrng_response_t *response_to_bob = otrng_response_new();
  otrng_response_t *response_to_alice = otrng_response_new();

  otrng_server_t *server = malloc(sizeof(otrng_server_t));
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

  // Bob receives prekey message
  otrng_assert(otrng_receive_message(response_to_alice,
                                     response_to_bob->to_send, bob) == SUCCESS);
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  otrng_assert(bob->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(bob->keys->current);

  otrng_assert_ec_public_key_eq(bob->keys->their_ecdh,
                                alice->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(bob->keys->their_dh, alice->keys->our_dh->pub);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  otrng_assert(otrng_send_non_interactive_auth_msg(&response_to_alice->to_send,
                                                   bob, "") == SUCCESS);

  // Should send an non interactive auth
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AASN", response_to_alice->to_send, 9);

  // Alice receives an non interactive auth
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

  // Check double ratchet is initialized
  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(alice->keys->current);

  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // Both have the same shared secret
  otrng_assert_root_key_eq(alice->keys->current->root_key,
                           bob->keys->current->root_key);
  otrng_assert_chain_key_eq(alice->keys->current->chain_a->key,
                            bob->keys->current->chain_a->key);
  otrng_assert_chain_key_eq(bob->keys->current->chain_b->key,
                            alice->keys->current->chain_b->key);

  chain_key_t bob_sending_key, alice_receiving_key;
  key_manager_get_sending_chain_key(bob_sending_key, bob->keys);
  otrng_assert(key_manager_get_receiving_chain_key(alice_receiving_key, 0,
                                                   alice->keys) == SUCCESS);
  otrng_assert_chain_key_eq(bob_sending_key, alice_receiving_key);

  int message_id;

  // Bob sends a data message
  string_t to_send = NULL;
  tlv_t *tlv = NULL;
  otrng_err_t err;

  // TODO: this is usually set up by the querry or whitespace,
  // this will be defined on the prekey server spec.
  bob->running_version = OTRNG_VERSION_4;
  alice->running_version = OTRNG_VERSION_4;

  for (message_id = 2; message_id < 5; message_id++) {
    err = otrng_prepare_to_send_message(&to_send, "hi", &tlv, 0, alice);
    assert_msg_sent(err, to_send);
    otrng_assert(!alice->keys->old_mac_keys);

    // This is a follow up message.
    g_assert_cmpint(alice->keys->i, ==, 0);
    g_assert_cmpint(alice->keys->j, ==, message_id);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    otrng_err_t err = otrng_receive_message(response_to_alice, to_send, bob);
    assert_msg_rec(err, "hi", response_to_alice);
    otrng_assert(bob->keys->old_mac_keys);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==,
                    message_id - 1);

    // Next message Bob sends is a new "ratchet"
    g_assert_cmpint(bob->keys->i, ==, 0);
    g_assert_cmpint(bob->keys->j, ==, 0);

    free_message_and_response(response_to_alice, &to_send);
  }

  for (message_id = 1; message_id < 4; message_id++) {
    // Bob sends a data message
    err = otrng_prepare_to_send_message(&to_send, "hello", &tlv, 0, bob);
    assert_msg_sent(err, to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

    // New ratchet hapenned
    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, message_id);

    // Alice receives a data message
    response_to_bob = otrng_response_new();
    otrng_err_t err = otrng_receive_message(response_to_bob, to_send, alice);
    assert_msg_rec(err, "hello", response_to_bob);
    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, message_id);

    // Alice follows the ratchet 1 (and prepares to a new "ratchet")
    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, 0);

    free_message_and_response(response_to_bob, &to_send);
  }

  uint16_t tlv_len = 2;
  uint8_t tlv_data[2] = {0x08, 0x05};
  tlv_t *tlvs = otrng_tlv_new(OTRNG_TLV_SMP_MSG_1, tlv_len, tlv_data);
  otrng_assert(tlvs);

  // Bob sends a message with TLV
  err = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, bob);
  assert_msg_sent(err, to_send);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);
  otrng_tlv_free(tlvs);

  // Alice receives a data message with TLV
  response_to_bob = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 4);

  // Check TLVS
  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->type, ==, OTRNG_TLV_SMP_MSG_1);
  g_assert_cmpint(response_to_bob->tlvs->len, ==, tlv_len);
  otrng_assert_cmpmem(response_to_bob->tlvs->data, tlv_data, tlv_len);

  free_message_and_response(response_to_bob, &to_send);

  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);

  otrng_free_all(alice, bob);

  otrng_tlv_free(tlv);

  OTRNG_FREE;
}

void test_api_non_interactive_conversation_with_enc_msg(void) {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  otrng_response_t *response_to_bob = otrng_response_new();
  otrng_response_t *response_to_alice = otrng_response_new();

  otrng_server_t *server = malloc(sizeof(otrng_server_t));
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

  // Bob receives prekey message
  otrng_assert(otrng_receive_message(response_to_alice,
                                     response_to_bob->to_send, bob) == SUCCESS);

  otrng_assert(bob->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(bob->keys->current);

  otrng_assert_ec_public_key_eq(bob->keys->their_ecdh,
                                alice->keys->our_ecdh->pub);
  otrng_assert_dh_public_key_eq(bob->keys->their_dh, alice->keys->our_dh->pub);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  otrng_assert(otrng_send_non_interactive_auth_msg(&response_to_alice->to_send,
                                                   bob, "hi") == SUCCESS);

  // Should send an non interactive auth
  otrng_assert(response_to_alice->to_display == NULL);
  otrng_assert(response_to_alice->to_send);
  otrng_assert_cmpmem("?OTR:AASN", response_to_alice->to_send, 9);

  // Alice receives an non interactive auth
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

  // Check double ratchet is initialized
  otrng_assert(alice->state == OTRNG_STATE_ENCRYPTED_MESSAGES);
  otrng_assert(alice->keys->current);

  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // Both have the same shared secret
  otrng_assert_root_key_eq(alice->keys->current->root_key,
                           bob->keys->current->root_key);
  otrng_assert_chain_key_eq(alice->keys->current->chain_a->key,
                            bob->keys->current->chain_a->key);
  otrng_assert_chain_key_eq(bob->keys->current->chain_b->key,
                            alice->keys->current->chain_b->key);

  chain_key_t bob_sending_key, alice_receiving_key;
  key_manager_get_sending_chain_key(bob_sending_key, bob->keys);
  otrng_assert(key_manager_get_receiving_chain_key(alice_receiving_key, 0,
                                                   alice->keys) == SUCCESS);
  otrng_assert_chain_key_eq(bob_sending_key, alice_receiving_key);

  int message_id;

  // Bob sends a data message
  string_t to_send = NULL;
  tlv_t *tlv = NULL;
  otrng_err_t err;

  // TODO: this is usually set up by the querry or whitespace,
  // this will be defined on the prekey server spec.
  bob->running_version = OTRNG_VERSION_4;
  alice->running_version = OTRNG_VERSION_4;

  for (message_id = 2; message_id < 5; message_id++) {
    err = otrng_prepare_to_send_message(&to_send, "hi", &tlv, 0, alice);
    assert_msg_sent(err, to_send);
    otrng_assert(!alice->keys->old_mac_keys);

    // This is a follow up message.
    g_assert_cmpint(alice->keys->i, ==, 0);
    g_assert_cmpint(alice->keys->j, ==, message_id);

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    otrng_err_t err = otrng_receive_message(response_to_alice, to_send, bob);
    assert_msg_rec(err, "hi", response_to_alice);
    otrng_assert(bob->keys->old_mac_keys);

    free_message_and_response(response_to_alice, &to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==,
                    message_id - 1);

    // Next message Bob sends is a new "ratchet"
    g_assert_cmpint(bob->keys->i, ==, 0);
    g_assert_cmpint(bob->keys->j, ==, 0);
  }

  for (message_id = 1; message_id < 4; message_id++) {
    // Bob sends a data message
    err = otrng_prepare_to_send_message(&to_send, "hello", &tlv, 0, bob);
    assert_msg_sent(err, to_send);

    g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

    // New ratchet hapenned
    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, message_id);

    // Alice receives a data message
    response_to_bob = otrng_response_new();
    otrng_err_t err = otrng_receive_message(response_to_bob, to_send, alice);
    assert_msg_rec(err, "hello", response_to_bob);
    g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, message_id);

    free_message_and_response(response_to_bob, &to_send);

    // Alice follows the ratchet 1 (and prepares to a new "ratchet")
    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, 0);
  }

  uint16_t tlv_len = 2;
  uint8_t tlv_data[2] = {0x08, 0x05};
  tlv_t *tlvs = otrng_tlv_new(OTRNG_TLV_SMP_MSG_1, tlv_len, tlv_data);
  otrng_assert(tlvs);

  // Bob sends a message with TLV
  err = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, bob);
  assert_msg_sent(err, to_send);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);
  otrng_tlv_free(tlvs);

  // Alice receives a data message with TLV
  response_to_bob = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 4);

  // Check TLVS
  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->type, ==, OTRNG_TLV_SMP_MSG_1);
  g_assert_cmpint(response_to_bob->tlvs->len, ==, tlv_len);
  otrng_assert_cmpmem(response_to_bob->tlvs->data, tlv_data, tlv_len);

  free_message_and_response(response_to_bob, &to_send);

  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);

  otrng_free_all(alice, bob);

  otrng_tlv_free(tlv);

  OTRNG_FREE;
}

void test_api_conversation_errors(void) {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  bob_state->pad = true;
  alice_state->pad = true;

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  int message_id = 2;
  otrng_response_t *response_to_alice = NULL;
  otrng_response_t *response_to_bob = NULL;

  // Alice sends a data message
  string_t to_send = NULL;
  tlv_t *tlvs = NULL;
  otrng_err_t err;

  err = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice);
  assert_msg_sent(err, to_send);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);

  // This is a follow up message.
  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, message_id);

  // To trigger the error message
  bob->state = OTRNG_STATE_START;

  // Bob receives a data message in the incorrect state
  response_to_alice = otrng_response_new();
  err = otrng_receive_message(response_to_alice, to_send, bob);

  string_t err_code = "?OTR Error: ERROR_2: OTRNG_ERR_MSG_NOT_PRIVATE_STATE";
  otrng_assert_cmpmem(err_code, response_to_alice->to_send, strlen(err_code));

  otrng_assert(err == ERROR);
  otrng_assert(response_to_alice->to_send != NULL);
  otrng_assert(!bob->keys->old_mac_keys);
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  response_to_bob = otrng_response_new();
  err =
      otrng_receive_message(response_to_bob, response_to_alice->to_send, alice);

  otrng_assert(err == SUCCESS);
  otrng_assert(response_to_bob);
  otrng_assert_cmpmem(err_code, response_to_bob->to_display, strlen(err_code));

  otrng_response_free(response_to_alice);
  otrng_response_free(response_to_bob);
  free(to_send);
  to_send = NULL;

  // Alice sends another data message
  err = otrng_prepare_to_send_message(&to_send, "hi", &tlvs, 0, alice);
  assert_msg_sent(err, to_send);
  otrng_assert(tlvs);
  otrng_assert(!alice->keys->old_mac_keys);

  bob->state = OTRNG_STATE_ENCRYPTED_MESSAGES;
  bob->keys->j = 15;

  // Bob receives a non valid data message
  response_to_alice = otrng_response_new();
  err = otrng_receive_message(response_to_alice, to_send, bob);

  otrng_assert(err == MSG_NOT_VALID);
  otrng_assert(response_to_alice->to_send == NULL);
  otrng_assert(response_to_alice->warning == OTRNG_WARN_RECEIVED_NOT_VALID);

  otrng_tlv_free(tlvs);

  free_message_and_response(response_to_alice, &to_send);
  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);

  OTRNG_FREE;
}

static void do_ake_v3(otrng_t *alice, otrng_t *bob) {
  otrng_response_t *response_to_bob = otrng_response_new();
  otrng_response_t *response_to_alice = otrng_response_new();

  // Alice sends query message
  string_t query_message = NULL;
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
  OTRNG_INIT;
  tlv_t *tlv = NULL;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  set_up_client_state(alice_state, ALICE_IDENTITY, PHI, 1);

  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);
  set_up_client_state(bob_state, BOB_IDENTITY, PHI, 2);

  otrng_policy_t policy = {.allows = OTRNG_ALLOW_V3};
  otrng_t *alice = otrng_new(alice_state, policy);
  otrng_t *bob = otrng_new(bob_state, policy);

  // Set up v3 context
  alice->v3_conn = otrng_v3_conn_new(alice_state, "bob");
  bob->v3_conn = otrng_v3_conn_new(bob_state, "alice");

  // Generate long term private key.
  FILE *tmpFILEp;
  tmpFILEp = tmpfile();
  otrng_assert(!otrl_privkey_generate_FILEp(alice_state->userstate, tmpFILEp,
                                            alice_state->account_name,
                                            alice_state->protocol_name));
  fclose(tmpFILEp);

  tmpFILEp = tmpfile();
  otrng_assert(!otrl_privkey_generate_FILEp(bob_state->userstate, tmpFILEp,
                                            bob_state->account_name,
                                            bob_state->protocol_name));
  fclose(tmpFILEp);

  // Generate instance tag
  otrng_client_state_add_instance_tag(alice_state, 0x100 + 1);
  otrng_client_state_add_instance_tag(bob_state, 0x100 + 2);

  // AKE HAS FINISHED.
  do_ake_v3(alice, bob);

  otrng_response_t *response_to_bob = NULL;
  otrng_response_t *response_to_alice = NULL;
  string_t to_send = NULL;

  // Alice sends a data message
  otrng_assert(otrng_prepare_to_send_message(&to_send, "hi", &tlv, 0, alice) ==
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
  otrng_assert(otrng_prepare_to_send_message(&to_send, "hi", &tlv, 0, bob) ==
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

  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_free_all(alice, bob);
  otrng_client_state_free_all(alice_state, bob_state);

  otrng_tlv_free(tlv);

  OTRNG_FREE;
}

void test_api_multiple_clients(void) {
  OTRNG_INIT;

  bool send_response = true;
  otrng_err_t err;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_phone_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_pc_state = otrng_client_state_new(NULL);

  // The account name should be the same. The account can be logged
  // on different clients. Instance tags are used for that. This
  // account name can be used as phi.
  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob_phone = set_up_otr(bob_phone_state, BOB_IDENTITY, PHI, 2);
  otrng_t *bob_pc = set_up_otr(bob_pc_state, BOB_IDENTITY, PHI, 3);

  otrng_response_t *pc_to_alice = otrng_response_new();
  otrng_response_t *phone_to_alice = otrng_response_new();
  otrng_response_t *alice_to_pc = otrng_response_new();
  otrng_response_t *alice_to_phone = otrng_response_new();

  // PC receives query msg and sends identity msg
  err = otrng_receive_message(pc_to_alice, "?OTRv4?", bob_pc);
  assert_rec_msg_inc_state(err, pc_to_alice, bob_pc, OTRNG_STATE_WAITING_AUTH_R,
                           send_response);

  // PHONE receives query msg and sends identity msg
  err = otrng_receive_message(phone_to_alice, "?OTRv4?", bob_phone);
  assert_rec_msg_inc_state(err, phone_to_alice, bob_phone,
                           OTRNG_STATE_WAITING_AUTH_R, send_response);

  // ALICE receives Identity msg from PC and sends AUTH-R
  err = otrng_receive_message(alice_to_pc, pc_to_alice->to_send, alice);
  assert_rec_msg_inc_state(err, alice_to_pc, alice, OTRNG_STATE_WAITING_AUTH_I,
                           send_response);
  otrng_response_free(pc_to_alice);

  // ALICE receives Identity msg from PHONE (on state
  // OTRNG_STATE_WAITING_AUTH_I) and sends AUTH-R. ALICE will replace keys and
  // profile info from PC with info from PHONE.
  err = otrng_receive_message(alice_to_phone, phone_to_alice->to_send, alice);
  assert_rec_msg_inc_state(err, alice_to_phone, alice,
                           OTRNG_STATE_WAITING_AUTH_I, send_response);
  otrng_response_free(phone_to_alice);

  // PC receives AUTH-R succesfully
  pc_to_alice = otrng_response_new();
  err = otrng_receive_message(pc_to_alice, alice_to_pc->to_send, bob_pc);
  assert_rec_msg_inc_state(err, pc_to_alice, bob_pc,
                           OTRNG_STATE_ENCRYPTED_MESSAGES, send_response);

  // PC deletes private keys as AUTH-R succesful
  otrng_assert(bob_pc->keys->our_dh->pub);
  otrng_assert(!bob_pc->keys->our_dh->priv);

  otrng_assert_not_zero(bob_pc->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_zero(bob_pc->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // PHONE receives AUTH-R with PC instance tag - Ignores
  phone_to_alice = otrng_response_new();
  err = otrng_receive_message(phone_to_alice, alice_to_pc->to_send, bob_phone);
  assert_rec_msg_inc_state(err, phone_to_alice, bob_phone,
                           OTRNG_STATE_WAITING_AUTH_R, !send_response);
  otrng_response_free_all(phone_to_alice, alice_to_pc);

  // PHONE does NOT remove the private keys yet - needed for AUTH-I when it
  // actually receives an AUTH-R
  otrng_assert(bob_phone->keys->our_dh->pub);
  otrng_assert(bob_phone->keys->our_dh->priv);

  otrng_assert_not_zero(bob_phone->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // ALICE receives AUTH-I from PC - Authentication fails
  alice_to_pc = otrng_response_new();
  err = otrng_receive_message(alice_to_pc, pc_to_alice->to_send, alice);

  assert_rec_msg_inc_state(!err, alice_to_pc, alice, OTRNG_STATE_WAITING_AUTH_I,
                           !send_response);

  otrng_response_free_all(pc_to_alice, alice_to_pc);

  // PC receives AUTH-R again - ignores
  pc_to_alice = otrng_response_new();
  err = otrng_receive_message(pc_to_alice, alice_to_phone->to_send, bob_pc);
  assert_rec_msg_inc_state(err, pc_to_alice, bob_pc,
                           OTRNG_STATE_ENCRYPTED_MESSAGES, !send_response);
  otrng_response_free(pc_to_alice);

  // PHONE receives correct AUTH-R message and sends AUTH-I
  phone_to_alice = otrng_response_new();
  err =
      otrng_receive_message(phone_to_alice, alice_to_phone->to_send, bob_phone);
  assert_rec_msg_inc_state(err, phone_to_alice, bob_phone,
                           OTRNG_STATE_ENCRYPTED_MESSAGES, send_response);
  otrng_response_free(alice_to_phone);

  // PHONE can now delete private keys
  otrng_assert(bob_phone->keys->our_dh->pub);
  otrng_assert(!bob_phone->keys->our_dh->priv);
  otrng_assert_not_zero(bob_phone->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_zero(bob_phone->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // ALICE receives AUTH-I from PHONE
  alice_to_phone = otrng_response_new();
  err = otrng_receive_message(alice_to_phone, phone_to_alice->to_send, alice);
  assert_rec_msg_inc_state(err, alice_to_phone, alice,
                           OTRNG_STATE_ENCRYPTED_MESSAGES, !send_response);

  // ALICE and PHONE have the same shared secret
  otrng_assert_root_key_eq(alice->keys->current->root_key,
                           bob_phone->keys->current->root_key);
  otrng_assert_chain_key_eq(alice->keys->current->chain_a->key,
                            bob_phone->keys->current->chain_a->key);
  otrng_assert_chain_key_eq(bob_phone->keys->current->chain_b->key,
                            alice->keys->current->chain_b->key);

  otrng_response_free_all(phone_to_alice, alice_to_phone);
  otrng_userstate_free_all(alice_state->userstate, bob_phone_state->userstate,
                           bob_pc_state->userstate);
  otrng_client_state_free_all(alice_state, bob_pc_state, bob_phone_state);
  otrng_free_all(alice, bob_pc, bob_phone);

  OTRNG_FREE;
}

void test_api_smp(void) {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_t *response_to_bob = NULL;
  otrng_response_t *response_to_alice = NULL;
  string_t to_send = NULL;
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

  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);

  OTRNG_FREE;
}

void test_api_smp_abort(void) {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_t *response_to_bob = NULL;
  otrng_response_t *response_to_alice = NULL;
  string_t to_send = NULL;
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
  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);

  OTRNG_FREE;
}

void test_api_extra_sym_key(void) {
  OTRNG_INIT;

  tlv_t *tlv = NULL;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrng_response_t *response_to_bob = NULL;
  otrng_response_t *response_to_alice = NULL;

  // Alice sends a data message
  string_t to_send = NULL;

  otrng_err_t err;

  err = otrng_prepare_to_send_message(&to_send, "hi", &tlv, 0, alice);
  assert_msg_sent(err, to_send);
  otrng_assert(!alice->keys->old_mac_keys);

  // This is a follow up message.
  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 2);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  err = otrng_receive_message(response_to_alice, to_send, bob);
  assert_msg_rec(err, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);

  // Next message Bob sends is a new "ratchet"
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  uint16_t tlv_len = 6;
  uint8_t tlv_data[6] = {0x08, 0x05, 0x09, 0x00, 0x02, 0x04};
  // Bob sends a message with TLV
  int use = 134547712;
  uint8_t usedata[2] = {0x02, 0x04};
  uint16_t usedatalen = 2;
  err = otrng_send_symkey_message(&to_send, use, usedata, usedatalen,
                                  bob->keys->extra_key, bob);
  assert_msg_sent(err, to_send);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  // Alice receives a data message with TLV
  response_to_bob = otrng_response_new();
  otrng_assert(otrng_receive_message(response_to_bob, to_send, alice) ==
               SUCCESS);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 1);

  // Check TLVS
  otrng_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->type, ==, OTRNG_TLV_SYM_KEY);
  g_assert_cmpint(response_to_bob->tlvs->len, ==, tlv_len);
  otrng_assert_cmpmem(response_to_bob->tlvs->data, tlv_data, tlv_len);

  otrng_assert(!response_to_bob->tlvs->next);

  free_message_and_response(response_to_bob, &to_send);

  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);

  otrng_tlv_free(tlv);

  OTRNG_FREE;
}

void test_dh_key_rotation(void) {
  OTRNG_INIT;
  tlv_t *tlv = NULL;
  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  int ratchet_id;
  otrng_response_t *response_to_bob = NULL;
  otrng_response_t *response_to_alice = NULL;

  // Bob sends a data message
  string_t to_send = NULL;
  otrng_err_t err;

  for (ratchet_id = 1; ratchet_id < 6; ratchet_id += 2) {
    // Bob sends a data message
    err = otrng_prepare_to_send_message(&to_send, "hello", &tlv, 0, bob);
    assert_msg_sent(err, to_send);

    // New ratchet happened
    g_assert_cmpint(bob->keys->i, ==, ratchet_id);
    g_assert_cmpint(bob->keys->j, ==, 1);

    // Alice receives a data message
    response_to_bob = otrng_response_new();
    otrng_err_t err = otrng_receive_message(response_to_bob, to_send, alice);
    assert_msg_rec(err, "hello", response_to_bob);

    // Alice follows the ratchet 1 (and prepares to a new "ratchet")
    g_assert_cmpint(alice->keys->i, ==, ratchet_id);
    g_assert_cmpint(alice->keys->j, ==, 0); // New ratchet should happen

    // Alice deletes priv key when receiving on ratchet 3
    if (ratchet_id == 1) {
      otrng_assert(alice->keys->our_dh->priv);
      otrng_assert(!bob->keys->our_dh->priv);
    } else if (ratchet_id == 3 || ratchet_id == 5) {
      otrng_assert(!alice->keys->our_dh->priv);
      otrng_assert(bob->keys->our_dh->priv);
    }

    free_message_and_response(response_to_bob, &to_send);

    // Now alice ratchets and sends a data message
    err = otrng_prepare_to_send_message(&to_send, "hi", &tlv, 0, alice);
    assert_msg_sent(err, to_send);

    g_assert_cmpint(alice->keys->i, ==, ratchet_id + 1);
    g_assert_cmpint(alice->keys->j, ==, 1);

    if (ratchet_id == 3) {
      otrng_assert(!alice->keys->our_dh->priv);
      otrng_assert(bob->keys->our_dh->priv);
    }

    // Bob receives a data message
    response_to_alice = otrng_response_new();
    err = otrng_receive_message(response_to_alice, to_send, bob);
    assert_msg_rec(err, "hi", response_to_alice);

    free_message_and_response(response_to_alice, &to_send);

    g_assert_cmpint(bob->keys->i, ==, ratchet_id + 1);
    g_assert_cmpint(bob->keys->j, ==, 0); // New ratchet should happen

    // Bob deletes priv key when receiving on ratchet 6
    if (ratchet_id + 1 == 2 || ratchet_id + 1 == 6) {
      otrng_assert(alice->keys->our_dh->priv);
      otrng_assert(!bob->keys->our_dh->priv);
    } else if (ratchet_id + 1 == 4) {
      otrng_assert(!alice->keys->our_dh->priv);
      otrng_assert(bob->keys->our_dh->priv);
    }
  }

  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);
  otrng_tlv_free(tlv);

  OTRNG_FREE;
}

void test_ecdh_priv_keys_destroyed_early() {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 2);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrng_response_t *response_to_bob = NULL;
  otrng_response_t *response_to_alice = NULL;
  string_t to_send = NULL;
  otrng_err_t err;

  // Alice sends a data message
  err = otrng_prepare_to_send_message(&to_send, "hi", NULL, 0, alice);
  assert_msg_sent(err, to_send);

  // Follow up message
  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 2);

  // Alice should not delete ECDH priv key
  otrng_assert_not_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  err = otrng_receive_message(response_to_alice, to_send, bob);
  assert_msg_rec(err, "hi", response_to_alice);

  free_message_and_response(response_to_alice, &to_send);

  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  // Bob's ECDH priv key should be zero still from the DAKE
  otrng_assert_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Bob sends a data message
  err = otrng_prepare_to_send_message(&to_send, "hello", NULL, 0, bob);
  assert_msg_sent(err, to_send);

  // New ratchet
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 1);

  // Bob's ECDH priv key should not be zero after sending
  otrng_assert_not_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  err = otrng_receive_message(response_to_bob, to_send, alice);
  assert_msg_rec(err, "hello", response_to_bob);

  free_message_and_response(response_to_bob, &to_send);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 0);

  // Alice should delete ECDH priv key
  otrng_assert_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Alice sends a data message
  err = otrng_prepare_to_send_message(&to_send, "hi", NULL, 0, alice);
  assert_msg_sent(err, to_send);

  // New ratchet
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // Alice should NOT delete ECDH priv key
  otrng_assert_not_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  err = otrng_receive_message(response_to_alice, to_send, bob);
  assert_msg_rec(err, "hi", response_to_alice);

  free_message_and_response(response_to_alice, &to_send);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 0);

  // Bob should delete ECDH priv key
  otrng_assert_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);

  OTRNG_FREE;
}

void test_unreadable_flag() {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 3);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  string_t to_send = NULL;
  otrng_err_t err;

  // Alice sends a data message with text
  err = otrng_prepare_to_send_message(&to_send, "hello", NULL, 0, alice);
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  otrl_base64_otr_decode(to_send, &decoded, &dec_len);

  assert_msg_sent(err, to_send);
  const int flag_position = 11;
  otrng_assert(decoded[flag_position] == 0);

  free(to_send);
  to_send = NULL;
  free(decoded);
  decoded = NULL;

  // Alice sends a heartbeat message
  err = otrng_prepare_to_send_message(&to_send, "", NULL, 0, alice);
  otrl_base64_otr_decode(to_send, &decoded, &dec_len);

  assert_msg_sent(err, to_send);
  otrng_assert(decoded[flag_position] == MSGFLAGS_IGNORE_UNREADABLE);
  free(decoded);
  decoded = NULL;

  // Bob receives a heartbeat message
  otrng_response_t *response_to_alice = otrng_response_new();
  err = otrng_receive_message(response_to_alice, to_send, bob);

  otrng_assert(err == SUCCESS);
  otrng_assert(!response_to_alice->to_display);
  otrng_assert(!response_to_alice->to_send);

  free_message_and_response(response_to_alice, &to_send);

  alice_state->pad = true;

  tlv_t *tlv = NULL;

  // Alice sends a heartbeat message with padding
  err = otrng_prepare_to_send_message(&to_send, "", &tlv, 0, alice);
  otrl_base64_otr_decode(to_send, &decoded, &dec_len);

  assert_msg_sent(err, to_send);
  otrng_assert(decoded[flag_position] == MSGFLAGS_IGNORE_UNREADABLE);
  otrng_tlv_free(tlv);
  free(decoded);
  decoded = NULL;

  // Bob receives a heartbeat message with padding
  response_to_alice = otrng_response_new();
  err = otrng_receive_message(response_to_alice, to_send, bob);

  otrng_assert(err == SUCCESS);
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

  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);

  OTRNG_FREE;
}

void test_heartbeat_messages() {
  OTRNG_INIT;

  otrng_client_state_t *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_t *bob_state = otrng_client_state_new(NULL);

  otrng_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, PHI, 1);
  otrng_t *bob = set_up_otr(bob_state, BOB_IDENTITY, PHI, 3);

  // set heartbeat wait time
  alice_state->heartbeat->time = 300;
  bob_state->heartbeat->time = 100;

  // DAKE has finished
  do_dake_fixture(alice, bob);

  string_t to_send = NULL;
  otrng_err_t err;
  time_t hundred_seconds_ago = time(0) - 100;

  // set last_msg_sent time in the past
  alice_state->heartbeat->last_msg_sent = hundred_seconds_ago;

  // Alice sends a data message with text
  err = otrng_prepare_to_send_message(&to_send, "hello", NULL, 0, alice);

  assert_msg_sent(err, to_send);
  otrng_assert(alice_state->heartbeat->last_msg_sent == time(0));

  // Bob receives the msg
  otrng_response_t *response_to_alice = otrng_response_new();
  err = otrng_receive_message(response_to_alice, to_send, bob);

  assert_msg_rec(err, "hello", response_to_alice);
  free_message_and_response(response_to_alice, &to_send);

  // 100 seconds have passed
  alice_state->heartbeat->last_msg_sent = hundred_seconds_ago;
  bob_state->heartbeat->last_msg_sent = hundred_seconds_ago;

  // Alice doesn't send a heartbeat
  err = otrng_heartbeat_checker(&to_send, alice);
  otrng_assert(err == SUCCESS);
  otrng_assert(to_send == NULL);
  otrng_assert(alice_state->heartbeat->last_msg_sent == hundred_seconds_ago);

  // Bob sends a heartbeat
  err = otrng_heartbeat_checker(&to_send, bob);
  otrng_assert(err == SUCCESS);
  otrng_assert(to_send != NULL);
  otrng_assert(bob_state->heartbeat->last_msg_sent == time(0));

  // Alice receives the heartbeat
  otrng_response_t *response_to_bob = otrng_response_new();
  err = otrng_receive_message(response_to_bob, to_send, bob);

  otrng_assert(err == SUCCESS);
  otrng_assert(!response_to_bob->to_display);
  otrng_assert(!response_to_bob->to_send);

  free_message_and_response(response_to_bob, &to_send);
  otrng_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);

  OTRNG_FREE;
}
