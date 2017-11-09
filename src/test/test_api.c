#include <string.h>

#include "../list.h"
#include "../otrv4.h"
#include "../str.h"

#include <libotr/privkey.h>

#define assert_msg_sent(err, to_send)                                          \
  do {                                                                         \
    otrv4_assert(err == OTR4_SUCCESS);                                         \
    otrv4_assert(to_send);                                                     \
    otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);                              \
  } while (0);

#define assert_msg_rec(err, message, response)                                 \
  do {                                                                         \
    otrv4_assert(err == OTR4_SUCCESS);                                         \
    otrv4_assert_cmpmem(message, response->to_display, strlen(message) + 1);   \
    otrv4_assert(response->to_send == NULL);                                   \
  } while (0);

#define assert_rec_msg_inc_state(result, respond_to, sender, otr_state,        \
                                 send_response)                                \
  do {                                                                         \
    otrv4_assert(result);                                                      \
    otrv4_assert(!respond_to->to_display);                                     \
    otrv4_assert(sender->state == otr_state);                                  \
    if (send_response) {                                                       \
      otrv4_assert(respond_to->to_send);                                       \
    } else {                                                                   \
      otrv4_assert(!respond_to->to_send);                                      \
    }                                                                          \
  } while (0);

static void free_message_and_response(otrv4_response_t *response,
                                      string_t message) {
  otrv4_response_free(response);
  free(message);
  message = NULL;
}

// TODO: add pad
static void set_up_client_state(otr4_client_state_t *state,
                                string_t account_name, int byte) {
  state->userstate = otrl_userstate_create();
  state->account_name = otrv4_strdup(account_name);
  state->protocol_name = otrv4_strdup("protocol");

  uint8_t sym_key[ED448_PRIVATE_BYTES] = {byte};
  otr4_client_state_add_private_key_v4(state, sym_key);
  otr4_client_state_add_instance_tag(state, 0x100 + byte);
}

// TODO: a cliente state is not part of a otr creation
static otrv4_t *set_up_otr(otr4_client_state_t *state, char *account_name,
                           int byte) {
  set_up_client_state(state, account_name, byte);

  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4};

  return otrv4_new(state, policy);
}

void test_api_conversation(void) {
  OTR4_INIT;

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  alice_state->pad = true;
  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);
  bob_state->pad = true;

  otrv4_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, 1);
  otrv4_t *bob = set_up_otr(bob_state, BOB_IDENTITY, 2);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  int message_id;
  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;

  // Alice sends a data message
  string_t to_send = NULL;
  tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_NONE, 0, NULL);
  otr4_err_t err;

  for (message_id = 2; message_id < 5; message_id++) {
    err = otrv4_prepare_to_send_message(&to_send, "hi", tlv, alice);
    assert_msg_sent(err, to_send);
    otrv4_assert(!alice->keys->old_mac_keys);

    // This is a follow up message.
    g_assert_cmpint(alice->keys->i, ==, 0);
    g_assert_cmpint(alice->keys->j, ==, message_id);

    // Bob receives a data message
    response_to_alice = otrv4_response_new();
    otr4_err_t err = otrv4_receive_message(response_to_alice, to_send, bob);
    assert_msg_rec(err, "hi", response_to_alice);
    otrv4_assert(bob->keys->old_mac_keys);

    free_message_and_response(response_to_alice, to_send);

    g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, message_id - 1);

    // Next message Bob sends is a new "ratchet"
    g_assert_cmpint(bob->keys->i, ==, 0);
    g_assert_cmpint(bob->keys->j, ==, 0);
  }

  for (message_id = 1; message_id < 4; message_id++) {
    // Bob sends a data message
    err = otrv4_prepare_to_send_message(&to_send, "hello", tlv, bob);
    assert_msg_sent(err, to_send);

    g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, 0);

    // New ratchet hapenned
    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, message_id);

    // Alice receives a data message
    response_to_bob = otrv4_response_new();
    otr4_err_t err = otrv4_receive_message(response_to_bob, to_send, alice);
    assert_msg_rec(err, "hello", response_to_bob);
    g_assert_cmpint(list_len(alice->keys->old_mac_keys), ==, message_id);

    free_message_and_response(response_to_bob, to_send);

    // Alice follows the ratchet 1 (and prepares to a new "ratchet")
    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, 0);
  }

  uint16_t tlv_len = 2;
  uint8_t tlv_data[2] = {0x08, 0x05};
  tlv_t *tlvs = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_1, tlv_len, tlv_data);
  otrv4_assert(tlvs);

  // Bob sends a message with TLV
  err = otrv4_prepare_to_send_message(&to_send, "hi", tlvs, bob);
  assert_msg_sent(err, to_send);

  g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, 0);
  otrv4_tlv_free(tlvs);

  // Alice receives a data message with TLV
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob, to_send, alice) ==
               OTR4_SUCCESS);
  g_assert_cmpint(list_len(alice->keys->old_mac_keys), ==, 4);

  // Check TLVS
  otrv4_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->type, ==, OTRV4_TLV_SMP_MSG_1);
  g_assert_cmpint(response_to_bob->tlvs->len, ==, tlv_len);
  otrv4_assert_cmpmem(response_to_bob->tlvs->data, tlv_data, tlv_len);

  // Check Padding
  otrv4_assert(response_to_bob->tlvs->next);
  g_assert_cmpint(response_to_bob->tlvs->next->type, ==, OTRV4_TLV_PADDING);
  g_assert_cmpint(response_to_bob->tlvs->next->len, ==, 249);

  free_message_and_response(response_to_bob, to_send);

  otrv4_userstate_free_all(2, alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(2, alice_state, bob_state);

  otrv4_free_all(2, alice, bob);

  otrv4_tlv_free(tlv);

  OTR4_FREE;
}

void test_dh_key_rotation(void) {
  OTR4_INIT;
  tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_NONE, 0, NULL);
  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);

  otrv4_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, 1);
  otrv4_t *bob = set_up_otr(bob_state, BOB_IDENTITY, 2);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  int ratchet_id;
  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;

  // Bob sends a data message
  string_t to_send = NULL;
  otr4_err_t err;

  for (ratchet_id = 1; ratchet_id < 6; ratchet_id += 2) {
    // Bob sends a data message
    err = otrv4_prepare_to_send_message(&to_send, "hello", tlv, bob);
    assert_msg_sent(err, to_send);

    // New ratchet happened
    g_assert_cmpint(bob->keys->i, ==, ratchet_id);
    g_assert_cmpint(bob->keys->j, ==, 1);

    // Alice receives a data message
    response_to_bob = otrv4_response_new();
    otr4_err_t err = otrv4_receive_message(response_to_bob, to_send, alice);
    assert_msg_rec(err, "hello", response_to_bob);

    // Alice follows the ratchet 1 (and prepares to a new "ratchet")
    g_assert_cmpint(alice->keys->i, ==, ratchet_id);
    g_assert_cmpint(alice->keys->j, ==, 0); // New ratchet should happen

    // Alice deletes priv key when receiving on ratchet 3
    if (ratchet_id == 1) {
      otrv4_assert(alice->keys->our_dh->priv);
      otrv4_assert(!bob->keys->our_dh->priv);
    } else if (ratchet_id == 3 || ratchet_id == 5) {
      otrv4_assert(!alice->keys->our_dh->priv);
      otrv4_assert(bob->keys->our_dh->priv);
    }

    free_message_and_response(response_to_bob, to_send);

    // Now alice ratchets and sends a data message
    err = otrv4_prepare_to_send_message(&to_send, "hi", tlv, alice);
    assert_msg_sent(err, to_send);

    g_assert_cmpint(alice->keys->i, ==, ratchet_id + 1);
    g_assert_cmpint(alice->keys->j, ==, 1);

    if (ratchet_id == 3) {
      otrv4_assert(!alice->keys->our_dh->priv);
      otrv4_assert(bob->keys->our_dh->priv);
    }

    // Bob receives a data message
    response_to_alice = otrv4_response_new();
    err = otrv4_receive_message(response_to_alice, to_send, bob);
    assert_msg_rec(err, "hi", response_to_alice);

    free_message_and_response(response_to_alice, to_send);

    g_assert_cmpint(bob->keys->i, ==, ratchet_id + 1);
    g_assert_cmpint(bob->keys->j, ==, 0); // New ratchet should happen

    // Bob deletes priv key when receiving on ratchet 6
    if (ratchet_id + 1 == 2 || ratchet_id + 1 == 6) {
      otrv4_assert(alice->keys->our_dh->priv);
      otrv4_assert(!bob->keys->our_dh->priv);
    } else if (ratchet_id + 1 == 4) {
      otrv4_assert(!alice->keys->our_dh->priv);
      otrv4_assert(bob->keys->our_dh->priv);
    }
  }

  otrv4_userstate_free_all(2, alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(2, alice_state, bob_state);
  otrv4_free_all(2, alice, bob);
  otrv4_tlv_free(tlv);

  OTR4_FREE;
}

static void do_ake_otr3(otrv4_t *alice, otrv4_t *bob) {
  otrv4_response_t *response_to_bob = otrv4_response_new();
  otrv4_response_t *response_to_alice = otrv4_response_new();

  // Alice sends query message
  string_t query_message = NULL;
  otrv4_build_query_message(&query_message, "", alice);
  otrv4_assert_cmpmem("?OTRv3", query_message, 6);

  // Bob receives query message
  otrv4_assert(otrv4_receive_message(response_to_alice, query_message, bob) ==
               OTR4_SUCCESS);
  free(query_message);
  query_message = NULL;

  // Should reply with a DH-Commit
  otrv4_assert(response_to_alice->to_display == NULL);
  otrv4_assert(response_to_alice->to_send);
  otrv4_assert_cmpmem("?OTR:AAMC", response_to_alice->to_send, 9);

  // Alice receives DH-Commit
  otrv4_assert(otrv4_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == OTR4_SUCCESS);
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Should reply with a DH Key
  otrv4_assert(response_to_bob->to_display == NULL);
  otrv4_assert(response_to_bob->to_send);
  otrv4_assert_cmpmem("?OTR:AAMK", response_to_bob->to_send, 9);

  // Bob receives a DH Key
  otrv4_assert(otrv4_receive_message(response_to_alice,
                                     response_to_bob->to_send,
                                     bob) == OTR4_SUCCESS);
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  // Bob should reply with a Reveal Sig
  otrv4_assert(response_to_alice->to_display == NULL);
  otrv4_assert(response_to_alice->to_send);
  otrv4_assert_cmpmem("?OTR:AAMR", response_to_alice->to_send, 9);

  // Alice receives Reveal Sig
  otrv4_assert(otrv4_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == OTR4_SUCCESS);
  free(response_to_alice->to_send);
  response_to_alice->to_send = NULL;

  // Should reply with a Sig
  otrv4_assert(response_to_bob->to_display == NULL);
  otrv4_assert(response_to_bob->to_send);
  otrv4_assert_cmpmem("?OTR:AAMS", response_to_bob->to_send, 9);

  // Alice should be encrypted
  g_assert_cmpint(OTRL_MSGSTATE_ENCRYPTED, ==, alice->otr3_conn->ctx->msgstate);

  // Bob receives a Sig
  otrv4_assert(otrv4_receive_message(response_to_alice,
                                     response_to_bob->to_send,
                                     bob) == OTR4_SUCCESS);
  free(response_to_bob->to_send);
  response_to_bob->to_send = NULL;

  // Bob should NOT reply
  otrv4_assert(response_to_alice->to_display == NULL);
  otrv4_assert(!response_to_alice->to_send);

  // Alice should be encrypted
  g_assert_cmpint(OTRL_MSGSTATE_ENCRYPTED, ==, bob->otr3_conn->ctx->msgstate);

  otrv4_response_free_all(2, response_to_alice, response_to_bob);
}

void test_api_conversation_v3(void) {
  OTR4_INIT;
  tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_NONE, 0, NULL);

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  set_up_client_state(alice_state, "alice@protocol", 1);

  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);
  set_up_client_state(bob_state, "bob@protocol", 2);

  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3};
  otrv4_t *alice = otrv4_new(alice_state, policy);
  otrv4_t *bob = otrv4_new(bob_state, policy);

  // Set up OTRv3 context
  alice->otr3_conn = otr3_conn_new(alice_state, "bob");
  bob->otr3_conn = otr3_conn_new(bob_state, "alice");

  // Generate long term private key.
  FILE *tmpFILEp;
  tmpFILEp = tmpfile();
  otrv4_assert(!otrl_privkey_generate_FILEp(alice_state->userstate, tmpFILEp,
                                            alice_state->account_name,
                                            alice_state->protocol_name));
  fclose(tmpFILEp);

  tmpFILEp = tmpfile();
  otrv4_assert(!otrl_privkey_generate_FILEp(bob_state->userstate, tmpFILEp,
                                            bob_state->account_name,
                                            bob_state->protocol_name));
  fclose(tmpFILEp);

  // Generate instance tag
  otr4_client_state_add_instance_tag(alice_state, 0x100 + 1);
  otr4_client_state_add_instance_tag(bob_state, 0x100 + 2);

  // AKE HAS FINISHED.
  do_ake_otr3(alice, bob);

  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;
  string_t to_send = NULL;

  // Alice sends a data message
  otrv4_assert(otrv4_prepare_to_send_message(&to_send, "hi", tlv, alice) ==
               OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Bob receives a data message
  response_to_alice = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_alice, to_send, bob) ==
               OTR4_SUCCESS);

  otrv4_assert(response_to_alice->to_display);
  otrv4_assert_cmpmem("hi", response_to_alice->to_display, 3);
  otrv4_assert(!response_to_alice->to_send);
  free_message_and_response(response_to_alice, to_send);

  // Bob sends a data message
  otrv4_assert(otrv4_prepare_to_send_message(&to_send, "hi", tlv, bob) ==
               OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Alice receives a data message
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob, to_send, alice) ==
               OTR4_SUCCESS);

  otrv4_assert(response_to_bob->to_display);
  otrv4_assert_cmpmem("hi", response_to_bob->to_display, 3);
  otrv4_assert(!response_to_bob->to_send);
  free_message_and_response(response_to_bob, to_send);

  otrv4_userstate_free_all(2, alice_state->userstate, bob_state->userstate);
  otrv4_free_all(2, alice, bob);
  otrv4_client_state_free_all(2, alice_state, bob_state);

  otrv4_tlv_free(tlv);

  OTR4_FREE;
}

void test_api_smp(void) {
  OTR4_INIT;

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);

  otrv4_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, 1);
  otrv4_t *bob = set_up_otr(bob_state, BOB_IDENTITY, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;
  string_t to_send = NULL;
  char *secret = "secret";

  // Alice sends SMP1
  otrv4_assert(otrv4_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                               strlen(secret), alice) == OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT2);

  // Bob receives SMP1
  response_to_alice = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_alice, to_send, bob) ==
               OTR4_SUCCESS);

  otrv4_assert(!response_to_alice->to_send);
  free_message_and_response(response_to_alice, to_send);

  // This will be called by bob when the OTRV4_SMPEVENT_ASK_FOR_SECRET is
  // triggered.
  otrv4_assert(otrv4_smp_continue(&to_send, (uint8_t *)secret, strlen(secret),
                                  bob) == OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP2
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT3);

  // Alice receives SMP2
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob, to_send, alice) ==
               OTR4_SUCCESS);

  otrv4_assert(response_to_bob->to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9); // SMP3

  // Bob receives SMP3
  response_to_alice = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_alice,
                                     response_to_bob->to_send,
                                     bob) == OTR4_SUCCESS);
  free_message_and_response(response_to_bob, to_send);

  otrv4_assert(response_to_alice->to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", response_to_alice->to_send, 9); // SMP4
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT4);

  // Alice receives SMP4
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == OTR4_SUCCESS);
  otrv4_response_free(response_to_alice);
  response_to_alice = NULL;

  // TODO: Should be in the correct state
  otrv4_assert(!response_to_bob->to_send);

  otrv4_response_free(response_to_bob);
  response_to_bob = NULL;

  otrv4_userstate_free_all(2, alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(2, alice_state, bob_state);
  otrv4_free_all(2, alice, bob);

  OTR4_FREE;
}

void test_api_smp_abort(void) {
  OTR4_INIT;

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);

  otrv4_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, 1);
  otrv4_t *bob = set_up_otr(bob_state, BOB_IDENTITY, 2);

  // Starts an smp state machine
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;
  string_t to_send = NULL;
  char *secret = "secret";

  // Alice sends SMP1
  otrv4_assert(otrv4_smp_start(&to_send, NULL, 0, (uint8_t *)secret,
                               strlen(secret), alice) == OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT2);

  // Bob receives SMP1
  response_to_alice = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_alice, to_send, bob) ==
               OTR4_SUCCESS);

  otrv4_assert(!response_to_alice->to_send);
  free_message_and_response(response_to_alice, to_send);

  // From here
  // Bob sends SMP Abort. TODO: check it does not trigger anything else
  otrv4_assert(otrv4_smp_abort(&to_send, bob) == OTR4_SUCCESS);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  // Alice receives SMP ABORT, send SMP_ABORT
  // TODO: Alice probably should not send and abort at this point
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob, to_send, alice) ==
               OTR4_SUCCESS);

  otrv4_assert(response_to_bob->to_send);

  otrv4_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9);
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);

  free_message_and_response(response_to_bob, to_send);

  // TODO: Alice can restart here the smp. This will mem leak though
  otrv4_userstate_free_all(2, alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(2, alice_state, bob_state);
  otrv4_free_all(2, alice, bob);

  OTR4_FREE;
}

void test_api_extra_sym_key(void) {
  OTR4_INIT;

  tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_NONE, 0, NULL);

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  alice_state->pad = false;
  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);
  bob_state->pad = false;

  otrv4_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, 1);
  otrv4_t *bob = set_up_otr(bob_state, BOB_IDENTITY, 2);

  // DAKE HAS FINISHED.
  do_dake_fixture(alice, bob);

  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;

  // Alice sends a data message
  string_t to_send = NULL;

  otr4_err_t err;

  err = otrv4_prepare_to_send_message(&to_send, "hi", tlv, alice);
  assert_msg_sent(err, to_send);
  otrv4_assert(!alice->keys->old_mac_keys);

  // This is a follow up message.
  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 2);

  // Bob receives a data message
  response_to_alice = otrv4_response_new();
  err = otrv4_receive_message(response_to_alice, to_send, bob);
  assert_msg_rec(err, "hi", response_to_alice);
  otrv4_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, to_send);

  g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, 1);

  // Next message Bob sends is a new "ratchet"
  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  uint16_t tlv_len = 6;
  uint8_t tlv_data[6] = {0x08, 0x05, 0x09, 0x00, 0x02, 0x04};
  // Bob sends a message with TLV
  int use = 134547712;
  uint8_t usedata[2] = {0x02, 0x04};
  uint16_t usedatalen = 2;
  err = otrv4_send_symkey_message(&to_send, use, usedata, usedatalen,
                                  bob->keys->extra_key, bob);
  assert_msg_sent(err, to_send);

  g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, 0);

  // Alice receives a data message with TLV
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob, to_send, alice) ==
               OTR4_SUCCESS);
  g_assert_cmpint(list_len(alice->keys->old_mac_keys), ==, 1);

  // Check TLVS
  otrv4_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->type, ==, OTRV4_TLV_SYM_KEY);
  g_assert_cmpint(response_to_bob->tlvs->len, ==, tlv_len);
  otrv4_assert_cmpmem(response_to_bob->tlvs->data, tlv_data, tlv_len);

  otrv4_assert(!response_to_bob->tlvs->next);

  free_message_and_response(response_to_bob, to_send);

  otrv4_userstate_free_all(2, alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(2, alice_state, bob_state);
  otrv4_free_all(2, alice, bob);

  otrv4_tlv_free(tlv);

  OTR4_FREE;
}

static int should_succeed(otr4_err_t err) { return err == OTR4_SUCCESS; }

void test_api_multiple_clients(void) {
  OTR4_INIT;

  bool send_response = true;
  otr4_err_t err;

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  otr4_client_state_t *bob_phone_state = otr4_client_state_new(NULL);
  otr4_client_state_t *bob_pc_state = otr4_client_state_new(NULL);

  // The account name should be the same. The account can be logged
  // on different clients. Instance tags are used for that. This
  // account name can be used as phi.
  otrv4_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, 1);
  otrv4_t *bob_phone = set_up_otr(bob_phone_state, BOB_IDENTITY, 2);
  otrv4_t *bob_pc = set_up_otr(bob_pc_state, BOB_IDENTITY, 3);

  otrv4_response_t *pc_to_alice = otrv4_response_new();
  otrv4_response_t *phone_to_alice = otrv4_response_new();
  otrv4_response_t *alice_to_pc = otrv4_response_new();
  otrv4_response_t *alice_to_phone = otrv4_response_new();

  // PC receives query msg and sends identity msg
  err = otrv4_receive_message(pc_to_alice, "?OTRv4?", bob_pc);
  assert_rec_msg_inc_state(should_succeed(err), pc_to_alice, bob_pc,
                           OTRV4_STATE_WAITING_AUTH_R, send_response);

  // PHONE receives query msg and sends identity msg
  err = otrv4_receive_message(phone_to_alice, "?OTRv4?", bob_phone);
  assert_rec_msg_inc_state(should_succeed(err), phone_to_alice, bob_phone,
                           OTRV4_STATE_WAITING_AUTH_R, send_response);

  // ALICE receives Identity msg from PC and sends AUTH-R
  err = otrv4_receive_message(alice_to_pc, pc_to_alice->to_send, alice);
  assert_rec_msg_inc_state(should_succeed(err), alice_to_pc, alice,
                           OTRV4_STATE_WAITING_AUTH_I, send_response);
  otrv4_response_free(pc_to_alice);

  // ALICE receives Identity msg from PHONE (on state
  // OTRV4_STATE_WAITING_AUTH_I) and sends AUTH-R. ALICE will replace keys and
  // profile info from PC with info from PHONE.
  err = otrv4_receive_message(alice_to_phone, phone_to_alice->to_send, alice);
  assert_rec_msg_inc_state(should_succeed(err), alice_to_phone, alice,
                           OTRV4_STATE_WAITING_AUTH_I, send_response);
  otrv4_response_free(phone_to_alice);

  // PC receives AUTH-R succesfully
  pc_to_alice = otrv4_response_new();
  err = otrv4_receive_message(pc_to_alice, alice_to_pc->to_send, bob_pc);
  assert_rec_msg_inc_state(should_succeed(err), pc_to_alice, bob_pc,
                           OTRV4_STATE_ENCRYPTED_MESSAGES, send_response);

  // PC deletes private keys as AUTH-R succesful
  otrv4_assert(bob_pc->keys->our_dh->pub);
  otrv4_assert(!bob_pc->keys->our_dh->priv);

  otrv4_assert_not_zero(bob_pc->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrv4_assert_zero(bob_pc->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // PHONE receives AUTH-R with PC instance tag - Ignores
  phone_to_alice = otrv4_response_new();
  err = otrv4_receive_message(phone_to_alice, alice_to_pc->to_send, bob_phone);
  assert_rec_msg_inc_state(should_succeed(err), phone_to_alice, bob_phone,
                           OTRV4_STATE_WAITING_AUTH_R, !send_response);
  otrv4_response_free(phone_to_alice);
  otrv4_response_free(alice_to_pc);

  // PHONE does NOT remove the private keys yet - needed for AUTH-I when it
  // actually receives an AUTH-R
  otrv4_assert(bob_phone->keys->our_dh->pub);
  otrv4_assert(bob_phone->keys->our_dh->priv);

  otrv4_assert_not_zero(bob_phone->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrv4_assert_not_zero(bob_phone->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // ALICE receives AUTH-I from PC - Authentication fails
  alice_to_pc = otrv4_response_new();
  err = otrv4_receive_message(alice_to_pc, pc_to_alice->to_send, alice);
  assert_rec_msg_inc_state(!should_succeed(err), alice_to_pc, alice,
                           OTRV4_STATE_WAITING_AUTH_I, !send_response);

  otrv4_response_free(pc_to_alice);
  otrv4_response_free(alice_to_pc);

  // PC receives AUTH-R again - ignores
  pc_to_alice = otrv4_response_new();
  err = otrv4_receive_message(pc_to_alice, alice_to_phone->to_send, bob_pc);
  assert_rec_msg_inc_state(should_succeed(err), pc_to_alice, bob_pc,
                           OTRV4_STATE_ENCRYPTED_MESSAGES, !send_response);
  otrv4_response_free(pc_to_alice);

  // PHONE receives correct AUTH-R message and sends AUTH-I
  phone_to_alice = otrv4_response_new();
  err =
      otrv4_receive_message(phone_to_alice, alice_to_phone->to_send, bob_phone);
  assert_rec_msg_inc_state(should_succeed(err), phone_to_alice, bob_phone,
                           OTRV4_STATE_ENCRYPTED_MESSAGES, send_response);
  otrv4_response_free(alice_to_phone);

  // PHONE can now delete private keys
  otrv4_assert(bob_phone->keys->our_dh->pub);
  otrv4_assert(!bob_phone->keys->our_dh->priv);
  otrv4_assert_not_zero(bob_phone->keys->our_ecdh->pub, ED448_POINT_BYTES);
  otrv4_assert_zero(bob_phone->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // ALICE receives AUTH-I from PHONE
  alice_to_phone = otrv4_response_new();
  err = otrv4_receive_message(alice_to_phone, phone_to_alice->to_send, alice);
  assert_rec_msg_inc_state(should_succeed(err), alice_to_phone, alice,
                           OTRV4_STATE_ENCRYPTED_MESSAGES, !send_response);

  // ALICE and PHONE have the same shared secret
  otrv4_assert_root_key_eq(alice->keys->current->root_key,
                           bob_phone->keys->current->root_key);
  otrv4_assert_chain_key_eq(alice->keys->current->chain_a->key,
                            bob_phone->keys->current->chain_a->key);
  otrv4_assert_chain_key_eq(bob_phone->keys->current->chain_b->key,
                            alice->keys->current->chain_b->key);

  otrv4_response_free_all(2, phone_to_alice, alice_to_phone);
  otrv4_userstate_free_all(3, alice_state->userstate,
                           bob_phone_state->userstate, bob_pc_state->userstate);
  otrv4_client_state_free_all(3, alice_state, bob_pc_state, bob_phone_state);
  otrv4_free_all(3, alice, bob_pc, bob_phone);

  OTR4_FREE;
}

void test_ecdh_priv_keys_destroyed_early() {
  OTR4_INIT;

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);

  otrv4_t *alice = set_up_otr(alice_state, ALICE_IDENTITY, 1);
  otrv4_t *bob = set_up_otr(bob_state, BOB_IDENTITY, 2);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;
  string_t to_send = NULL;
  otr4_err_t err;

  // Alice sends a data message
  err = otrv4_prepare_to_send_message(&to_send, "hi", NULL, alice);
  assert_msg_sent(err, to_send);

  // Follow up message
  g_assert_cmpint(alice->keys->i, ==, 0);
  g_assert_cmpint(alice->keys->j, ==, 2);

  // Alice should not delete ECDH priv key
  otrv4_assert_not_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Bob receives a data message
  response_to_alice = otrv4_response_new();
  err = otrv4_receive_message(response_to_alice, to_send, bob);
  assert_msg_rec(err, "hi", response_to_alice);

  free_message_and_response(response_to_alice, to_send);

  g_assert_cmpint(bob->keys->i, ==, 0);
  g_assert_cmpint(bob->keys->j, ==, 0);

  // Bob's ECDH priv key should be zero still from the DAKE
  otrv4_assert_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Bob sends a data message
  err = otrv4_prepare_to_send_message(&to_send, "hello", NULL, bob);
  assert_msg_sent(err, to_send);

  // New ratchet
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 1);

  // Bob's ECDH priv key should not be zero after sending
  otrv4_assert_not_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Alice receives a data message
  response_to_bob = otrv4_response_new();
  err = otrv4_receive_message(response_to_bob, to_send, alice);
  assert_msg_rec(err, "hello", response_to_bob);

  free_message_and_response(response_to_bob, to_send);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 0);

  // Alice should delete ECDH priv key
  otrv4_assert_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Alice sends a data message
  err = otrv4_prepare_to_send_message(&to_send, "hi", NULL, alice);
  assert_msg_sent(err, to_send);

  // New ratchet
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 1);

  // Alice should NOT delete ECDH priv key
  otrv4_assert_not_zero(alice->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  // Bob receives a data message
  response_to_alice = otrv4_response_new();
  err = otrv4_receive_message(response_to_alice, to_send, bob);
  assert_msg_rec(err, "hi", response_to_alice);

  free_message_and_response(response_to_alice, to_send);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 0);

  // Bob should delete ECDH priv key
  otrv4_assert_zero(bob->keys->our_ecdh->priv, ED448_SCALAR_BYTES);

  otrv4_userstate_free_all(2, alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(2, alice_state, bob_state);
  otrv4_free_all(2, alice, bob);

  OTR4_FREE;
}
