#include <string.h>

#include "../list.h"
#include "../otrv4.h"
#include "../str.h"

#include <libotr/privkey.h>

void test_api_conversation(void) {
  OTR4_INIT;

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);

  uint8_t alice_sym[ED448_PRIVATE_BYTES] = {
      1}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(alice_state, alice_sym);

  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {
      2}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(bob_state, bob_sym);

  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4};
  otrv4_t *alice = otrv4_new(alice_state, policy);
  otrv4_assert(!alice->keys->old_mac_keys);
  otrv4_t *bob = otrv4_new(bob_state, policy);
  otrv4_assert(!bob->keys->old_mac_keys);

  // AKE HAS FINISHED.
  do_ake_fixture(alice, bob);

  // int ratchet_id;
  int message_id;
  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;

  // Bob sends a data message
  string_t to_send = NULL;

  for (message_id = 2; message_id < 5; message_id++) {
    otrv4_assert(otrv4_send_message(&to_send, "hi", NULL, alice) ==
                 OTR4_SUCCESS);
    otrv4_assert(to_send);
    otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);
    otrv4_assert(!alice->keys->old_mac_keys);

    // This is a follow up message.
    g_assert_cmpint(alice->keys->i, ==, 0);
    g_assert_cmpint(alice->keys->j, ==, message_id);

    // Bob receives a data message
    response_to_alice = otrv4_response_new();
    otrv4_assert(otrv4_receive_message(response_to_alice, to_send, bob) ==
                 OTR4_SUCCESS);

    otrv4_assert(bob->keys->old_mac_keys);
    free(to_send);
    to_send = NULL;

    otrv4_assert_cmpmem("hi", response_to_alice->to_display, 3);
    g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, message_id - 1);
    otrv4_assert(response_to_alice->to_send == NULL);

    otrv4_response_free(response_to_alice);
    response_to_alice = NULL;

    // Next message Bob  sends is a new "ratchet"
    g_assert_cmpint(bob->keys->i, ==, 0);
    g_assert_cmpint(bob->keys->j, ==, 0);
  }

  for (message_id = 1; message_id < 4; message_id++) {
    // Bob sends a data message
    otrv4_assert(otrv4_send_message(&to_send, "hello", NULL, bob) ==
                 OTR4_SUCCESS);
    otrv4_assert(to_send);
    otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);
    g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, 0);

    // New ratchet hapenned
    g_assert_cmpint(bob->keys->i, ==, 1);
    g_assert_cmpint(bob->keys->j, ==, message_id);

    // Alice receives a data message
    response_to_bob = otrv4_response_new();
    otrv4_assert(otrv4_receive_message(response_to_bob, (string_t)to_send,
                                       alice) == OTR4_SUCCESS);
    g_assert_cmpint(list_len(alice->keys->old_mac_keys), ==, message_id);
    free(to_send);
    to_send = NULL;

    otrv4_assert_cmpmem("hello", response_to_bob->to_display, 6);
    otrv4_assert(response_to_bob->to_send == NULL);
    otrv4_response_free(response_to_bob);
    response_to_bob = NULL;

    // Alice follows the ratchet 1 (and prepares to a new "ratchet")
    g_assert_cmpint(alice->keys->i, ==, 1);
    g_assert_cmpint(alice->keys->j, ==, 0);
  }

  tlv_t *tlvs = otrv4_padding_tlv_new(10);
  otrv4_assert(tlvs);

  // Bob sends a message with TLV
  otrv4_assert(otrv4_send_message(&to_send, "hi", tlvs, bob) == OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);
  g_assert_cmpint(list_len(bob->keys->old_mac_keys), ==, 0);
  otrv4_tlv_free(tlvs);

  // Alice receives a data message with TLV
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob, (string_t)to_send,
                                     alice) == OTR4_SUCCESS);
  g_assert_cmpint(list_len(alice->keys->old_mac_keys), ==, 4);
  free(to_send);
  to_send = NULL;

  otrv4_assert(response_to_bob->tlvs);
  g_assert_cmpint(response_to_bob->tlvs->type, ==, OTRV4_TLV_PADDING);
  g_assert_cmpint(response_to_bob->tlvs->len, ==, 10);
  otrv4_response_free(response_to_bob);
  response_to_bob = NULL;

  otr4_client_state_free(alice_state);
  otr4_client_state_free(bob_state);

  otrv4_free(bob);
  otrv4_free(alice);

  OTR4_FREE;
}

void test_dh_key_rotation(void) {
  OTR4_INIT;

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);

  uint8_t alice_sym[ED448_PRIVATE_BYTES] = {
      1}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(alice_state, alice_sym);

  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {
      2}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(bob_state, bob_sym);

  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4};
  otrv4_t *alice = otrv4_new(alice_state, policy);
  otrv4_t *bob = otrv4_new(bob_state, policy);

  // AKE HAS FINISHED.
  do_ake_fixture(alice, bob);

  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;

  // Bob sends a data message
  string_t to_send = NULL;
  otr4_err_t err = OTR4_ERROR;

  for (int ratchet_id = 1; ratchet_id < 6; ratchet_id += 2) {

    // Bob sends a data message
    err = otrv4_send_message(&to_send, "hello", NULL, bob);
    otrv4_assert(err == OTR4_SUCCESS);
    otrv4_assert(to_send);
    otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);

    // New ratchet happened
    g_assert_cmpint(bob->keys->i, ==, ratchet_id);
    g_assert_cmpint(bob->keys->j, ==, 1);

    // it should always be NULL
    // manager->our_dh->priv == NULL

    // Alice receives a data message
    response_to_bob = otrv4_response_new();
    err = otrv4_receive_message(response_to_bob, to_send, alice); // HERE!
    otrv4_assert(err == OTR4_SUCCESS);
    free(to_send);
    to_send = NULL;

    otrv4_assert_cmpmem("hello", response_to_bob->to_display, 6);
    otrv4_assert(response_to_bob->to_send == NULL);
    otrv4_response_free(response_to_bob);
    response_to_bob = NULL;

    // Alice follows the ratchet 1 (and prepares to a new "ratchet")
    g_assert_cmpint(alice->keys->i, ==, ratchet_id);
    g_assert_cmpint(alice->keys->j, ==, 0); // New ratchet should happen
    if (ratchet_id == 3) {
      otrv4_assert(alice->keys->our_dh->priv == NULL);
      otrv4_assert(bob->keys->our_dh->priv != NULL);
    }

    //
    // Now alice ratchets
    //

    err = otrv4_send_message(&to_send, "hi", NULL, alice);
    otrv4_assert(err == OTR4_SUCCESS);
    otrv4_assert(to_send);
    otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9);

    g_assert_cmpint(alice->keys->i, ==, ratchet_id + 1);
    g_assert_cmpint(alice->keys->j, ==, 1);

    // Bob receives a data message
    response_to_alice = otrv4_response_new();
    err = otrv4_receive_message(response_to_alice, to_send, bob);
    otrv4_assert(err == OTR4_SUCCESS);

    g_assert_cmpint(bob->keys->i, ==, ratchet_id + 1);
    g_assert_cmpint(bob->keys->j, ==, 0); // New ratchet should happen

    free(to_send);
    to_send = NULL;

    otrv4_assert_cmpmem("hi", response_to_alice->to_display, 3);
    otrv4_assert(response_to_alice->to_send == NULL);

    otrv4_response_free(response_to_alice);
    response_to_alice = NULL;
  }

  otrv4_assert(alice->keys->our_dh->priv != NULL);
  otrv4_assert(bob->keys->our_dh->priv == NULL);

  otr4_client_state_free(alice_state);
  otr4_client_state_free(bob_state);

  otrv4_free(bob);
  otrv4_free(alice);

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
  otrv4_assert(response_to_alice->to_send == NULL);

  // Alice should be encrypted
  g_assert_cmpint(OTRL_MSGSTATE_ENCRYPTED, ==, bob->otr3_conn->ctx->msgstate);

  otrv4_response_free(response_to_alice);
  otrv4_response_free(response_to_bob);
}

void test_api_conversation_v3(void) {
  OTR4_INIT;

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  alice_state->protocol_name = otrv4_strdup("protocol");
  alice_state->account_name = otrv4_strdup("alice@protocol");

  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);
  bob_state->protocol_name = otrv4_strdup("protocol");
  bob_state->account_name = otrv4_strdup("bob@protocol");

  alice_state->userstate = otrl_userstate_create();
  bob_state->userstate = otrl_userstate_create();

  uint8_t alice_sym[ED448_PRIVATE_BYTES] = {
      1}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(alice_state, alice_sym);

  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {
      2}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(bob_state, bob_sym);

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
  otrv4_assert(otrv4_send_message(&to_send, "hi", NULL, alice) == OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Bob receives a data message
  response_to_alice = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_alice, to_send, bob) ==
               OTR4_SUCCESS);
  free(to_send);
  to_send = NULL;

  otrv4_assert(response_to_alice->to_display);
  otrv4_assert_cmpmem("hi", response_to_alice->to_display, 3);
  otrv4_assert(response_to_alice->to_send == NULL);
  otrv4_response_free(response_to_alice);
  response_to_alice = NULL;

  // Bob sends a data message
  otrv4_assert(otrv4_send_message(&to_send, "hi", NULL, bob) == OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAMD", to_send, 9);

  // Alice receives a data message
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob, to_send, alice) ==
               OTR4_SUCCESS);
  free(to_send);
  to_send = NULL;

  otrv4_assert(response_to_bob->to_display);
  otrv4_assert_cmpmem("hi", response_to_bob->to_display, 3);
  otrv4_assert(response_to_bob->to_send == NULL);
  otrv4_response_free(response_to_bob);
  response_to_bob = NULL;

  otrl_userstate_free(alice_state->userstate);
  otrl_userstate_free(bob_state->userstate);
  otrv4_free(alice);
  otrv4_free(bob);
  otr4_client_state_free(alice_state);
  otr4_client_state_free(bob_state);

  OTR4_FREE;
}

void test_api_smp(void) {
  OTR4_INIT;

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  otr4_client_state_t *bob_state = otr4_client_state_new(NULL);

  uint8_t alice_sym[ED448_PRIVATE_BYTES] = {
      1}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(alice_state, alice_sym);

  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {
      2}; // non-random private key on purpose
  otr4_client_state_add_private_key_v4(bob_state, bob_sym);

  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4};
  otrv4_t *alice = otrv4_new(alice_state, policy);
  otrv4_t *bob = otrv4_new(bob_state, policy);

  // AKE HAS FINISHED.
  do_ake_fixture(alice, bob);

  otrv4_response_t *response_to_bob = NULL;
  otrv4_response_t *response_to_alice = NULL;
  string_t to_send = NULL;
  char *secret = "secret";

  // Alice sends SMP1
  otrv4_assert(otrv4_smp_start(&to_send, NULL, (uint8_t *)secret,
                               strlen(secret), alice) == OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP1

  // Bob receives SMP1
  response_to_alice = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_alice, to_send, bob) ==
               OTR4_SUCCESS);
  free(to_send);
  to_send = NULL;

  otrv4_assert(!response_to_alice->to_send);
  otrv4_response_free(response_to_alice);
  response_to_alice = NULL;

  // This will be called by bob when the OTRV4_SMPEVENT_ASK_FOR_SECRET is
  // triggered.
  otrv4_assert(otrv4_smp_continue(&to_send, (uint8_t *)secret, strlen(secret),
                                  bob) == OTR4_SUCCESS);
  otrv4_assert(to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", to_send, 9); // SMP2

  // Alice receives SMP2
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob, to_send, alice) ==
               OTR4_SUCCESS);
  free(to_send);
  to_send = NULL;

  otrv4_assert(response_to_bob->to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", response_to_bob->to_send, 9); // SMP3

  // Bob receives SMP3
  response_to_alice = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_alice,
                                     response_to_bob->to_send,
                                     bob) == OTR4_SUCCESS);
  otrv4_response_free(response_to_bob);
  response_to_bob = NULL;

  // TODO: Should be in the corect state
  otrv4_assert(response_to_alice->to_send);
  otrv4_assert_cmpmem("?OTR:AAQD", response_to_alice->to_send, 9); // SMP4

  // Alice receives SMP4
  response_to_bob = otrv4_response_new();
  otrv4_assert(otrv4_receive_message(response_to_bob,
                                     response_to_alice->to_send,
                                     alice) == OTR4_SUCCESS);
  otrv4_response_free(response_to_alice);
  response_to_alice = NULL;

  // TODO: Should be in the corect state
  otrv4_assert(!response_to_bob->to_send);

  otrv4_response_free(response_to_bob);
  response_to_bob = NULL;

  otrv4_free(alice);
  otrv4_free(bob);
  otr4_client_state_free(alice_state);
  otr4_client_state_free(bob_state);

  OTR4_FREE;
}

void test_api_multiple_clients(void) {
  OTR4_INIT;

  otr4_client_state_t *bob_phone_state = otr4_client_state_new(NULL);
  bob_phone_state->userstate = otrl_userstate_create();
    bob_phone_state->account_name = otrv4_strdup("bob@phone");
    bob_phone_state->protocol_name = otrv4_strdup("proto");

  otr4_client_state_t *bob_pc_state = otr4_client_state_new(NULL);
  bob_pc_state->userstate = otrl_userstate_create();
    bob_pc_state->account_name = otrv4_strdup("bob@pc");
    bob_pc_state->protocol_name = otrv4_strdup("proto");

  otr4_client_state_t *alice_state = otr4_client_state_new(NULL);
  alice_state->userstate = otrl_userstate_create();
    alice_state->account_name = otrv4_strdup("alice");
    alice_state->protocol_name = otrv4_strdup("proto");

  uint8_t bob_phone_key[ED448_PRIVATE_BYTES] = {1};
  uint8_t bob_pc_key[ED448_PRIVATE_BYTES] = {2};
  uint8_t alice_key[ED448_PRIVATE_BYTES] = {3};

  otr4_client_state_add_private_key_v4(bob_phone_state, bob_phone_key);
  otr4_client_state_add_private_key_v4(bob_pc_state, bob_pc_key);
  otr4_client_state_add_private_key_v4(alice_state, alice_key);

  otr4_client_state_add_instance_tag(bob_phone_state, 0x100+1);
  otr4_client_state_add_instance_tag(bob_pc_state, 0x100+2);
  otr4_client_state_add_instance_tag(alice_state, 0x100+3);

  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V4};

  otrv4_t *alice = otrv4_new(alice_state, policy);
  otrv4_t *bob_phone = otrv4_new(bob_phone_state, policy);
  otrv4_t *bob_pc = otrv4_new(bob_pc_state, policy);

  otr4_err_t err = OTR4_ERROR;
  otrv4_response_t *from_pc = otrv4_response_new();
  otrv4_response_t *from_phone = otrv4_response_new();
  otrv4_response_t *to_pc = otrv4_response_new();
  otrv4_response_t *to_phone = otrv4_response_new();

  err = otrv4_receive_message(from_pc, "?OTRv4?", bob_pc);
  otrv4_assert(err == OTR4_SUCCESS);
  otrv4_assert(!from_pc->to_display);
  otrv4_assert(from_pc->to_send);
  otrv4_assert(bob_pc->state == OTRV4_STATE_WAITING_AUTH_R);

  err = otrv4_receive_message(from_phone, "?OTRv4?", bob_phone);
  otrv4_assert(err == OTR4_SUCCESS);
  otrv4_assert(!from_phone->to_display);
  otrv4_assert(from_phone->to_send);
  otrv4_assert(bob_phone->state == OTRV4_STATE_WAITING_AUTH_R);

  // Receives first Identity Message from PC
  err = otrv4_receive_message(to_pc, from_pc->to_send, alice);
  otrv4_response_free(from_pc);
  otrv4_assert(err == OTR4_SUCCESS);
  otrv4_assert(!to_pc->to_display);
  otrv4_assert(to_pc->to_send);
  otrv4_assert(alice->state == OTRV4_STATE_WAITING_AUTH_I);

  // Receives second Identity Message from PHONE (on state OTRV4_STATE_WAITING_AUTH_I)
  err = otrv4_receive_message(to_phone, from_phone->to_send, alice); 
  otrv4_response_free(from_phone);
  otrv4_assert(err == OTR4_SUCCESS);
  otrv4_assert(!to_phone->to_display);
  otrv4_assert(to_phone->to_send);
  otrv4_assert(alice->state == OTRV4_STATE_WAITING_AUTH_I);

  //Both receive the AUTH-R but only PC accepts
  from_pc = otrv4_response_new();
  err = otrv4_receive_message(from_pc, to_pc->to_send, bob_pc);
  otrv4_assert(err == OTR4_SUCCESS);
  otrv4_assert(!from_pc->to_display);
  otrv4_assert(from_pc->to_send);
  otrv4_assert(bob_pc->state == OTRV4_STATE_ENCRYPTED_MESSAGES);

  from_phone = otrv4_response_new();
  err = otrv4_receive_message(from_phone, to_pc->to_send, bob_phone);
  otrv4_assert(err == OTR4_SUCCESS);
  otrv4_assert(!from_phone->to_display);
  otrv4_assert(!from_phone->to_send); // This message was sent to PC instance tag.
  otrv4_assert(bob_phone->state == OTRV4_STATE_WAITING_AUTH_R);

  // The message was ignored. It should not remove the private key yet.
  otrv4_assert(bob_phone->keys->our_dh->pub != NULL);
  otrv4_assert(bob_phone->keys->our_dh->priv != NULL);

  //TODO: Alice should receive from PC (PHONE will have ignored the message).

  //Both receive but only PHONE accepts
  from_pc = otrv4_response_new();
  err = otrv4_receive_message(from_pc, to_phone->to_send, bob_pc);
  otrv4_assert(err == OTR4_SUCCESS);
  otrv4_assert(!from_pc->to_display);
  otrv4_assert(!from_pc->to_send); // This message was sent to PC instance tag.
  otrv4_assert(bob_pc->state == OTRV4_STATE_ENCRYPTED_MESSAGES);

  from_phone = otrv4_response_new();
  err = otrv4_receive_message(from_phone, to_phone->to_send, bob_phone); // This segfaults, because we are freeing
  otrv4_assert(err == OTR4_SUCCESS);
  otrv4_assert(!from_phone->to_display);
  otrv4_assert(from_phone->to_send);
  otrv4_assert(bob_phone->state == OTRV4_STATE_ENCRYPTED_MESSAGES);

  //TODO: Alice should receive from PHONE (PC will have ignored the message).

  otrl_userstate_free(alice_state->userstate);
  otrl_userstate_free(bob_phone_state->userstate);
  otrl_userstate_free(bob_pc_state->userstate);

  otr4_client_state_free(alice_state);
  otr4_client_state_free(bob_pc_state);
  otr4_client_state_free(bob_phone_state);

  otrv4_free(bob_pc);
  otrv4_free(bob_phone);
  otrv4_free(alice);

  OTR4_FREE;
}
