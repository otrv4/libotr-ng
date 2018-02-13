#include <stdio.h>

#include "../client.h"
#include "../fragment.h"
#include "../instance_tag.h"
#include "../messaging.h"
#include "../serialize.h"
#include "../shake.h"

static otrv4_client_t *set_up_client(otrv4_client_state_t *state,
                                    const char *account_name, const char *phi,
                                    uint8_t byte) {
  set_up_client_state(state, account_name, phi, byte);
  otrv4_client_t *dst = otrv4_client_new(state);

  return dst;
}

void test_client_conversation_api() {
  OTR4_INIT;

  otrv4_client_state_t *alice_state = otrv4_client_state_new(NULL);

  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);
  otrv4_assert(!alice->conversations);

  otrv4_conversation_t *alice_to_bob =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  otrv4_conversation_t *alice_to_charlie = otrv4_client_get_conversation(
      !FORCE_CREATE_CONVO, CHARLIE_IDENTITY, alice);

  otrv4_assert(!alice->conversations);
  otrv4_assert(!alice_to_bob);
  otrv4_assert(!alice_to_charlie);

  alice_to_bob =
      otrv4_client_get_conversation(FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  alice_to_charlie =
      otrv4_client_get_conversation(FORCE_CREATE_CONVO, CHARLIE_IDENTITY, alice);

  otrv4_assert(alice_to_bob);
  otrv4_assert(alice_to_bob->conn);
  otrv4_assert(alice_to_charlie);
  otrv4_assert(alice_to_charlie->conn);

  alice_to_bob =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  alice_to_charlie = otrv4_client_get_conversation(!FORCE_CREATE_CONVO,
                                                  CHARLIE_IDENTITY, alice);

  otrv4_assert(alice_to_bob);
  otrv4_assert(alice_to_bob->conn);
  otrv4_assert(alice_to_charlie);
  otrv4_assert(alice_to_charlie->conn);

  // Free memory
  otrl_userstate_free(alice_state->userstate);
  otrv4_client_state_free(alice_state);
  otrv4_client_free(alice);

  OTR4_FREE
}

void test_client_api() {
  OTR4_INIT;

  otrv4_client_state_t *alice_state = otrv4_client_state_new("alice");
  otrv4_client_state_t *bob_state = otrv4_client_state_new("bob");
  otrv4_client_state_t *charlie_state = otrv4_client_state_new("charlie");

  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);
  otrv4_client_t *bob = set_up_client(bob_state, BOB_IDENTITY, PHI, 2);
  otrv4_client_t *charlie =
      set_up_client(charlie_state, CHARLIE_IDENTITY, PHI, 3);

  char *query_msg_to_bob =
      otrv4_client_query_message(BOB_IDENTITY, "Hi bob", alice, OTRV4_ALLOW_V4);
  otrv4_assert(query_msg_to_bob);

  char *query_msg_to_charlie = otrv4_client_query_message(
      CHARLIE_IDENTITY, "Hi charlie", alice, OTRV4_ALLOW_V4);
  otrv4_assert(query_msg_to_charlie);

  int ignore = 0;
  char *from_alice_to_bob = NULL, *from_alice_to_charlie = NULL,
       *frombob = NULL, *fromcharlie = NULL, *todisplay = NULL;

  // Bob receives query message, sends identity msg
  ignore = otrv4_client_receive(&frombob, &todisplay, query_msg_to_bob,
                               ALICE_IDENTITY, bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  // Charlie receives query message, sends identity message
  ignore = otrv4_client_receive(&fromcharlie, &todisplay, query_msg_to_charlie,
                               ALICE_IDENTITY, charlie);
  free(query_msg_to_charlie);
  query_msg_to_charlie = NULL;

  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  otrv4_conversation_t *alice_to_bob =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  otrv4_conversation_t *alice_to_charlie = otrv4_client_get_conversation(
      !FORCE_CREATE_CONVO, CHARLIE_IDENTITY, alice);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_START);
  otrv4_assert(alice_to_charlie->conn->state == OTRV4_STATE_START);

  // Alice receives identity message (from Bob), sends Auth-R message
  ignore = otrv4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  otrv4_assert(from_alice_to_bob);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  // Alice receives identity message (from Charlie), sends Auth-R message
  ignore = otrv4_client_receive(&from_alice_to_charlie, &todisplay, fromcharlie,
                               CHARLIE_IDENTITY, alice);
  free(fromcharlie);
  fromcharlie = NULL;

  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrv4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrv4_assert(ignore);
  otrv4_assert(frombob);
  otrv4_assert(!todisplay);

  // Charlie receives Auth-R message, sends Auth-I message
  ignore = otrv4_client_receive(&fromcharlie, &todisplay, from_alice_to_charlie,
                               ALICE_IDENTITY, charlie);
  free(from_alice_to_charlie);
  from_alice_to_charlie = NULL;

  otrv4_assert(ignore);
  otrv4_assert(fromcharlie);
  otrv4_assert(!todisplay);

  // Alice receives Auth-I message (from Bob)
  ignore = otrv4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  otrv4_assert(!from_alice_to_bob);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  // Alice receives Auth-I message (from Charlie)
  ignore = otrv4_client_receive(&from_alice_to_charlie, &todisplay, fromcharlie,
                               CHARLIE_IDENTITY, alice);
  free(fromcharlie);
  fromcharlie = NULL;

  otrv4_assert(!from_alice_to_charlie);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  // Alice sends a disconnected to Bob
  int err = otrv4_client_disconnect(&from_alice_to_bob, BOB_IDENTITY, alice);
  otrv4_assert(!err);
  otrv4_assert(from_alice_to_bob);

  // We've deleted the conversation
  otrv4_assert(
      !otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice));

  // TODO: Should we keep the conversation and set state to start instead?
  // g_assert_cmpint(alice_to_bob->conn->state, ==, OTRV4_STATE_START);

  // Bob receives the disconnected from Alice
  ignore = otrv4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrv4_assert(ignore);
  otrv4_assert(!frombob);
  otrv4_assert(!todisplay);

  // Free memory
  otrv4_userstate_free_all(alice_state->userstate, bob_state->userstate,
                           charlie_state->userstate);
  otrv4_client_state_free_all(alice_state, bob_state, charlie_state);
  otrv4_client_free_all(alice, bob, charlie);

  OTR4_FREE
}

void test_client_get_our_fingerprint() {
  OTR4_INIT;

  otrv4_client_state_t *alice_state = otrv4_client_state_new("alice");
  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);

  otrv4_fingerprint_t our_fp = {0};
  otrv4_assert(!otrv4_client_get_our_fingerprint(our_fp, alice));

  uint8_t serialized[ED448_PUBKEY_BYTES] = {0};
  g_assert_cmpint(
      otrv4_serialize_otrv4_public_key(serialized, alice_state->keypair->pub), ==,
      ED448_PUBKEY_BYTES);

  otrv4_fingerprint_t expected_fp = {0};
  hash_hash(expected_fp, sizeof(otrv4_fingerprint_t), serialized,
            sizeof(serialized));
  otrv4_assert_cmpmem(expected_fp, our_fp, sizeof(otrv4_fingerprint_t));

  otrl_userstate_free(alice_state->userstate);
  otrv4_client_state_free(alice_state);
  otrv4_client_free(alice);

  OTR4_FREE
}

void test_fingerprint_hash_to_human() {
  char *expected_fp = "00010203 04050607 08090A0B 0C0D0E0F "
                      "10111213 14151617 18191A1B 1C1D1E1F "
                      "20212223 24252627 28292A2B 2C2D2E2F "
                      "30313233 34353637";

  uint8_t fp_hash[FPRINT_LEN_BYTES] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  };

  char fp_human[FPRINT_HUMAN_LEN];
  memset(fp_human, 0, sizeof fp_human);

  otrv4_fingerprint_hash_to_human(fp_human, fp_hash);

  g_assert_cmpint(0, ==, strncmp(expected_fp, fp_human, FPRINT_HUMAN_LEN));
}

void test_conversation_with_multiple_locations() {
  OTR4_INIT;

  otrv4_client_state_t *alice_state = otrv4_client_state_new("alice");
  otrv4_client_state_t *bob_state = otrv4_client_state_new("bob");

  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);
  otrv4_client_t *bob = set_up_client(bob_state, BOB_IDENTITY, PHI, 2);

  char *query_msg =
      otrv4_client_query_message(BOB_IDENTITY, "Hi bob", alice, OTRV4_ALLOW_V4);

  int ignore = 0;
  char *from_alice_to_bob = NULL, *frombob = NULL, *todisplay = NULL;

  // Bob receives query message, sends identity msg
  ignore =
      otrv4_client_receive(&frombob, &todisplay, query_msg, ALICE_IDENTITY, bob);
  free(query_msg);
  query_msg = NULL;

  // Alice receives identity message (from Bob), sends Auth-R message
  ignore = otrv4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrv4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice receives Auth-I message (from Bob)
  ignore = otrv4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  char *message = "hello";

  // Bob sends a message with original instance tag
  otrv4_client_send(&frombob, message, ALICE_IDENTITY, bob);

  // Alice receives the message.
  ignore = otrv4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  otrv4_assert(!ignore);
  otrv4_assert(!from_alice_to_bob);
  otrv4_assert(todisplay);

  free(todisplay);
  todisplay = NULL;

  // Bob sends a message with a different instance tag
  otrv4_conversation_t *conv =
      otrv4_client_get_conversation(0, ALICE_IDENTITY, bob);
  conv->conn->their_instance_tag = conv->conn->their_instance_tag + 1;
  otrv4_client_send(&frombob, "hello again", ALICE_IDENTITY, bob);

  // Alice receives and ignores the message.
  ignore = otrv4_client_receive(&from_alice_to_bob, &todisplay, frombob,
                               BOB_IDENTITY, alice);
  free(frombob);
  frombob = NULL;

  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  // Free the ignored reply
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice sends a disconnected to Bob
  otrv4_client_disconnect(&from_alice_to_bob, BOB_IDENTITY, alice);

  // Bob receives the disconnected from Alice
  ignore = otrv4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Free the ignored reply
  free(frombob);
  frombob = NULL;

  // Free memory
  otrv4_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(alice_state, bob_state);
  otrv4_client_free_all(alice, bob);

  OTR4_FREE
}

void test_valid_identity_msg_in_waiting_auth_i() {
  OTR4_INIT;

  otrv4_client_state_t *alice_state = otrv4_client_state_new("alice");
  otrv4_client_state_t *bob_state = otrv4_client_state_new("bob");

  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);
  otrv4_client_t *bob = set_up_client(bob_state, BOB_IDENTITY, PHI, 2);

  char *query_msg_to_bob =
      otrv4_client_query_message(BOB_IDENTITY, "Hi bob", alice, OTRV4_ALLOW_V4);

  int ignore = 0;
  char *from_alice_to_bob = NULL, *todisplay = NULL, *bobs_id = NULL,
       *bobs_auth_i = NULL, *frombob = NULL;

  // Bob receives query message, sends identity message
  // Do not free bob identity message
  // Do not free alice query message
  ignore = otrv4_client_receive(&bobs_id, &todisplay, query_msg_to_bob,
                               ALICE_IDENTITY, bob);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  // Alice receives identity message (from Bob), sends Auth-R message
  ignore = otrv4_client_receive(&from_alice_to_bob, &todisplay, bobs_id,
                               BOB_IDENTITY, alice);

  otrv4_assert(from_alice_to_bob);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  otrv4_conversation_t *alice_to_bob =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice);

  ec_point_t stored_their_ecdh;
  otrv4_ec_point_copy(stored_their_ecdh, alice_to_bob->conn->keys->their_ecdh);

  dh_public_key_t stored_their_dh;
  stored_their_dh = otrv4_dh_mpi_copy(alice_to_bob->conn->keys->their_dh);

  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  free(bobs_id);
  bobs_id = NULL;

  // Bob generates an identity message again
  ignore = otrv4_client_receive(&bobs_id, &todisplay, query_msg_to_bob,
                               ALICE_IDENTITY, bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  otrv4_conversation_t *bob_to_alice =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, ALICE_IDENTITY, bob);

  otrv4_assert(bob_to_alice->conn->state == OTRV4_STATE_WAITING_AUTH_R);

  // Alice receives identity message (from Bob) again, sends Auth-R message
  ignore = otrv4_client_receive(&from_alice_to_bob, &todisplay, bobs_id,
                               BOB_IDENTITY, alice);
  free(bobs_id);
  bobs_id = NULL;

  ec_point_t new_their_ecdh;
  otrv4_ec_point_copy(new_their_ecdh, alice_to_bob->conn->keys->their_ecdh);

  dh_public_key_t new_their_dh;
  new_their_dh = otrv4_dh_mpi_copy(alice_to_bob->conn->keys->their_dh);

  otrv4_assert(otrv4_ec_point_eq(stored_their_ecdh, new_their_ecdh) == otrv4_false);
  otrv4_ec_point_destroy(stored_their_ecdh);
  otrv4_ec_point_destroy(new_their_ecdh);

  g_assert_cmpint(dh_mpi_cmp(stored_their_dh, new_their_dh), !=, 0);
  otrv4_dh_mpi_release(stored_their_dh);
  stored_their_dh = NULL;
  otrv4_dh_mpi_release(new_their_dh);
  new_their_dh = NULL;

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_WAITING_AUTH_I);

  otrv4_assert(ignore);
  otrv4_assert(from_alice_to_bob);
  otrv4_assert(!todisplay);

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrv4_client_receive(&bobs_auth_i, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrv4_assert(ignore);
  otrv4_assert(bobs_auth_i);
  otrv4_assert(!todisplay);

  // Alice receives auth-i message (from Bob)
  ignore = otrv4_client_receive(&from_alice_to_bob, &todisplay, bobs_auth_i,
                               BOB_IDENTITY, alice);
  free(bobs_auth_i);
  bobs_auth_i = NULL;

  otrv4_assert(!from_alice_to_bob);
  otrv4_assert(ignore);
  otrv4_assert(!todisplay);

  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice sends a disconnected to Bob
  int err = otrv4_client_disconnect(&from_alice_to_bob, BOB_IDENTITY, alice);
  otrv4_assert(!err);
  otrv4_assert(from_alice_to_bob);

  // We've deleted the conversation
  otrv4_assert(
      !otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice));

  // Bob receives the disconnected from Alice
  ignore = otrv4_client_receive(&frombob, &todisplay, from_alice_to_bob,
                               ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrv4_assert(ignore);
  otrv4_assert(!frombob);
  otrv4_assert(!todisplay);

  // Free memory
  otrv4_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(alice_state, bob_state);
  otrv4_client_free_all(alice, bob);

  OTR4_FREE
}

void test_invalid_auth_r_msg_in_not_waiting_auth_r() {
  OTR4_INIT;

  otrv4_client_state_t *alice_state = otrv4_client_state_new("alice");
  otrv4_client_state_t *bob_state = otrv4_client_state_new("bob");

  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);
  otrv4_client_t *bob = set_up_client(bob_state, BOB_IDENTITY, PHI, 2);

  // Alice sends a query message to Bob
  char *query_msg_to_bob =
      otrv4_client_query_message(BOB_IDENTITY, "Hi bob", alice, OTRV4_ALLOW_V4);

  int ignore = 0;
  char *todisplay = NULL, *bobs_id = NULL, *alices_auth_r = NULL,
       *bobs_auth_i = NULL, *bob_last = NULL, *alice_last = NULL,
       *ignores = NULL;

  // Bob receives query message, sends identity msg
  ignore = otrv4_client_receive(&bobs_id, &todisplay, query_msg_to_bob,
                               ALICE_IDENTITY, bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  otrv4_assert(ignore);
  otrv4_assert(bobs_id);
  otrv4_assert(!todisplay);

  otrv4_conversation_t *alice_to_bob =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  otrv4_conversation_t *bob_to_alice =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, ALICE_IDENTITY, bob);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_START);
  otrv4_assert(bob_to_alice->conn->state == OTRV4_STATE_WAITING_AUTH_R);

  // Alice receives identity message, sends Auth-R msg
  // Do not free bob identity message
  ignore = otrv4_client_receive(&alices_auth_r, &todisplay, bobs_id,
                               BOB_IDENTITY, alice);
  otrv4_assert(ignore);
  otrv4_assert(alices_auth_r);
  otrv4_assert(!todisplay);
  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_WAITING_AUTH_I);

  free(bobs_id);
  bobs_id = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrv4_client_receive(&bobs_auth_i, &todisplay, alices_auth_r,
                               ALICE_IDENTITY, bob);
  otrv4_assert(ignore);
  otrv4_assert(bobs_auth_i);
  otrv4_assert(!todisplay);

  otrv4_assert(bob_to_alice->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES);

  // Bob receives again Auth-R message, ignores
  ignore = otrv4_client_receive(&ignores, &todisplay, alices_auth_r,
                               ALICE_IDENTITY, bob);
  free(alices_auth_r);
  alices_auth_r = NULL;

  otrv4_assert(ignore);
  otrv4_assert(!ignores);
  otrv4_assert(!todisplay);

  otrv4_assert(bob_to_alice->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES);

  // Alice receives Auth-I message
  ignore = otrv4_client_receive(&alice_last, &todisplay, bobs_auth_i,
                               BOB_IDENTITY, alice);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES);

  otrv4_assert(ignore);
  otrv4_assert(!alice_last);
  otrv4_assert(!todisplay);

  free(bobs_auth_i);
  bobs_auth_i = NULL;

  free(alice_last);
  alice_last = NULL;

  // Alice sends a disconnected to Bob
  int error = otrv4_client_disconnect(&alice_last, BOB_IDENTITY, alice);
  otrv4_assert(!error);
  otrv4_assert(alice_last);

  // We've deleted the conversation
  otrv4_assert(
      !otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice));

  // Bob receives the disconnected from Alice
  ignore = otrv4_client_receive(&bob_last, &todisplay, alice_last,
                               ALICE_IDENTITY, bob);
  free(alice_last);
  alice_last = NULL;

  otrv4_assert(ignore);
  otrv4_assert(!bob_last);
  otrv4_assert(!todisplay);

  free(bob_last);
  bob_last = NULL;

  // Free memory
  otrv4_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(alice_state, bob_state);
  otrv4_client_free_all(alice, bob);

  OTR4_FREE
}

void test_valid_identity_msg_in_waiting_auth_r() {
  OTR4_INIT;

  otrv4_client_state_t *alice_state = otrv4_client_state_new("alice");
  otrv4_client_state_t *bob_state = otrv4_client_state_new("bob");

  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);
  otrv4_client_t *bob = set_up_client(bob_state, BOB_IDENTITY, PHI, 2);

  // Alice sends a query message to Bob
  char *query_msg_to_bob =
      otrv4_client_query_message(BOB_IDENTITY, "Hi bob", alice, OTRV4_ALLOW_V4);

  // Bob sends a query message to Alice
  char *query_msg_to_alice = otrv4_client_query_message(
      ALICE_IDENTITY, "Hi alice", bob, OTRV4_ALLOW_V4);

  int ignore = 0;
  char *todisplay = NULL, *alices_id = NULL, *bobs_id = NULL,
       *alices_auth_r = NULL, *bobs_auth_r = NULL, *alices_auth_i = NULL,
       *bobs_auth_i = NULL, *bob_last = NULL, *alice_last = NULL;

  // Alice receives query message, sends identity message
  ignore = otrv4_client_receive(&alices_id, &todisplay, query_msg_to_alice,
                               BOB_IDENTITY, alice);
  otrv4_assert(ignore);
  otrv4_assert(alices_id);
  otrv4_assert(!todisplay);

  free(query_msg_to_alice);
  query_msg_to_alice = NULL;

  otrv4_conversation_t *alice_to_bob =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  otrv4_conversation_t *bob_to_alice =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, ALICE_IDENTITY, bob);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_WAITING_AUTH_R);
  otrv4_assert(bob_to_alice->conn->state == OTRV4_STATE_START);

  // Bob receives query message, sends identity message
  ignore = otrv4_client_receive(&bobs_id, &todisplay, query_msg_to_bob,
                               ALICE_IDENTITY, bob);
  otrv4_assert(ignore);
  otrv4_assert(bobs_id);
  otrv4_assert(!todisplay);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_WAITING_AUTH_R);
  otrv4_assert(bob_to_alice->conn->state == OTRV4_STATE_WAITING_AUTH_R);

  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  // Alice receives identity message. At this point, she can either:
  // 1. ignore and resend her identity message
  // 2. send an Auth-R message
  ignore = otrv4_client_receive(&alices_auth_r, &todisplay, bobs_id,
                               BOB_IDENTITY, alice);

  // 2. Alice sends and Auth-R message
  if (alices_auth_r) {
    free(alices_id);
    alices_id = NULL;

    free(bobs_id);
    bobs_id = NULL;

    otrv4_assert(ignore);
    otrv4_assert(!todisplay);

    // Bob receives and Auth-R message. He sends and Auth-I message.
    ignore = otrv4_client_receive(&bobs_auth_i, &todisplay, alices_auth_r,
                                 ALICE_IDENTITY, bob);
    free(alices_auth_r);
    alices_auth_r = NULL;

    otrv4_assert(bobs_auth_i);
    otrv4_assert(ignore);
    otrv4_assert(!todisplay);

    // Alice receives Auth-I message
    ignore = otrv4_client_receive(&alice_last, &todisplay, bobs_auth_i,
                                 BOB_IDENTITY, alice);
    free(bobs_auth_i);
    bobs_auth_i = NULL;

    otrv4_assert(!alice_last);
    otrv4_assert(ignore);
    otrv4_assert(!todisplay);

    // Alice sends a disconnected to Alice
    int error = otrv4_client_disconnect(&alice_last, BOB_IDENTITY, alice);
    otrv4_assert(!error);
    otrv4_assert(alice_last);

    // We've deleted the conversation
    otrv4_assert(!otrv4_client_get_conversation(!FORCE_CREATE_CONVO,
                                               BOB_IDENTITY, alice));

    // Bob receives the disconnected from Alice
    ignore = otrv4_client_receive(&bob_last, &todisplay, alice_last,
                                 ALICE_IDENTITY, bob);
    free(alice_last);
    alice_last = NULL;

    otrv4_assert(ignore);
    otrv4_assert(!bob_last);
    otrv4_assert(!todisplay);

  } else {
    // 1. Alice ignores and resends her identity message
    otrv4_assert(ignore);
    otrv4_assert(!alices_auth_r);
    otrv4_assert(!todisplay);

    free(bobs_id);
    bobs_id = NULL;

    // Bob receives an identity message on state
    // OTRV4_WAITING_FOR_AUTH-R. He is now the lower side
    ignore = otrv4_client_receive(&bobs_auth_r, &todisplay, alices_id,
                                 ALICE_IDENTITY, bob);
    free(alices_id);
    alices_id = NULL;

    otrv4_assert(bobs_auth_r);
    otrv4_assert(ignore);
    otrv4_assert(!todisplay);

    // Alice receives Auth-R, sends Auth-I
    ignore = otrv4_client_receive(&alices_auth_i, &todisplay, bobs_auth_r,
                                 BOB_IDENTITY, alice);
    free(bobs_auth_r);
    bobs_auth_r = NULL;

    otrv4_assert(ignore);
    otrv4_assert(alices_auth_i);
    otrv4_assert(!todisplay);

    // Bob receives Auth-I message
    ignore = otrv4_client_receive(&bob_last, &todisplay, alices_auth_i,
                                 ALICE_IDENTITY, bob);
    free(alices_auth_i);
    alices_auth_i = NULL;

    otrv4_assert(!bob_last);
    otrv4_assert(ignore);
    otrv4_assert(!todisplay);

    // Bob sends a disconnected to Alice
    int error = otrv4_client_disconnect(&bob_last, ALICE_IDENTITY, bob);
    otrv4_assert(!error);
    otrv4_assert(bob_last);

    // We've deleted the conversation
    otrv4_assert(!otrv4_client_get_conversation(!FORCE_CREATE_CONVO,
                                               ALICE_IDENTITY, bob));

    // Alice receives the disconnected from Bob
    ignore = otrv4_client_receive(&alice_last, &todisplay, bob_last,
                                 BOB_IDENTITY, alice);
    free(bob_last);
    bob_last = NULL;

    otrv4_assert(ignore);
    otrv4_assert(!alice_last);
    otrv4_assert(!todisplay);
  }
  // Free memory
  otrv4_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(alice_state, bob_state);
  otrv4_client_free_all(alice, bob);

  OTR4_FREE
}

void test_invalid_auth_i_msg_in_not_waiting_auth_i() {
  OTR4_INIT;

  otrv4_client_state_t *alice_state = otrv4_client_state_new("alice");
  otrv4_client_state_t *bob_state = otrv4_client_state_new("bob");

  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);
  otrv4_client_t *bob = set_up_client(bob_state, BOB_IDENTITY, PHI, 2);

  // Alice sends a query message to Bob
  char *query_msg_to_bob =
      otrv4_client_query_message(BOB_IDENTITY, "Hi bob", alice, OTRV4_ALLOW_V4);

  int ignore = 0;
  char *todisplay = NULL, *bobs_id = NULL, *alices_auth_r = NULL,
       *bobs_auth_i = NULL, *bob_last = NULL, *alice_last = NULL;

  // Bob receives query message, sends identity message
  ignore = otrv4_client_receive(&bobs_id, &todisplay, query_msg_to_bob,
                               ALICE_IDENTITY, bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  otrv4_assert(ignore);
  otrv4_assert(bobs_id);
  otrv4_assert(!todisplay);

  otrv4_conversation_t *alice_to_bob =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice);
  otrv4_conversation_t *bob_to_alice =
      otrv4_client_get_conversation(!FORCE_CREATE_CONVO, ALICE_IDENTITY, bob);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_START);
  otrv4_assert(bob_to_alice->conn->state == OTRV4_STATE_WAITING_AUTH_R);

  // Alice receives identity message, sends Auth-R msg
  ignore = otrv4_client_receive(&alices_auth_r, &todisplay, bobs_id,
                               BOB_IDENTITY, alice);
  free(bobs_id);
  bobs_id = NULL;

  otrv4_assert(ignore);
  otrv4_assert(alices_auth_r);
  otrv4_assert(!todisplay);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_WAITING_AUTH_I);

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrv4_client_receive(&bobs_auth_i, &todisplay, alices_auth_r,
                               ALICE_IDENTITY, bob);
  free(alices_auth_r);
  alices_auth_r = NULL;

  otrv4_assert(ignore);
  otrv4_assert(bobs_auth_i);
  otrv4_assert(!todisplay);

  otrv4_assert(bob_to_alice->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES);

  // Alice receives Auth-I message
  ignore = otrv4_client_receive(&alice_last, &todisplay, bobs_auth_i,
                               BOB_IDENTITY, alice);
  otrv4_assert(ignore);
  otrv4_assert(!alice_last);
  otrv4_assert(!todisplay);

  otrv4_assert(alice_to_bob->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES);

  // Alice receives Auth-I message again
  ignore = otrv4_client_receive(&alice_last, &todisplay, bobs_auth_i,
                               BOB_IDENTITY, alice);
  otrv4_assert(ignore);
  otrv4_assert(!alice_last);
  otrv4_assert(!todisplay);

  free(bobs_auth_i);
  bobs_auth_i = NULL;

  free(alice_last);
  alice_last = NULL;

  // Alice sends a disconnected to Bob
  int error = otrv4_client_disconnect(&alice_last, BOB_IDENTITY, alice);
  otrv4_assert(!error);
  otrv4_assert(alice_last);

  // We've deleted the conversation
  otrv4_assert(
      !otrv4_client_get_conversation(!FORCE_CREATE_CONVO, BOB_IDENTITY, alice));

  // Bob receives the disconnected from Alice
  ignore = otrv4_client_receive(&bob_last, &todisplay, alice_last,
                               ALICE_IDENTITY, bob);
  free(alice_last);
  alice_last = NULL;

  otrv4_assert(ignore);
  otrv4_assert(!bob_last);
  otrv4_assert(!todisplay);

  free(bob_last);
  bob_last = NULL;

  // Free memory
  otrv4_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(alice_state, bob_state);
  otrv4_client_free_all(alice, bob);

  OTR4_FREE
}

void test_client_receives_fragmented_message(void) {
  char *msg = "Receiving fragmented plaintext";

  otrv4_message_to_send_t *fmsg = malloc(sizeof(otrv4_message_to_send_t));
  otrv4_assert(otrv4_fragment_message(60, fmsg, 0, 0, msg) == SUCCESS);

  otrv4_client_state_t *alice_state = otrv4_client_state_new("alice");
  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);

  char *tosend = NULL, *todisplay = NULL;

  for (int i = 0; i < fmsg->total; i++) {
    otrv4_client_receive(&tosend, &todisplay, fmsg->pieces[i], BOB_IDENTITY,
                        alice);
    otrv4_assert(!tosend);
  }

  g_assert_cmpstr(todisplay, ==, "Receiving fragmented plaintext");

  free(todisplay);
  todisplay = NULL;

  otrv4_message_free(fmsg);
  otrl_userstate_free(alice_state->userstate);
  otrv4_client_state_free(alice_state);
  otrv4_client_free(alice);
}

void test_client_sends_fragmented_message(void) {
  OTR4_INIT;

  otrv4_client_state_t *alice_state = otrv4_client_state_new("alice");
  otrv4_client_state_t *bob_state = otrv4_client_state_new("bob");

  otrv4_client_t *alice = set_up_client(alice_state, ALICE_IDENTITY, PHI, 1);
  otrv4_client_t *bob = set_up_client(bob_state, BOB_IDENTITY, PHI, 2);

  char *query_msg_to_bob =
      otrv4_client_query_message(BOB_IDENTITY, "Hi bob", alice, OTRV4_ALLOW_V4);
  otrv4_assert(query_msg_to_bob);

  char *from_alice_to_bob = NULL, *from_bob = NULL, *todisplay = NULL;

  // Bob receives query message, sends identity msg
  otrv4_client_receive(&from_bob, &todisplay, query_msg_to_bob, ALICE_IDENTITY,
                      bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  // Alice receives identity message (from Bob), sends Auth-R message
  otrv4_client_receive(&from_alice_to_bob, &todisplay, from_bob, BOB_IDENTITY,
                      alice);
  free(from_bob);
  from_bob = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  otrv4_client_receive(&from_bob, &todisplay, from_alice_to_bob, ALICE_IDENTITY,
                      bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice receives Auth-I message (from Bob)
  otrv4_client_receive(&from_alice_to_bob, &todisplay, from_bob, BOB_IDENTITY,
                      alice);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;
  free(from_bob);
  from_bob = NULL;

  otrv4_message_to_send_t *to_send = otrv4_message_new();
  char *message = "We should fragment when is needed";

  // Alice fragments the message
  otrv4_client_send_fragment(&to_send, message, 100, BOB_IDENTITY, alice);

  for (int i = 0; i < to_send->total; i++) {
    // Bob receives the fragments
    otrv4_client_receive(&from_bob, &todisplay, to_send->pieces[i],
                        ALICE_IDENTITY, bob);
    otrv4_assert(!from_bob);

    if (to_send->total - 1 == i)
      g_assert_cmpstr(todisplay, ==, message);
  }

  free(from_bob);
  from_bob = NULL;

  free(todisplay);
  todisplay = NULL;

  otrv4_message_free(to_send);
  otrv4_userstate_free_all(alice_state->userstate, bob_state->userstate);
  otrv4_client_state_free_all(alice_state, bob_state);
  otrv4_client_free_all(alice, bob);

  OTR4_FREE;
}
