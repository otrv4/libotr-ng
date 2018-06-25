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

#include <stdio.h>

#include "../client.h"
#include "../fragment.h"
#include "../instance_tag.h"
#include "../messaging.h"
#include "../serialize.h"
#include "../shake.h"

// TODO: This function is duplicate. See test_api.c
static otrng_client_s *set_up_client(otrng_client_state_s *state,
                                     const char *account_name, uint8_t byte) {
  set_up_client_state(state, account_name, byte);
  otrng_client_s *dst = otrng_client_new(state);

  return dst;
}

void test_client_conversation_api() {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_assert(!alice->conversations);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_IDENTITY, alice);
  otrng_conversation_s *alice_to_charlie = otrng_client_get_conversation(
      NOT_FORCE_CREATE_CONV, CHARLIE_IDENTITY, alice);
  otrng_assert(!alice->conversations);
  otrng_assert(!alice_to_bob);
  otrng_assert(!alice_to_charlie);

  alice_to_bob =
      otrng_client_get_conversation(FORCE_CREATE_CONV, BOB_IDENTITY, alice);
  alice_to_charlie =
      otrng_client_get_conversation(FORCE_CREATE_CONV, CHARLIE_IDENTITY, alice);
  otrng_assert(alice_to_bob);
  otrng_assert(alice_to_bob->conn);
  otrng_assert(alice_to_charlie);
  otrng_assert(alice_to_charlie->conn);

  alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_IDENTITY, alice);
  alice_to_charlie = otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                                   CHARLIE_IDENTITY, alice);
  otrng_assert(alice_to_bob);
  otrng_assert(alice_to_bob->conn);
  otrng_assert(alice_to_charlie);
  otrng_assert(alice_to_charlie->conn);

  // Free memory
  otrl_userstate_free(alice_client_state->user_state);
  otrng_client_state_free(alice_client_state);
  otrng_client_free(alice);
}

void test_client_api() {
  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_state_s *bob_client_state = otrng_client_state_new("bob");
  otrng_client_state_s *charlie_state = otrng_client_state_new("charlie");

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_client_s *bob = set_up_client(bob_client_state, BOB_IDENTITY, 2);
  otrng_client_s *charlie = set_up_client(charlie_state, CHARLIE_IDENTITY, 3);

  char *query_msg_to_bob =
      otrng_client_query_message(BOB_IDENTITY, "Hi bob", alice);
  otrng_assert(query_msg_to_bob);

  char *query_msg_to_charlie =
      otrng_client_query_message(CHARLIE_IDENTITY, "Hi charlie", alice);
  otrng_assert(query_msg_to_charlie);

  int ignore = 0;
  char *from_alice_to_bob = NULL, *from_alice_to_charlie = NULL,
       *from_bob = NULL, *from_charlie = NULL, *to_display = NULL;

  // Bob receives query message, sends the identity message
  ignore = otrng_client_receive(&from_bob, &to_display, query_msg_to_bob,
                                ALICE_IDENTITY, bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  otrng_assert(ignore);
  otrng_assert(!to_display);

  // Charlie receives query message, sends identity message
  ignore = otrng_client_receive(&from_charlie, &to_display,
                                query_msg_to_charlie, ALICE_IDENTITY, charlie);
  free(query_msg_to_charlie);
  query_msg_to_charlie = NULL;

  otrng_assert(ignore);
  otrng_assert(!to_display);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_IDENTITY, alice);
  otrng_conversation_s *alice_to_charlie = otrng_client_get_conversation(
      NOT_FORCE_CREATE_CONV, CHARLIE_IDENTITY, alice);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_START);
  otrng_assert(alice_to_charlie->conn->state == OTRNG_STATE_START);

  // Alice receives identity message (from Bob), sends Auth-R message
  ignore = otrng_client_receive(&from_alice_to_bob, &to_display, from_bob,
                                BOB_IDENTITY, alice);
  free(from_bob);
  from_bob = NULL;

  otrng_assert(from_alice_to_bob);
  otrng_assert(ignore);
  otrng_assert(!to_display);

  // Alice receives identity message (from Charlie), sends Auth-R message
  ignore = otrng_client_receive(&from_alice_to_charlie, &to_display,
                                from_charlie, CHARLIE_IDENTITY, alice);
  free(from_charlie);
  from_charlie = NULL;

  otrng_assert(ignore);
  otrng_assert(!to_display);

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrng_client_receive(&from_bob, &to_display, from_alice_to_bob,
                                ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(ignore);
  otrng_assert(from_bob);
  otrng_assert(!to_display);

  // Charlie receives Auth-R message, sends Auth-I message
  ignore = otrng_client_receive(&from_charlie, &to_display,
                                from_alice_to_charlie, ALICE_IDENTITY, charlie);
  free(from_alice_to_charlie);
  from_alice_to_charlie = NULL;

  otrng_assert(ignore);
  otrng_assert(from_charlie);
  otrng_assert(!to_display);

  // Alice receives Auth-I message (from Bob)
  ignore = otrng_client_receive(&from_alice_to_bob, &to_display, from_bob,
                                BOB_IDENTITY, alice);
  free(from_bob);
  from_bob = NULL;

  otrng_assert(!from_alice_to_bob);
  otrng_assert(ignore);
  otrng_assert(!to_display);

  // Alice receives Auth-I message (from Charlie)
  ignore = otrng_client_receive(&from_alice_to_charlie, &to_display,
                                from_charlie, CHARLIE_IDENTITY, alice);
  free(from_charlie);
  from_charlie = NULL;

  otrng_assert(!from_alice_to_charlie);
  otrng_assert(ignore);
  otrng_assert(!to_display);

  // Alice sends a disconnected to Bob
  int err = otrng_client_disconnect(&from_alice_to_bob, BOB_IDENTITY, alice);
  otrng_assert(!err);
  otrng_assert(from_alice_to_bob);

  // We've deleted the conversation
  otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                              BOB_IDENTITY, alice));

  // TODO: @client Should we keep the conversation and set state to start
  // instead? g_assert_cmpint(alice_to_bob->conn->state, ==, OTRNG_STATE_START);

  // Bob receives the disconnected from Alice
  ignore = otrng_client_receive(&from_bob, &to_display, from_alice_to_bob,
                                ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(ignore);
  otrng_assert(!from_bob);
  otrng_assert(!to_display);

  // Free memory
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state,
                            charlie_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state,
                              charlie_state);
  otrng_client_free_all(alice, bob, charlie);
}

void test_client_get_our_fingerprint() {
  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);

  otrng_fingerprint_p expected_fp = {0};
  otrng_assert(!otrng_serialize_fingerprint(expected_fp,
                                            alice_client_state->keypair->pub));

  otrng_fingerprint_p our_fp = {0};
  otrng_assert(!otrng_client_get_our_fingerprint(our_fp, alice));
  otrng_assert_cmpmem(expected_fp, our_fp, sizeof(otrng_fingerprint_p));

  otrl_userstate_free(alice_client_state->user_state);
  otrng_client_state_free(alice_client_state);
  otrng_client_free(alice);
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

  otrng_fingerprint_hash_to_human(fp_human, fp_hash);

  g_assert_cmpint(0, ==, strncmp(expected_fp, fp_human, FPRINT_HUMAN_LEN));
}

void test_conversation_with_multiple_locations() {
  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_state_s *bob_client_state = otrng_client_state_new("bob");

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_client_s *bob = set_up_client(bob_client_state, BOB_IDENTITY, 2);

  char *query_msg = otrng_client_query_message(BOB_IDENTITY, "Hi bob", alice);

  int ignore = 0;
  char *from_alice_to_bob = NULL, *from_bob = NULL, *to_display = NULL;

  // Bob receives query message, sends identity msg
  ignore = otrng_client_receive(&from_bob, &to_display, query_msg,
                                ALICE_IDENTITY, bob);
  free(query_msg);

  // Alice receives identity message (from Bob), sends Auth-R message
  ignore = otrng_client_receive(&from_alice_to_bob, &to_display, from_bob,
                                BOB_IDENTITY, alice);
  free(from_bob);
  from_bob = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrng_client_receive(&from_bob, &to_display, from_alice_to_bob,
                                ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice receives Auth-I message (from Bob)
  ignore = otrng_client_receive(&from_alice_to_bob, &to_display, from_bob,
                                BOB_IDENTITY, alice);
  free(from_bob);
  from_bob = NULL;

  char *message = "hello";

  // Alice sends a message with original instance tag
  otrng_client_send(&from_alice_to_bob, message, BOB_IDENTITY, alice);

  // Bob receives the message.
  ignore = otrng_client_receive(&from_bob, &to_display, from_alice_to_bob,
                                ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(!from_bob);
  otrng_assert(to_display);

  free(to_display);
  to_display = NULL;

  // Alice sends a message with a different instance tag
  otrng_conversation_s *conv =
      otrng_client_get_conversation(0, BOB_IDENTITY, alice);
  conv->conn->their_instance_tag = conv->conn->their_instance_tag + 1;
  otrng_client_send(&from_alice_to_bob, "hello again", BOB_IDENTITY, alice);

  // Bob receives and ignore the message.
  ignore = otrng_client_receive(&from_bob, &to_display, from_alice_to_bob,
                                ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(ignore);
  otrng_assert(!to_display);

  // Free the ignored reply
  free(from_bob);
  from_bob = NULL;

  // Bob sends a disconnected to Alice
  otrng_client_disconnect(&from_bob, ALICE_IDENTITY, bob);

  // Alice receives the disconnected from Alice
  ignore = otrng_client_receive(&from_alice_to_bob, &to_display, from_bob,
                                BOB_IDENTITY, alice);
  free(from_bob);
  from_bob = NULL;

  // Free the ignored reply
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Free memory
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_client_free_all(alice, bob);
}

void test_valid_identity_msg_in_waiting_auth_i() {
  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_state_s *bob_client_state = otrng_client_state_new("bob");

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_client_s *bob = set_up_client(bob_client_state, BOB_IDENTITY, 2);

  char *query_msg_to_bob =
      otrng_client_query_message(BOB_IDENTITY, "Hi bob", alice);

  int ignore = 0;
  char *from_alice_to_bob = NULL, *to_display = NULL, *bobs_id = NULL,
       *bobs_auth_i = NULL, *from_bob = NULL;

  // Bob receives query message, sends identity message
  // Do not free bob identity message
  // Do not free alice query message
  ignore = otrng_client_receive(&bobs_id, &to_display, query_msg_to_bob,
                                ALICE_IDENTITY, bob);
  otrng_assert(ignore);
  otrng_assert(!to_display);

  otrng_conversation_s *bob_to_alice =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, ALICE_IDENTITY, bob);

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  // Alice receives identity message (from Bob), sends Auth-R message
  ignore = otrng_client_receive(&from_alice_to_bob, &to_display, bobs_id,
                                BOB_IDENTITY, alice);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_IDENTITY, alice);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_I);
  otrng_assert(from_alice_to_bob);
  otrng_assert(ignore);
  otrng_assert(!to_display);

  ec_point_p stored_their_ecdh;
  otrng_ec_point_copy(stored_their_ecdh, alice_to_bob->conn->keys->their_ecdh);

  dh_public_key_p stored_their_dh;
  stored_their_dh = otrng_dh_mpi_copy(alice_to_bob->conn->keys->their_dh);

  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  free(bobs_id);
  bobs_id = NULL;

  // Bob generates an identity message again
  ignore = otrng_client_receive(&bobs_id, &to_display, query_msg_to_bob,
                                ALICE_IDENTITY, bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  // Alice receives identity message (from Bob) again, sends Auth-R message
  ignore = otrng_client_receive(&from_alice_to_bob, &to_display, bobs_id,
                                BOB_IDENTITY, alice);
  free(bobs_id);
  bobs_id = NULL;

  ec_point_p new_their_ecdh;
  otrng_ec_point_copy(new_their_ecdh, alice_to_bob->conn->keys->their_ecdh);

  dh_public_key_p new_their_dh;
  new_their_dh = otrng_dh_mpi_copy(alice_to_bob->conn->keys->their_dh);

  otrng_assert(otrng_ec_point_eq(stored_their_ecdh, new_their_ecdh) ==
               otrng_false);
  otrng_ec_point_destroy(stored_their_ecdh);
  otrng_ec_point_destroy(new_their_ecdh);

  g_assert_cmpint(dh_mpi_cmp(stored_their_dh, new_their_dh), !=, 0);
  otrng_dh_mpi_release(stored_their_dh);
  stored_their_dh = NULL;
  otrng_dh_mpi_release(new_their_dh);
  new_their_dh = NULL;

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_I);

  otrng_assert(ignore);
  otrng_assert(from_alice_to_bob);
  otrng_assert(!to_display);

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrng_client_receive(&bobs_auth_i, &to_display, from_alice_to_bob,
                                ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(ignore);
  otrng_assert(bobs_auth_i);
  otrng_assert(!to_display);

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Alice receives auth-i message (from Bob)
  ignore = otrng_client_receive(&from_alice_to_bob, &to_display, bobs_auth_i,
                                BOB_IDENTITY, alice);
  free(bobs_auth_i);
  bobs_auth_i = NULL;

  otrng_assert(!from_alice_to_bob);
  otrng_assert(ignore);
  otrng_assert(!to_display);

  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Alice sends a disconnected to Bob
  int err = otrng_client_disconnect(&from_alice_to_bob, BOB_IDENTITY, alice);
  otrng_assert(!err);
  otrng_assert(from_alice_to_bob);

  // We've deleted the conversation
  otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                              BOB_IDENTITY, alice));

  // Bob receives the disconnected from Alice
  ignore = otrng_client_receive(&from_bob, &to_display, from_alice_to_bob,
                                ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(ignore);
  otrng_assert(!from_bob);
  otrng_assert(!to_display);

  // Free memory
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_client_free_all(alice, bob);
}

void test_invalid_auth_r_msg_in_not_waiting_auth_r() {
  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_state_s *bob_client_state = otrng_client_state_new("bob");

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_client_s *bob = set_up_client(bob_client_state, BOB_IDENTITY, 2);

  // Alice sends a query message to Bob
  char *query_msg_to_bob =
      otrng_client_query_message(BOB_IDENTITY, "Hi bob", alice);

  int ignore = 0;
  char *to_display = NULL, *bobs_id = NULL, *alices_auth_r = NULL,
       *bobs_auth_i = NULL, *bob_last = NULL, *alice_last = NULL,
       *ignore_msg = NULL;

  // Bob receives query message, sends identity msg
  ignore = otrng_client_receive(&bobs_id, &to_display, query_msg_to_bob,
                                ALICE_IDENTITY, bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  otrng_assert(ignore);
  otrng_assert(bobs_id);
  otrng_assert(!to_display);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_IDENTITY, alice);
  otrng_conversation_s *bob_to_alice =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, ALICE_IDENTITY, bob);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_START);
  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  // Alice receives identity message, sends Auth-R msg
  // Do not free bob identity message
  ignore = otrng_client_receive(&alices_auth_r, &to_display, bobs_id,
                                BOB_IDENTITY, alice);
  otrng_assert(ignore);
  otrng_assert(alices_auth_r);
  otrng_assert(!to_display);
  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_I);

  free(bobs_id);
  bobs_id = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrng_client_receive(&bobs_auth_i, &to_display, alices_auth_r,
                                ALICE_IDENTITY, bob);
  otrng_assert(ignore);
  otrng_assert(bobs_auth_i);
  otrng_assert(!to_display);

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Bob receives again Auth-R message, ignores
  ignore = otrng_client_receive(&ignore_msg, &to_display, alices_auth_r,
                                ALICE_IDENTITY, bob);
  free(alices_auth_r);
  alices_auth_r = NULL;

  otrng_assert(ignore);
  otrng_assert(!ignore_msg);
  otrng_assert(!to_display);

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Alice receives Auth-I message
  ignore = otrng_client_receive(&alice_last, &to_display, bobs_auth_i,
                                BOB_IDENTITY, alice);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  otrng_assert(ignore);
  otrng_assert(!alice_last);
  otrng_assert(!to_display);

  free(bobs_auth_i);
  bobs_auth_i = NULL;

  free(alice_last);
  alice_last = NULL;

  // Alice sends a disconnected to Bob
  int error = otrng_client_disconnect(&alice_last, BOB_IDENTITY, alice);
  otrng_assert(!error);
  otrng_assert(alice_last);

  // We've deleted the conversation
  otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                              BOB_IDENTITY, alice));

  // Bob receives the disconnected from Alice
  ignore = otrng_client_receive(&bob_last, &to_display, alice_last,
                                ALICE_IDENTITY, bob);
  free(alice_last);
  alice_last = NULL;

  otrng_assert(ignore);
  otrng_assert(!bob_last);
  otrng_assert(!to_display);

  free(bob_last);
  bob_last = NULL;

  // Free memory
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_client_free_all(alice, bob);
}

void test_valid_identity_msg_in_waiting_auth_r() {
  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_state_s *bob_client_state = otrng_client_state_new("bob");

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_client_s *bob = set_up_client(bob_client_state, BOB_IDENTITY, 2);

  // Alice sends a query message to Bob
  char *query_msg_to_bob =
      otrng_client_query_message(BOB_IDENTITY, "Hi alice", alice);

  // Bob sends a query message to Alice
  char *query_msg_to_alice =
      otrng_client_query_message(ALICE_IDENTITY, "Hi bob", bob);

  int ignore = 0;
  char *to_display = NULL, *alices_id = NULL, *bobs_id = NULL,
       *alices_auth_r = NULL, *bobs_auth_r = NULL, *alices_auth_i = NULL,
       *bobs_auth_i = NULL, *bob_last = NULL, *alice_last = NULL;

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_IDENTITY, alice);
  otrng_conversation_s *bob_to_alice =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, ALICE_IDENTITY, bob);

  // Alice receives query message, sends identity message
  ignore = otrng_client_receive(&alices_id, &to_display, query_msg_to_alice,
                                BOB_IDENTITY, alice);

  g_assert_cmpstr(bob_to_alice->conn->sending_init_msg, ==,
                  alice_to_bob->conn->receiving_init_msg);
  g_assert_cmpstr(bob_to_alice->conn->sending_init_msg, ==, "?OTRv4? Hi bob");
  g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==, "?OTRv4? Hi alice");
  otrng_assert(bob_to_alice->conn->receiving_init_msg == NULL);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  otrng_assert(ignore);
  otrng_assert(alices_id);
  otrng_assert(!to_display);

  free(query_msg_to_alice);
  query_msg_to_alice = NULL;

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_R);
  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_START);

  // Bob receives query message, sends identity message
  ignore = otrng_client_receive(&bobs_id, &to_display, query_msg_to_bob,
                                ALICE_IDENTITY, bob);

  g_assert_cmpstr(bob_to_alice->conn->sending_init_msg, ==,
                  alice_to_bob->conn->receiving_init_msg);
  g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==,
                  bob_to_alice->conn->receiving_init_msg);
  g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==, "?OTRv4? Hi alice");
  g_assert_cmpstr(bob_to_alice->conn->sending_init_msg, ==, "?OTRv4? Hi bob");

  otrng_assert(ignore);
  otrng_assert(bobs_id);
  otrng_assert(!to_display);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_R);
  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  // Alice receives identity message. At this point, she can either:
  // 1. ignore and resend her identity message
  // 2. send an Auth-R message
  ignore = otrng_client_receive(&alices_auth_r, &to_display, bobs_id,
                                BOB_IDENTITY, alice);

  // 2. Alice sends and Auth-R message
  if (alices_auth_r) {
    free(alices_id);
    alices_id = NULL;

    free(bobs_id);
    bobs_id = NULL;

    otrng_assert(ignore);
    otrng_assert(!to_display);

    // Bob receives and Auth-R message. He sends and Auth-I message.
    ignore = otrng_client_receive(&bobs_auth_i, &to_display, alices_auth_r,
                                  ALICE_IDENTITY, bob);
    free(alices_auth_r);
    alices_auth_r = NULL;

    otrng_assert(bobs_auth_i);
    otrng_assert(ignore);
    otrng_assert(!to_display);

    // Alice receives Auth-I message
    ignore = otrng_client_receive(&alice_last, &to_display, bobs_auth_i,
                                  BOB_IDENTITY, alice);
    free(bobs_auth_i);
    bobs_auth_i = NULL;

    otrng_assert(!alice_last);
    otrng_assert(ignore);
    otrng_assert(!to_display);

    g_assert_cmpstr(bob_to_alice->conn->sending_init_msg, ==,
                    alice_to_bob->conn->receiving_init_msg);
    g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==,
                    bob_to_alice->conn->receiving_init_msg);
    g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==,
                    "?OTRv4? Hi alice");
    g_assert_cmpstr(bob_to_alice->conn->sending_init_msg, ==, "?OTRv4? Hi bob");

    // Alice sends a disconnected to Bob
    int error = otrng_client_disconnect(&alice_last, BOB_IDENTITY, alice);
    otrng_assert(!error);
    otrng_assert(alice_last);

    // We've deleted the conversation
    otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                                BOB_IDENTITY, alice));

    // Bob receives the disconnected from Alice
    ignore = otrng_client_receive(&bob_last, &to_display, alice_last,
                                  ALICE_IDENTITY, bob);
    free(alice_last);
    alice_last = NULL;

    otrng_assert(ignore);
    otrng_assert(!bob_last);
    otrng_assert(!to_display);

  } else {
    // 1. Alice ignores and resends her identity message
    otrng_assert(ignore);
    otrng_assert(!alices_auth_r);
    otrng_assert(!to_display);

    free(bobs_id);
    bobs_id = NULL;

    // Bob receives an identity message on state
    // OTRNG_WAITING_FOR_AUTH-R. He is now the lower side
    ignore = otrng_client_receive(&bobs_auth_r, &to_display, alices_id,
                                  ALICE_IDENTITY, bob);
    free(alices_id);
    alices_id = NULL;

    otrng_assert(bobs_auth_r);
    otrng_assert(ignore);
    otrng_assert(!to_display);

    // Alice receives Auth-R, sends Auth-I
    ignore = otrng_client_receive(&alices_auth_i, &to_display, bobs_auth_r,
                                  BOB_IDENTITY, alice);
    free(bobs_auth_r);
    bobs_auth_r = NULL;

    otrng_assert(ignore);
    otrng_assert(alices_auth_i);
    otrng_assert(!to_display);

    // Bob receives Auth-I message
    ignore = otrng_client_receive(&bob_last, &to_display, alices_auth_i,
                                  ALICE_IDENTITY, bob);
    free(alices_auth_i);
    alices_auth_i = NULL;

    otrng_assert(!bob_last);
    otrng_assert(ignore);
    otrng_assert(!to_display);

    otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

    g_assert_cmpstr(bob_to_alice->conn->sending_init_msg, ==,
                    alice_to_bob->conn->receiving_init_msg);
    g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==,
                    bob_to_alice->conn->receiving_init_msg);
    g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==,
                    "?OTRv4? Hi alice");
    g_assert_cmpstr(bob_to_alice->conn->sending_init_msg, ==, "?OTRv4? Hi bob");

    // Bob sends a disconnected to Alice
    int error = otrng_client_disconnect(&bob_last, ALICE_IDENTITY, bob);
    otrng_assert(!error);
    otrng_assert(bob_last);

    // We've deleted the conversation
    otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                                ALICE_IDENTITY, bob));

    otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

    // Alice receives the disconnected from Bob
    ignore = otrng_client_receive(&alice_last, &to_display, bob_last,
                                  BOB_IDENTITY, alice);

    otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_FINISHED);

    free(bob_last);
    bob_last = NULL;

    otrng_assert(ignore);
    otrng_assert(!alice_last);
    otrng_assert(!to_display);
  }
  // Free memory
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_client_free_all(alice, bob);
}

void test_invalid_auth_i_msg_in_not_waiting_auth_i() {
  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_state_s *bob_client_state = otrng_client_state_new("bob");

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_client_s *bob = set_up_client(bob_client_state, BOB_IDENTITY, 2);

  // Alice sends a query message to Bob
  char *query_msg_to_bob =
      otrng_client_query_message(BOB_IDENTITY, "Hi bob", alice);

  int ignore = 0;
  char *to_display = NULL, *bobs_id = NULL, *alices_auth_r = NULL,
       *bobs_auth_i = NULL, *bob_last = NULL, *alice_last = NULL;

  // Bob receives query message, sends identity message
  ignore = otrng_client_receive(&bobs_id, &to_display, query_msg_to_bob,
                                ALICE_IDENTITY, bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  otrng_assert(ignore);
  otrng_assert(bobs_id);
  otrng_assert(!to_display);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_IDENTITY, alice);
  otrng_conversation_s *bob_to_alice =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, ALICE_IDENTITY, bob);

  g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==,
                  bob_to_alice->conn->receiving_init_msg);
  g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==, "?OTRv4? Hi bob");
  otrng_assert(bob_to_alice->conn->sending_init_msg == NULL);
  otrng_assert(alice_to_bob->conn->receiving_init_msg == NULL);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_START);
  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  // Alice receives identity message, sends Auth-R msg
  ignore = otrng_client_receive(&alices_auth_r, &to_display, bobs_id,
                                BOB_IDENTITY, alice);

  free(bobs_id);
  bobs_id = NULL;

  otrng_assert(ignore);
  otrng_assert(alices_auth_r);
  otrng_assert(!to_display);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_I);

  // Bob receives Auth-R message, sends Auth-I message
  ignore = otrng_client_receive(&bobs_auth_i, &to_display, alices_auth_r,
                                ALICE_IDENTITY, bob);
  free(alices_auth_r);
  alices_auth_r = NULL;

  otrng_assert(ignore);
  otrng_assert(bobs_auth_i);
  otrng_assert(!to_display);

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Alice receives Auth-I message
  ignore = otrng_client_receive(&alice_last, &to_display, bobs_auth_i,
                                BOB_IDENTITY, alice);

  g_assert_cmpstr(alice_to_bob->conn->sending_init_msg, ==,
                  bob_to_alice->conn->receiving_init_msg);

  otrng_assert(ignore);
  otrng_assert(!alice_last);
  otrng_assert(!to_display);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Alice receives Auth-I message again
  ignore = otrng_client_receive(&alice_last, &to_display, bobs_auth_i,
                                BOB_IDENTITY, alice);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  otrng_assert(ignore);
  otrng_assert(!alice_last);
  otrng_assert(!to_display);

  free(bobs_auth_i);
  bobs_auth_i = NULL;

  free(alice_last);
  alice_last = NULL;

  // Alice sends a disconnected to Bob
  int error = otrng_client_disconnect(&alice_last, BOB_IDENTITY, alice);
  otrng_assert(!error);
  otrng_assert(alice_last);

  // We've deleted the conversation
  otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                              BOB_IDENTITY, alice));

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Bob receives the disconnected from Alice
  ignore = otrng_client_receive(&bob_last, &to_display, alice_last,
                                ALICE_IDENTITY, bob);
  free(alice_last);
  alice_last = NULL;

  otrng_assert(ignore);
  otrng_assert(!bob_last);
  otrng_assert(!to_display);

  free(bob_last);
  bob_last = NULL;

  // Free memory
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_client_free_all(alice, bob);
}

void test_client_receives_fragmented_message(void) {
  char *msg = "Receiving fragmented plaintext";

  otrng_message_to_send_s *fmsg = malloc(sizeof(otrng_message_to_send_s));
  otrng_assert_is_success(otrng_fragment_message(60, fmsg, 0, 0, msg));

  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);

  char *tosend = NULL, *to_display = NULL;

  for (int i = 0; i < fmsg->total; i++) {
    otrng_client_receive(&tosend, &to_display, fmsg->pieces[i], BOB_IDENTITY,
                         alice);
    otrng_assert(!tosend);
  }

  g_assert_cmpstr(to_display, ==, "Receiving fragmented plaintext");

  free(to_display);
  to_display = NULL;

  otrng_message_free(fmsg);
  otrl_userstate_free(alice_client_state->user_state);
  otrng_client_state_free(alice_client_state);
  otrng_client_free(alice);
}

void test_client_expires_old_fragments(void) {
  char *msg = "Pending fragmented message";

  otrng_message_to_send_s *fmsg = malloc(sizeof(otrng_message_to_send_s));
  otrng_assert_is_success(otrng_fragment_message(60, fmsg, 0, 0, msg));

  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);

  char *tosend = NULL, *to_display = NULL;
  time_t expiration_time;

  expiration_time = time(NULL) - 3600;

  otrng_client_receive(&tosend, &to_display, fmsg->pieces[0], BOB_IDENTITY,
                       alice);

  otrng_conversation_s *conv =
      otrng_client_get_conversation(0, BOB_IDENTITY, alice);
  g_assert_cmpint(otrng_list_len(conv->conn->pending_fragments), ==, 1);

  otrng_client_expire_fragments(expiration_time, alice);

  g_assert_cmpint(otrng_list_len(conv->conn->pending_fragments), ==, 0);

  free(to_display);
  otrng_message_free(fmsg);
  otrl_userstate_free(alice_client_state->user_state);
  otrng_client_state_free(alice_client_state);
  otrng_client_free(alice);
}
void test_client_sends_fragmented_message(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new("alice");
  otrng_client_state_s *bob_client_state = otrng_client_state_new("bob");

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_client_s *bob = set_up_client(bob_client_state, BOB_IDENTITY, 2);

  char *query_msg_to_bob =
      otrng_client_query_message(BOB_IDENTITY, "Hi bob", alice);
  otrng_assert(query_msg_to_bob);

  char *from_alice_to_bob = NULL, *from_bob = NULL, *to_display = NULL;

  // Bob receives query message, sends identity msg
  otrng_client_receive(&from_bob, &to_display, query_msg_to_bob, ALICE_IDENTITY,
                       bob);
  free(query_msg_to_bob);
  query_msg_to_bob = NULL;

  // Alice receives identity message (from Bob), sends Auth-R message
  otrng_client_receive(&from_alice_to_bob, &to_display, from_bob, BOB_IDENTITY,
                       alice);
  free(from_bob);
  from_bob = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob,
                       ALICE_IDENTITY, bob);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice receives Auth-I message (from Bob)
  otrng_client_receive(&from_alice_to_bob, &to_display, from_bob, BOB_IDENTITY,
                       alice);
  free(from_alice_to_bob);
  from_alice_to_bob = NULL;
  free(from_bob);
  from_bob = NULL;

  otrng_message_to_send_s *to_send = otrng_message_new();
  char *message = "We should fragment when is needed";

  // Alice fragments the message
  otrng_client_send_fragment(&to_send, message, 100, BOB_IDENTITY, alice);

  for (int i = 0; i < to_send->total; i++) {
    // Bob receives the fragments
    otrng_client_receive(&from_bob, &to_display, to_send->pieces[i],
                         ALICE_IDENTITY, bob);
    otrng_assert(!from_bob);

    if (to_send->total - 1 == i)
      g_assert_cmpstr(to_display, ==, message);
  }

  free(from_bob);
  from_bob = NULL;

  free(to_display);
  to_display = NULL;

  otrng_message_free(to_send);
  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_client_free_all(alice, bob);
}
