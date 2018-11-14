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
#include <stdio.h>

#include "test_helpers.h"

#include "test_fixtures.h"

#include "client.h"
#include "fragment.h"
#include "instance_tag.h"
#include "messaging.h"
#include "serialize.h"
#include "shake.h"

static void test_client_conversation_api() {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);

  set_up_client(alice, ALICE_ACCOUNT, 1);
  otrng_assert(!alice->conversations);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_ACCOUNT, alice);
  otrng_conversation_s *alice_to_charlie = otrng_client_get_conversation(
      NOT_FORCE_CREATE_CONV, CHARLIE_ACCOUNT, alice);
  otrng_assert(!alice->conversations);
  otrng_assert(!alice_to_bob);
  otrng_assert(!alice_to_charlie);

  alice_to_bob =
      otrng_client_get_conversation(FORCE_CREATE_CONV, BOB_ACCOUNT, alice);
  alice_to_charlie =
      otrng_client_get_conversation(FORCE_CREATE_CONV, CHARLIE_ACCOUNT, alice);
  otrng_assert(alice_to_bob);
  otrng_assert(alice_to_bob->conn);
  otrng_assert(alice_to_charlie);
  otrng_assert(alice_to_charlie->conn);

  alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_ACCOUNT, alice);
  alice_to_charlie = otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                                   CHARLIE_ACCOUNT, alice);
  otrng_assert(alice_to_bob);
  otrng_assert(alice_to_bob->conn);
  otrng_assert(alice_to_charlie);
  otrng_assert(alice_to_charlie->conn);

  /* Free memory */
  otrng_global_state_free(alice->global_state);
  otrng_client_free(alice);
}

static void test_client_api() {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob = otrng_client_new(BOB_IDENTITY);
  otrng_client_s *charlie = otrng_client_new(CHARLIE_IDENTITY);

  set_up_client(alice, ALICE_ACCOUNT, 1);
  set_up_client(bob, BOB_ACCOUNT, 2);
  set_up_client(charlie, CHARLIE_ACCOUNT, 3);

  char *query_message_to_bob =
      otrng_client_query_message(BOB_ACCOUNT, "Hi bob", alice);
  otrng_assert(query_message_to_bob);

  char *query_message_to_charlie =
      otrng_client_query_message(CHARLIE_ACCOUNT, "Hi charlie", alice);
  otrng_assert(query_message_to_charlie);

  otrng_bool ignore = otrng_false;
  char *from_alice_to_bob = NULL, *from_alice_to_charlie = NULL,
       *from_bob = NULL, *from_charlie = NULL, *to_display = NULL;

  // Bob receives query message, sends the identity message
  otrng_client_receive(&from_bob, &to_display, query_message_to_bob,
                       ALICE_ACCOUNT, bob, &ignore);
  otrng_free(query_message_to_bob);
  query_message_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(!to_display);

  // Charlie receives query message, sends identity message
  otrng_client_receive(&from_charlie, &to_display, query_message_to_charlie,
                       ALICE_ACCOUNT, charlie, &ignore);
  otrng_free(query_message_to_charlie);
  query_message_to_charlie = NULL;

  otrng_assert(!ignore);
  otrng_assert(!to_display);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_ACCOUNT, alice);
  otrng_conversation_s *alice_to_charlie = otrng_client_get_conversation(
      NOT_FORCE_CREATE_CONV, CHARLIE_ACCOUNT, alice);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_START);
  otrng_assert(alice_to_charlie->conn->state == OTRNG_STATE_START);

  // Alice receives identity message (from Bob), sends Auth-R message
  otrng_client_receive(&from_alice_to_bob, &to_display, from_bob, BOB_ACCOUNT,
                       alice, &ignore);
  otrng_free(from_bob);
  from_bob = NULL;

  otrng_assert(from_alice_to_bob);
  otrng_assert(!ignore);
  otrng_assert(!to_display);

  // Alice receives identity message (from Charlie), sends Auth-R message
  otrng_client_receive(&from_alice_to_charlie, &to_display, from_charlie,
                       CHARLIE_ACCOUNT, alice, &ignore);
  otrng_free(from_charlie);
  from_charlie = NULL;

  otrng_assert(!ignore);
  otrng_assert(!to_display);

  // Bob receives Auth-R message, sends Auth-I message
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(from_bob);
  otrng_assert(!to_display);

  // Charlie receives Auth-R message, sends Auth-I message
  otrng_client_receive(&from_charlie, &to_display, from_alice_to_charlie,
                       ALICE_ACCOUNT, charlie, &ignore);
  otrng_free(from_alice_to_charlie);
  from_alice_to_charlie = NULL;

  otrng_assert(!ignore);
  otrng_assert(from_charlie);
  otrng_assert(!to_display);

  // Alice receives Auth-I message (from Bob), sends initial data message
  otrng_client_receive(&from_alice_to_bob, &to_display, from_bob, BOB_ACCOUNT,
                       alice, &ignore);
  otrng_free(from_bob);
  from_bob = NULL;

  otrng_assert(from_alice_to_bob);
  otrng_assert(!ignore);
  otrng_assert(!to_display);

  // Bob receives initial data message.
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!from_bob);
  otrng_assert(!ignore);
  otrng_assert(!to_display);

  // Alice receives Auth-I message (from Charlie), sends initial data message
  otrng_client_receive(&from_alice_to_charlie, &to_display, from_charlie,
                       CHARLIE_ACCOUNT, alice, &ignore);
  otrng_free(from_charlie);
  from_charlie = NULL;

  otrng_assert(from_alice_to_charlie);
  otrng_assert(!ignore);
  otrng_assert(!to_display);

  // Charlie receives initial data message.
  otrng_client_receive(&from_charlie, &to_display, from_alice_to_charlie,
                       ALICE_ACCOUNT, charlie, &ignore);
  otrng_free(from_alice_to_charlie);
  from_alice_to_charlie = NULL;

  otrng_assert(!from_charlie);
  otrng_assert(!ignore);
  otrng_assert(!to_display);

  // Alice sends a disconnected to Bob
  otrng_result err =
      otrng_client_disconnect(&from_alice_to_bob, BOB_ACCOUNT, alice);
  otrng_assert_is_success(err);
  otrng_assert(from_alice_to_bob);

  // We've deleted the conversation
  otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                              BOB_ACCOUNT, alice));

  // TODO: @client Should we keep the conversation and set state to start
  // instead? g_assert_cmpint(alice_to_bob->conn->state, ==, OTRNG_STATE_START);

  // Bob receives the disconnected from Alice
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(!from_bob);
  otrng_assert(!to_display);

  // Free memory
  otrng_global_state_free(alice->global_state);
  otrng_global_state_free(bob->global_state);
  otrng_global_state_free(charlie->global_state);
  otrng_client_free_all(alice, bob, charlie);
}

static void test_conversation_with_multiple_locations() {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob = otrng_client_new(BOB_IDENTITY);

  set_up_client(alice, ALICE_ACCOUNT, 1);
  set_up_client(bob, BOB_ACCOUNT, 2);

  // Alice sends a query message
  char *query_message =
      otrng_client_query_message(BOB_ACCOUNT, "Hi bob", alice);

  otrng_bool ignore = otrng_false;
  char *from_alice_to_bob = NULL, *from_bob = NULL, *to_display = NULL;

  // Bob receives query message, sends identity message
  otrng_client_receive(&from_bob, &to_display, query_message, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(query_message);

  // Alice receives identity message (from Bob), sends Auth-R message
  otrng_client_receive(&from_alice_to_bob, &to_display, from_bob, BOB_ACCOUNT,
                       alice, &ignore);
  otrng_free(from_bob);
  from_bob = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice receives Auth-I message (from Bob), sends initial data message
  otrng_client_receive(&from_alice_to_bob, &to_display, from_bob, BOB_ACCOUNT,
                       alice, &ignore);
  otrng_free(from_bob);
  from_bob = NULL;

  // Bob receives the message.
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Alice sends a message with original instance tag
  const char *message = "hello";
  otrng_client_send(&from_alice_to_bob, message, BOB_ACCOUNT, alice);

  // Bob receives the message.
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(!from_bob);
  otrng_assert(to_display);

  otrng_free(to_display);
  to_display = NULL;

  // Alice sends a message with a different instance tag
  otrng_conversation_s *conv =
      otrng_client_get_conversation(0, BOB_ACCOUNT, alice);
  conv->conn->their_instance_tag = conv->conn->their_instance_tag + 1;
  otrng_client_send(&from_alice_to_bob, "hello again", BOB_ACCOUNT, alice);

  // Bob receives and ignores the message.
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(!to_display);

  // Free the ignored reply
  otrng_free(from_bob);
  from_bob = NULL;

  // Bob sends a disconnected to Alice
  otrng_client_disconnect(&from_bob, ALICE_ACCOUNT, bob);

  // Alice receives the disconnected from Alice
  otrng_client_receive(&from_alice_to_bob, &to_display, from_bob, BOB_ACCOUNT,
                       alice, &ignore);
  otrng_free(from_bob);
  from_bob = NULL;

  // Free the ignored reply
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  // Free memory
  otrng_global_state_free(alice->global_state);
  otrng_global_state_free(bob->global_state);
  otrng_client_free_all(alice, bob);
}

static void test_valid_identity_message_in_waiting_auth_i() {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob = otrng_client_new(BOB_IDENTITY);

  set_up_client(alice, ALICE_ACCOUNT, 1);
  set_up_client(bob, BOB_ACCOUNT, 2);

  char *query_message_to_bob =
      otrng_client_query_message(BOB_ACCOUNT, "Hi bob", alice);

  otrng_bool ignore = otrng_false;
  char *from_alice_to_bob = NULL, *to_display = NULL, *bobs_id = NULL,
       *bobs_auth_i = NULL, *from_bob = NULL;

  // Bob receives query message, sends identity message
  // Do not free bob identity message
  // Do not free alice query message
  otrng_client_receive(&bobs_id, &to_display, query_message_to_bob,
                       ALICE_ACCOUNT, bob, &ignore);
  otrng_assert(!ignore);
  otrng_assert(!to_display);

  otrng_conversation_s *bob_to_alice =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, ALICE_ACCOUNT, bob);

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  // Alice receives identity message (from Bob), sends Auth-R message
  otrng_client_receive(&from_alice_to_bob, &to_display, bobs_id, BOB_ACCOUNT,
                       alice, &ignore);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_ACCOUNT, alice);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_I);
  otrng_assert(from_alice_to_bob);
  otrng_assert(!ignore);
  otrng_assert(!to_display);

  ec_point stored_their_ecdh;
  otrng_ec_point_copy(stored_their_ecdh, alice_to_bob->conn->keys->their_ecdh);

  dh_public_key stored_their_dh;
  stored_their_dh = otrng_dh_mpi_copy(alice_to_bob->conn->keys->their_dh);

  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_free(bobs_id);
  bobs_id = NULL;

  // Bob generates an identity message again
  otrng_client_receive(&bobs_id, &to_display, query_message_to_bob,
                       ALICE_ACCOUNT, bob, &ignore);
  otrng_free(query_message_to_bob);
  query_message_to_bob = NULL;

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  // Alice receives identity message (from Bob) again, sends Auth-R message
  otrng_client_receive(&from_alice_to_bob, &to_display, bobs_id, BOB_ACCOUNT,
                       alice, &ignore);
  otrng_free(bobs_id);
  bobs_id = NULL;

  ec_point new_their_ecdh;
  otrng_ec_point_copy(new_their_ecdh, alice_to_bob->conn->keys->their_ecdh);

  dh_public_key new_their_dh;
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

  otrng_assert(!ignore);
  otrng_assert(from_alice_to_bob);
  otrng_assert(!to_display);

  // Bob receives Auth-R message, sends Auth-I message
  otrng_client_receive(&bobs_auth_i, &to_display, from_alice_to_bob,
                       ALICE_ACCOUNT, bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(bobs_auth_i);
  otrng_assert(!to_display);

  otrng_assert(bob_to_alice->conn->state ==
               OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE);

  // Alice receives auth-i message (from Bob)
  otrng_client_receive(&from_alice_to_bob, &to_display, bobs_auth_i,
                       BOB_ACCOUNT, alice, &ignore);
  otrng_free(bobs_auth_i);
  bobs_auth_i = NULL;

  otrng_assert(from_alice_to_bob);
  otrng_assert_cmpmem("?OTR:AAQD", from_alice_to_bob, 9);
  otrng_assert(!ignore);
  otrng_assert(!to_display);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Bob receives the initial data message
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(!from_bob);
  otrng_assert(!to_display);

  // Alice sends a disconnected to Bob
  otrng_result err =
      otrng_client_disconnect(&from_alice_to_bob, BOB_ACCOUNT, alice);
  otrng_assert_is_success(err);
  otrng_assert(from_alice_to_bob);

  // We've deleted the conversation
  otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                              BOB_ACCOUNT, alice));

  // Bob receives the disconnected from Alice
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(!from_bob);
  otrng_assert(!to_display);

  // Free memory
  otrng_global_state_free(alice->global_state);
  otrng_global_state_free(bob->global_state);
  otrng_client_free_all(alice, bob);
}

static void test_invalid_auth_r_message_in_not_waiting_auth_r() {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob = otrng_client_new(BOB_IDENTITY);

  set_up_client(alice, ALICE_ACCOUNT, 1);
  set_up_client(bob, BOB_ACCOUNT, 2);

  // Alice sends a query message to Bob
  char *query_message_to_bob =
      otrng_client_query_message(BOB_ACCOUNT, "Hi bob", alice);

  otrng_bool ignore = otrng_false;
  char *to_display = NULL, *bobs_id = NULL, *alices_auth_r = NULL,
       *bobs_auth_i = NULL, *bob_last = NULL, *alice_last = NULL,
       *ignore_message = NULL;

  // Bob receives query message, sends identity message
  otrng_client_receive(&bobs_id, &to_display, query_message_to_bob,
                       ALICE_ACCOUNT, bob, &ignore);
  otrng_free(query_message_to_bob);
  query_message_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(bobs_id);
  otrng_assert(!to_display);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_ACCOUNT, alice);
  otrng_conversation_s *bob_to_alice =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, ALICE_ACCOUNT, bob);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_START);
  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  // Alice receives identity message, sends Auth-R message
  // Do not free bob identity message
  otrng_client_receive(&alices_auth_r, &to_display, bobs_id, BOB_ACCOUNT, alice,
                       &ignore);
  otrng_assert(!ignore);
  otrng_assert(alices_auth_r);
  otrng_assert(!to_display);
  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_I);

  otrng_free(bobs_id);
  bobs_id = NULL;

  // Bob receives Auth-R message, sends Auth-I message
  otrng_client_receive(&bobs_auth_i, &to_display, alices_auth_r, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_assert(!ignore);
  otrng_assert(bobs_auth_i);
  otrng_assert(!to_display);

  otrng_assert(bob_to_alice->conn->state ==
               OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE);

  // Bob receives again Auth-R message, ignores
  otrng_client_receive(&ignore_message, &to_display, alices_auth_r,
                       ALICE_ACCOUNT, bob, &ignore);
  otrng_free(alices_auth_r);
  alices_auth_r = NULL;

  otrng_assert(!ignore);
  otrng_assert(!ignore_message);
  otrng_assert(!to_display);

  otrng_assert(bob_to_alice->conn->state ==
               OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE);

  // Alice receives Auth-I message, sends initial data message
  otrng_client_receive(&alice_last, &to_display, bobs_auth_i, BOB_ACCOUNT,
                       alice, &ignore);
  otrng_free(bobs_auth_i);
  bobs_auth_i = NULL;

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  otrng_assert(!ignore);
  otrng_assert(alice_last);
  otrng_assert(!to_display);

  // Bob receives the initial data message
  otrng_client_receive(&bob_last, &to_display, alice_last, ALICE_ACCOUNT, bob,
                       &ignore);
  otrng_free(alice_last);
  alice_last = NULL;

  otrng_assert(!ignore);
  otrng_assert(!bob_last);
  otrng_assert(!to_display);

  // Alice sends a disconnected to Bob
  otrng_result error = otrng_client_disconnect(&alice_last, BOB_ACCOUNT, alice);
  otrng_assert_is_success(error);
  otrng_assert(alice_last);

  // We've deleted the conversation
  otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                              BOB_ACCOUNT, alice));

  // Bob receives the disconnected from Alice
  otrng_client_receive(&bob_last, &to_display, alice_last, ALICE_ACCOUNT, bob,
                       &ignore);
  otrng_free(alice_last);
  alice_last = NULL;

  otrng_assert(!ignore);
  otrng_assert(!bob_last);
  otrng_assert(!to_display);

  otrng_free(bob_last);
  bob_last = NULL;

  // Free memory
  otrng_global_state_free(alice->global_state);
  otrng_global_state_free(bob->global_state);
  otrng_client_free_all(alice, bob);
}

static void test_valid_identity_message_in_waiting_auth_r() {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob = otrng_client_new(BOB_IDENTITY);

  set_up_client(alice, ALICE_ACCOUNT, 1);
  set_up_client(bob, BOB_ACCOUNT, 2);

  // Alice sends a query message to Bob
  char *query_message_to_bob =
      otrng_client_query_message(BOB_ACCOUNT, "Hi alice", alice);

  // Bob sends a query message to Alice
  char *query_message_to_alice =
      otrng_client_query_message(ALICE_ACCOUNT, "Hi bob", bob);

  otrng_bool ignore = otrng_false;
  char *to_display = NULL, *alices_id = NULL, *bobs_id = NULL,
       *alices_auth_r = NULL, *bobs_auth_r = NULL, *alices_auth_i = NULL,
       *bobs_auth_i = NULL, *bob_last = NULL, *alice_last = NULL;

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_ACCOUNT, alice);
  otrng_conversation_s *bob_to_alice =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, ALICE_ACCOUNT, bob);

  // Alice receives query message, sends identity message
  otrng_client_receive(&alices_id, &to_display, query_message_to_alice,
                       BOB_ACCOUNT, alice, &ignore);

  g_assert_cmpstr(bob_to_alice->conn->sending_init_message, ==,
                  alice_to_bob->conn->receiving_init_message);
  g_assert_cmpstr(bob_to_alice->conn->sending_init_message, ==,
                  "?OTRv43? Hi bob");
  g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                  "?OTRv43? Hi alice");
  otrng_assert(bob_to_alice->conn->receiving_init_message == NULL);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  otrng_assert(!ignore);
  otrng_assert(alices_id);
  otrng_assert(!to_display);

  otrng_free(query_message_to_alice);
  query_message_to_alice = NULL;

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_R);
  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_START);

  // Bob receives query message, sends identity message
  otrng_client_receive(&bobs_id, &to_display, query_message_to_bob,
                       ALICE_ACCOUNT, bob, &ignore);

  g_assert_cmpstr(bob_to_alice->conn->sending_init_message, ==,
                  alice_to_bob->conn->receiving_init_message);
  g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                  bob_to_alice->conn->receiving_init_message);
  g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                  "?OTRv43? Hi alice");
  g_assert_cmpstr(bob_to_alice->conn->sending_init_message, ==,
                  "?OTRv43? Hi bob");

  otrng_assert(!ignore);
  otrng_assert(bobs_id);
  otrng_assert(!to_display);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_R);
  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  otrng_free(query_message_to_bob);
  query_message_to_bob = NULL;

  // Alice receives identity message. At this point, she can either:
  // 1. ignore and resend her identity message
  // 2. send an Auth-R message
  otrng_client_receive(&alices_auth_r, &to_display, bobs_id, BOB_ACCOUNT, alice,
                       &ignore);

  // 2. Alice sends and Auth-R message
  if (alices_auth_r) {
    otrng_free(alices_id);
    alices_id = NULL;

    otrng_free(bobs_id);
    bobs_id = NULL;

    otrng_assert(!ignore);
    otrng_assert(!to_display);

    // Bob receives and Auth-R message. He sends and Auth-I message.
    otrng_client_receive(&bobs_auth_i, &to_display, alices_auth_r,
                         ALICE_ACCOUNT, bob, &ignore);
    otrng_free(alices_auth_r);
    alices_auth_r = NULL;

    otrng_assert(bobs_auth_i);
    otrng_assert(!ignore);
    otrng_assert(!to_display);

    // Alice receives Auth-I message, sends initial data message
    otrng_client_receive(&alice_last, &to_display, bobs_auth_i, BOB_ACCOUNT,
                         alice, &ignore);
    otrng_free(bobs_auth_i);
    bobs_auth_i = NULL;

    g_assert_cmpstr(bob_to_alice->conn->sending_init_message, ==,
                    alice_to_bob->conn->receiving_init_message);
    g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                    bob_to_alice->conn->receiving_init_message);
    g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                    "?OTRv43? Hi alice");
    g_assert_cmpstr(bob_to_alice->conn->sending_init_message, ==,
                    "?OTRv43? Hi bob");

    // Bob receives initial data message
    otrng_client_receive(&bob_last, &to_display, alice_last, ALICE_ACCOUNT, bob,
                         &ignore);
    otrng_free(alice_last);
    alice_last = NULL;

    otrng_assert(!ignore);
    otrng_assert(!bob_last);
    otrng_assert(!to_display);

    // Alice sends a disconnected to Bob
    otrng_result error =
        otrng_client_disconnect(&alice_last, BOB_ACCOUNT, alice);
    otrng_assert_is_success(error);
    otrng_assert(alice_last);

    // We've deleted the conversation
    otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                                BOB_ACCOUNT, alice));

    // Bob receives the disconnected from Alice
    otrng_client_receive(&bob_last, &to_display, alice_last, ALICE_ACCOUNT, bob,
                         &ignore);
    otrng_free(alice_last);
    alice_last = NULL;

    otrng_assert(!ignore);
    otrng_assert(!bob_last);
    otrng_assert(!to_display);

  } else {
    // 1. Alice ignores and resends her identity message
    otrng_assert(!ignore);
    otrng_assert(!alices_auth_r);
    otrng_assert(!to_display);

    otrng_free(bobs_id);
    bobs_id = NULL;

    // Bob receives an identity message on state
    // OTRNG_WAITING_FOR_AUTH-R. He is now the lower side
    otrng_client_receive(&bobs_auth_r, &to_display, alices_id, ALICE_ACCOUNT,
                         bob, &ignore);
    otrng_free(alices_id);
    alices_id = NULL;

    otrng_assert(bobs_auth_r);
    otrng_assert(!ignore);
    otrng_assert(!to_display);

    // Alice receives Auth-R, sends Auth-I
    otrng_client_receive(&alices_auth_i, &to_display, bobs_auth_r, BOB_ACCOUNT,
                         alice, &ignore);
    otrng_free(bobs_auth_r);
    bobs_auth_r = NULL;

    otrng_assert(!ignore);
    otrng_assert(alices_auth_i);
    otrng_assert(!to_display);

    // Bob receives Auth-I message, sends initial data message
    otrng_client_receive(&bob_last, &to_display, alices_auth_i, ALICE_ACCOUNT,
                         bob, &ignore);
    otrng_free(alices_auth_i);
    alices_auth_i = NULL;

    otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

    g_assert_cmpstr(bob_to_alice->conn->sending_init_message, ==,
                    alice_to_bob->conn->receiving_init_message);
    g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                    bob_to_alice->conn->receiving_init_message);
    g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                    "?OTRv43? Hi alice");
    g_assert_cmpstr(bob_to_alice->conn->sending_init_message, ==,
                    "?OTRv43? Hi bob");

    otrng_assert(!ignore);
    otrng_assert(bob_last);
    otrng_assert(!to_display);

    // Alice receives initial data message
    otrng_client_receive(&alice_last, &to_display, bob_last, BOB_ACCOUNT, alice,
                         &ignore);
    otrng_free(bob_last);
    bob_last = NULL;

    otrng_assert(!ignore);
    otrng_assert(!alice_last);
    otrng_assert(!to_display);

    // Bob sends a disconnected to Alice
    otrng_result error = otrng_client_disconnect(&bob_last, ALICE_ACCOUNT, bob);
    otrng_assert_is_success(error);
    otrng_assert(bob_last);

    // We've deleted the conversation
    otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                                ALICE_ACCOUNT, bob));

    otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

    // Alice receives the disconnected from Bob
    otrng_client_receive(&alice_last, &to_display, bob_last, BOB_ACCOUNT, alice,
                         &ignore);

    otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_FINISHED);

    otrng_free(bob_last);
    bob_last = NULL;

    otrng_assert(!ignore);
    otrng_assert(!alice_last);
    otrng_assert(!to_display);
  }
  // Free memory
  otrng_global_state_free(alice->global_state);
  otrng_global_state_free(bob->global_state);
  otrng_client_free_all(alice, bob);
}

static void test_invalid_auth_i_message_in_not_waiting_auth_i() {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob = otrng_client_new(BOB_IDENTITY);

  set_up_client(alice, ALICE_ACCOUNT, 1);
  set_up_client(bob, BOB_ACCOUNT, 2);

  // Alice sends a query message to Bob
  char *query_message_to_bob =
      otrng_client_query_message(BOB_ACCOUNT, "Hi bob", alice);

  otrng_bool ignore = otrng_false;
  char *to_display = NULL, *bobs_id = NULL, *alices_auth_r = NULL,
       *bobs_auth_i = NULL, *bob_last = NULL, *alice_last = NULL;

  // Bob receives query message, sends identity message
  otrng_client_receive(&bobs_id, &to_display, query_message_to_bob,
                       ALICE_ACCOUNT, bob, &ignore);
  otrng_free(query_message_to_bob);
  query_message_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(bobs_id);
  otrng_assert(!to_display);

  otrng_conversation_s *alice_to_bob =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, BOB_ACCOUNT, alice);
  otrng_conversation_s *bob_to_alice =
      otrng_client_get_conversation(NOT_FORCE_CREATE_CONV, ALICE_ACCOUNT, bob);

  g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                  bob_to_alice->conn->receiving_init_message);
  g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                  "?OTRv43? Hi bob");
  otrng_assert(bob_to_alice->conn->sending_init_message == NULL);
  otrng_assert(alice_to_bob->conn->receiving_init_message == NULL);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_START);
  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_WAITING_AUTH_R);

  // Alice receives identity message, sends Auth-R message
  otrng_client_receive(&alices_auth_r, &to_display, bobs_id, BOB_ACCOUNT, alice,
                       &ignore);

  otrng_free(bobs_id);
  bobs_id = NULL;

  otrng_assert(!ignore);
  otrng_assert(alices_auth_r);
  otrng_assert(!to_display);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_WAITING_AUTH_I);

  // Bob receives Auth-R message, sends Auth-I message
  otrng_client_receive(&bobs_auth_i, &to_display, alices_auth_r, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(alices_auth_r);
  alices_auth_r = NULL;

  otrng_assert(!ignore);
  otrng_assert(bobs_auth_i);
  otrng_assert(!to_display);

  otrng_assert(bob_to_alice->conn->state ==
               OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE);

  // Alice receives Auth-I message, sends initial data message
  otrng_client_receive(&alice_last, &to_display, bobs_auth_i, BOB_ACCOUNT,
                       alice, &ignore);

  g_assert_cmpstr(alice_to_bob->conn->sending_init_message, ==,
                  bob_to_alice->conn->receiving_init_message);

  otrng_assert(!ignore);
  otrng_assert(alice_last);
  otrng_assert(!to_display);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Bob receives the initial data message
  otrng_client_receive(&bob_last, &to_display, alice_last, ALICE_ACCOUNT, bob,
                       &ignore);
  otrng_free(alice_last);
  alice_last = NULL;

  otrng_assert(!ignore);
  otrng_assert(!bob_last);
  otrng_assert(!to_display);

  // Alice receives Auth-I message again
  otrng_client_receive(&alice_last, &to_display, bobs_auth_i, BOB_ACCOUNT,
                       alice, &ignore);

  otrng_assert(alice_to_bob->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  otrng_assert(!ignore);
  otrng_assert(!alice_last);
  otrng_assert(!to_display);

  otrng_free(bobs_auth_i);
  bobs_auth_i = NULL;

  // Alice sends a disconnected to Bob
  otrng_result error = otrng_client_disconnect(&alice_last, BOB_ACCOUNT, alice);
  otrng_assert_is_success(error);
  otrng_assert(alice_last);

  // We've deleted the conversation
  otrng_assert(!otrng_client_get_conversation(NOT_FORCE_CREATE_CONV,
                                              BOB_ACCOUNT, alice));

  otrng_assert(bob_to_alice->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES);

  // Bob receives the disconnected from Alice
  otrng_client_receive(&bob_last, &to_display, alice_last, ALICE_ACCOUNT, bob,
                       &ignore);
  otrng_free(alice_last);
  alice_last = NULL;

  otrng_assert(!ignore);
  otrng_assert(!bob_last);
  otrng_assert(!to_display);

  otrng_free(bob_last);
  bob_last = NULL;

  // Free memory
  otrng_global_state_free(alice->global_state);
  otrng_global_state_free(bob->global_state);
  otrng_client_free_all(alice, bob);
}

static void test_client_receives_fragmented_message(void) {
  const char *message = "Receiving fragmented plaintext";

  otrng_message_to_send_s *fmessage =
      otrng_xmalloc_z(sizeof(otrng_message_to_send_s));
  otrng_assert_is_success(otrng_fragment_message(60, fmessage, 0, 0, message));

  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  set_up_client(alice, ALICE_ACCOUNT, 1);

  char *to_send = NULL, *to_display = NULL;
  otrng_bool ignore = otrng_false;

  for (int i = 0; i < fmessage->total; i++) {
    otrng_client_receive(&to_send, &to_display, fmessage->pieces[i],
                         BOB_ACCOUNT, alice, &ignore);
    otrng_assert(!to_send);
  }

  g_assert_cmpstr(to_display, ==, "Receiving fragmented plaintext");

  otrng_free(to_display);
  to_display = NULL;

  otrng_message_free(fmessage);
  otrng_global_state_free(alice->global_state);
  otrng_client_free(alice);
}

static void test_client_expires_old_fragments(void) {
  const char *message = "Pending fragmented message";

  otrng_message_to_send_s *fmessage =
      otrng_xmalloc_z(sizeof(otrng_message_to_send_s));
  otrng_assert_is_success(otrng_fragment_message(60, fmessage, 0, 0, message));

  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  set_up_client(alice, ALICE_ACCOUNT, 1);

  char *to_send = NULL, *to_display = NULL;
  time_t expiration_time;
  otrng_bool ignore = otrng_false;

  expiration_time = time(NULL) - 3600;

  otrng_client_receive(&to_send, &to_display, fmessage->pieces[0], BOB_ACCOUNT,
                       alice, &ignore);

  otrng_conversation_s *conv =
      otrng_client_get_conversation(0, BOB_ACCOUNT, alice);
  g_assert_cmpint(otrng_list_len(conv->conn->pending_fragments), ==, 1);

  otrng_client_expire_fragments(expiration_time, alice);

  g_assert_cmpint(otrng_list_len(conv->conn->pending_fragments), ==, 0);

  otrng_free(to_display);
  otrng_message_free(fmessage);
  otrng_global_state_free(alice->global_state);
  otrng_client_free(alice);
}

static void test_client_sends_fragmented_message(void) {
  otrng_bool ignore = otrng_false;
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob = otrng_client_new(BOB_IDENTITY);

  set_up_client(alice, ALICE_ACCOUNT, 1);
  set_up_client(bob, BOB_ACCOUNT, 2);

  char *query_message_to_bob =
      otrng_client_query_message(BOB_ACCOUNT, "Hi bob", alice);
  otrng_assert(query_message_to_bob);

  char *from_alice_to_bob = NULL, *from_bob = NULL, *to_display = NULL;

  /* Bob receives query message, sends identity message */
  otrng_client_receive(&from_bob, &to_display, query_message_to_bob,
                       ALICE_ACCOUNT, bob, &ignore);
  otrng_free(query_message_to_bob);
  query_message_to_bob = NULL;

  /* Alice receives identity message (from Bob), sends Auth-R message */
  otrng_client_receive(&from_alice_to_bob, &to_display, from_bob, BOB_ACCOUNT,
                       alice, &ignore);
  otrng_free(from_bob);
  from_bob = NULL;

  /* Bob receives Auth-R message, sends Auth-I message */
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  /* Alice receives Auth-I message (from Bob) */
  otrng_client_receive(&from_alice_to_bob, &to_display, from_bob, BOB_ACCOUNT,
                       alice, &ignore);
  otrng_free(from_bob);
  from_bob = NULL;

  /* Bob receives the initial data message */
  otrng_client_receive(&from_bob, &to_display, from_alice_to_bob, ALICE_ACCOUNT,
                       bob, &ignore);
  otrng_free(from_alice_to_bob);
  from_alice_to_bob = NULL;

  otrng_assert(!ignore);
  otrng_assert(!from_bob);
  otrng_assert(!to_display);

  otrng_message_to_send_s *to_send = otrng_message_new();
  const char *message = "We should fragment when is needed";

  /* Alice fragments the message */
  otrng_client_send_fragment(&to_send, message, 100, BOB_ACCOUNT, alice);

  for (int i = 0; i < to_send->total; i++) {
    /* Bob receives the fragments */
    otrng_client_receive(&from_bob, &to_display, to_send->pieces[i],
                         ALICE_ACCOUNT, bob, &ignore);
    otrng_assert(!from_bob);

    if (to_send->total - 1 == i) {
      g_assert_cmpstr(to_display, ==, message);
    }
  }

  otrng_free(from_bob);
  from_bob = NULL;

  otrng_free(to_display);
  to_display = NULL;

  otrng_message_free(to_send);
  otrng_global_state_free(alice->global_state);
  otrng_global_state_free(bob->global_state);
  otrng_client_free_all(alice, bob);
}

void functionals_client_add_tests(void) {
  g_test_add_func("/client/conversation_api", test_client_conversation_api);
  g_test_add_func("/client/sends_fragments",
                  test_client_sends_fragmented_message);
  g_test_add_func("/client/expires_old_fragments",
                  test_client_expires_old_fragments);
  g_test_add_func("/client/receives_fragments",
                  test_client_receives_fragmented_message);
  g_test_add_func("/client/invalid_auth_r_message_in_not_waiting_auth_r",
                  test_invalid_auth_r_message_in_not_waiting_auth_r);
  g_test_add_func("/client/invalid_auth_i_message_in_not_waiting_auth_i",
                  test_invalid_auth_i_message_in_not_waiting_auth_i);
  g_test_add_func("/client/identity_message_in_waiting_auth_i",
                  test_valid_identity_message_in_waiting_auth_i);
  g_test_add_func("/client/identity_message_in_waiting_auth_r",
                  test_valid_identity_message_in_waiting_auth_r);
  g_test_add_func("/client/conversation_data_message_multiple_locations",
                  test_conversation_with_multiple_locations);
  g_test_add_func("/client/api", test_client_api);
}
