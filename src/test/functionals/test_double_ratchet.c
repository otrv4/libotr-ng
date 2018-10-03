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

#include "test_helpers.h"

#include "test_fixtures.h"

/* Test the an in-order sending and receiving double ratchet */
static void test_double_ratchet_new_sending_ratchet_in_order(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;
  otrng_response_s *response_to_bob = NULL;

  string_p to_send_1 = NULL;
  string_p to_send_2 = NULL;
  string_p to_send_3 = NULL;
  string_p to_send_4 = NULL;
  string_p to_send_5 = NULL;
  otrng_result result;
  otrng_warning warn = OTRNG_WARN_NONE;

  // Alice sends a data message
  result = otrng_send_message(&to_send_1, "hi", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result =
      otrng_send_message(&to_send_2, "how are you?", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_2);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 3);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result = otrng_send_message(&to_send_3, "it's me", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_3);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 4);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives 2 data messages
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_2, bob);
  assert_msg_rec(result, "how are you?", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 3);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 3);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob sends a data message
  result = otrng_send_message(&to_send_4, "oh, hi", &warn, NULL, 0, bob);
  assert_msg_sent(result, to_send_4);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 3);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob receives the previous data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_3, bob);
  assert_msg_rec(result, "it's me", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_3);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 4);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, &warn, to_send_4, alice);
  assert_msg_rec(result, "oh, hi", response_to_bob);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 1);

  free_message_and_response(response_to_bob, &to_send_4);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 4);

  // Bob sends another data message
  result = otrng_send_message(&to_send_5, "I'm good", &warn, NULL, 0, bob);
  assert_msg_sent(result, to_send_5);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 2);
  g_assert_cmpint(bob->keys->k, ==, 4);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives the data message
  response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, &warn, to_send_5, alice);
  assert_msg_rec(result, "I'm good", response_to_bob);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 2);

  free_message_and_response(response_to_bob, &to_send_5);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 2);
  g_assert_cmpint(alice->keys->pn, ==, 4);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

/* Test the out-of-order on the same DH ratchet */
static void test_double_ratchet_same_ratchet_out_of_order(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;

  string_p to_send_1 = NULL;
  string_p to_send_2 = NULL;
  string_p to_send_3 = NULL;
  string_p to_send_4 = NULL;
  otrng_result result;
  otrng_warning warn = OTRNG_WARN_NONE;

  // Alice sends a data message

  result = otrng_send_message(&to_send_1, "hi", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result =
      otrng_send_message(&to_send_2, "how are you?", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_2);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 3);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result = otrng_send_message(&to_send_3, "it's me", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_3);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 4);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result = otrng_send_message(&to_send_4, "ok?", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_4);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 5);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_4, bob);
  assert_msg_rec(result, "ok?", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_4);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 3);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 5);
  g_assert_cmpint(bob->keys->pn, ==, 0);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 2);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_3, bob);
  assert_msg_rec(result, "it's me", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_3);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 4);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 5);
  g_assert_cmpint(bob->keys->pn, ==, 0);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 1);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_2, bob);
  assert_msg_rec(result, "how are you?", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 5);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 5);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

/* Test the out-of-order when a new DH ratchet has happened */
static void test_double_ratchet_new_ratchet_out_of_order(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;
  otrng_response_s *response_to_bob = NULL;

  string_p to_send_1 = NULL;
  string_p to_send_2 = NULL;
  string_p to_send_3 = NULL;
  string_p to_send_4 = NULL;
  string_p to_send_5 = NULL;
  otrng_result result;
  otrng_warning warn = OTRNG_WARN_NONE;

  // Alice sends a data message
  result = otrng_send_message(&to_send_1, "hi", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result =
      otrng_send_message(&to_send_2, "how are you?", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_2);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 3);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result = otrng_send_message(&to_send_3, "it's me", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_3);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 4);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives 2 data messages
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_2, bob);
  assert_msg_rec(result, "how are you?", response_to_alice);

  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 3);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 0);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 3);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob sends a data message
  result = otrng_send_message(&to_send_4, "oh, hi", &warn, NULL, 0, bob);
  assert_msg_sent(result, to_send_4);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 3);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, &warn, to_send_4, alice);
  assert_msg_rec(result, "oh, hi", response_to_bob);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 1);

  free_message_and_response(response_to_bob, &to_send_4);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 4);

  // Alice sends a data message
  result = otrng_send_message(&to_send_5, "good", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_5);

  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 0);

  g_assert_cmpint(alice->keys->i, ==, 3);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 4);

  // Bob receives the data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_5, bob);
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
  result = otrng_receive_message(response_to_alice, &warn, to_send_3, bob);
  assert_msg_rec(result, "it's me", response_to_alice);

  free_message_and_response(response_to_alice, &to_send_3);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 0);
  g_assert_cmpint(bob->keys->i, ==, 3);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 1);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

/* Test the double ratchet when a corrupted message arrives */
static void test_double_ratchet_corrupted_ratchet(void) {
  otrng_client_s *alice_client = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_client = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_client, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_client, BOB_ACCOUNT, 2);

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;

  string_p to_send_1 = NULL;
  string_p to_send_2 = NULL;
  otrng_result result;
  otrng_warning warn = OTRNG_WARN_NONE;

  // Alice sends a data message
  result = otrng_send_message(&to_send_1, "hi", &warn, NULL, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // A corrupted data message
  data_message_s *corrupted_data_msg = otrng_data_message_new();
  corrupted_data_msg->ratchet_id = 7;
  corrupted_data_msg->message_id = 9;
  corrupted_data_msg->previous_chain_n = 1;
  corrupted_data_msg->sender_instance_tag =
      otrng_client_get_instance_tag(alice_client);
  corrupted_data_msg->receiver_instance_tag =
      otrng_client_get_instance_tag(bob_client);
  corrupted_data_msg->enc_msg = (uint8_t *)otrng_xstrdup("hduejo");
  corrupted_data_msg->enc_msg_len = 7;
  otrng_ec_point_copy(corrupted_data_msg->ecdh, bob->keys->our_ecdh->pub);
  corrupted_data_msg->dh = otrng_dh_mpi_copy(bob->keys->our_dh->pub);
  memset(corrupted_data_msg->nonce, 0, DATA_MESSAGE_NONCE_BYTES);
  msg_mac_key mac_key;
  memset(mac_key, 0, sizeof mac_key);
  serialize_and_encode_data_msg(&to_send_2, mac_key, NULL, 0,
                                corrupted_data_msg);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, &warn, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob receives the corrupted data message
  response_to_alice = otrng_response_new();
  otrng_assert_is_error(
      otrng_receive_message(response_to_alice, &warn, to_send_2, bob));
  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 0);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  otrng_data_message_free(corrupted_data_msg);

  otrng_global_state_free(alice_client->global_state);
  otrng_global_state_free(bob_client->global_state);
  otrng_client_free_all(alice_client, bob_client);
  otrng_free_all(alice, bob);
}

void functionals_double_ratchet_add_tests(void) {
  g_test_add_func("/double_ratchet/in_order/new_sending_ratchet/v4",
                  test_double_ratchet_new_sending_ratchet_in_order);
  g_test_add_func("/double_ratchet/out_of_order/same_ratchet/v4",
                  test_double_ratchet_same_ratchet_out_of_order);
  g_test_add_func("/double_ratchet/out_of_order/new_ratchet/v4",
                  test_double_ratchet_new_ratchet_out_of_order);
  g_test_add_func("/double_ratchet/corrupted_ratchet/v4",
                  test_double_ratchet_corrupted_ratchet);
}
