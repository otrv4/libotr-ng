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

/* Test the an in-order sending and receiving double ratchet */
void test_double_ratchet_new_sending_ratchet_in_order(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

  alice_client_state->pad = true;
  bob_client_state->pad = true;

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
  otrng_notif notif = NOTIF_NONE;

  // Alice sends a data message
  result = otrng_send_message(&to_send_1, "hi", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result =
      otrng_send_message(&to_send_2, "how are you?", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_2);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result = otrng_send_message(&to_send_3, "it's me", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_3);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 3);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives 2 data messages
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send_2, bob);
  assert_msg_rec(result, "how are you?", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob sends a data message
  result = otrng_send_message(&to_send_4, "oh, hi", notif, NULL, 0, bob);
  assert_msg_sent(result, to_send_4);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob receives the previous data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send_3, bob);
  assert_msg_rec(result, "it's me", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_3);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 3);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, notif, to_send_4, alice);
  assert_msg_rec(result, "oh, hi", response_to_bob);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 1);

  free_message_and_response(response_to_bob, &to_send_4);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 3);

  // Bob sends another data message
  result = otrng_send_message(&to_send_5, "I'm good", notif, NULL, 0, bob);
  assert_msg_sent(result, to_send_5);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 2);
  g_assert_cmpint(bob->keys->k, ==, 3);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives the data message
  response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, notif, to_send_5, alice);
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

/* Test the out-of-order on the same DH ratchet */
void test_double_ratchet_same_ratchet_out_of_order(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

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
  otrng_notif notif = NOTIF_NONE;

  // Alice sends a data message
  result = otrng_send_message(&to_send_1, "hi", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result =
      otrng_send_message(&to_send_2, "how are you?", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_2);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result = otrng_send_message(&to_send_3, "it's me", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_3);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 3);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result = otrng_send_message(&to_send_4, "ok?", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_4);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 4);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send_4, bob);
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
  result = otrng_receive_message(response_to_alice, notif, to_send_3, bob);
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
  result = otrng_receive_message(response_to_alice, notif, to_send_2, bob);
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

/* Test the out-of-order when a new DH ratchet has happened */
void test_double_ratchet_new_ratchet_out_of_order(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

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
  otrng_notif notif = NOTIF_NONE;

  // Alice sends a data message
  result = otrng_send_message(&to_send_1, "hi", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result =
      otrng_send_message(&to_send_2, "how are you?", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_2);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 2);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  result = otrng_send_message(&to_send_3, "it's me", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_3);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 3);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // Bob receives 2 data messages
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send_2, bob);
  assert_msg_rec(result, "how are you?", response_to_alice);

  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 0);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob sends a data message
  result = otrng_send_message(&to_send_4, "oh, hi", notif, NULL, 0, bob);
  assert_msg_sent(result, to_send_4);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 0);

  g_assert_cmpint(bob->keys->i, ==, 2);
  g_assert_cmpint(bob->keys->j, ==, 1);
  g_assert_cmpint(bob->keys->k, ==, 2);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Alice receives a data message
  response_to_bob = otrng_response_new();
  result = otrng_receive_message(response_to_bob, notif, to_send_4, alice);
  assert_msg_rec(result, "oh, hi", response_to_bob);
  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 1);

  free_message_and_response(response_to_bob, &to_send_4);
  g_assert_cmpint(alice->keys->i, ==, 2);
  g_assert_cmpint(alice->keys->j, ==, 0);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 3);

  // Alice sends a data message
  result = otrng_send_message(&to_send_5, "good", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_5);

  g_assert_cmpint(otrng_list_len(alice->keys->old_mac_keys), ==, 0);

  g_assert_cmpint(alice->keys->i, ==, 3);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 1);
  g_assert_cmpint(alice->keys->pn, ==, 3);

  // Bob receives the data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send_5, bob);
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
  result = otrng_receive_message(response_to_alice, notif, to_send_3, bob);
  assert_msg_rec(result, "it's me", response_to_alice);

  free_message_and_response(response_to_alice, &to_send_3);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 2);
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 0);
  g_assert_cmpint(bob->keys->i, ==, 3);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 1);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}

/* Test the double ratchet when a corrupted message arrives */
void test_double_ratchet_corrupted_ratchet(void) {
  otrng_client_state_s *alice_client_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_client_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_client_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_client_state, BOB_IDENTITY, 2);

  bob_client_state->pad = true;
  alice_client_state->pad = true;

  // DAKE has finished
  do_dake_fixture(alice, bob);

  otrng_response_s *response_to_alice = NULL;

  string_p to_send_1 = NULL;
  string_p to_send_2 = NULL;
  otrng_err result;
  otrng_notif notif = NOTIF_NONE;

  // Alice sends a data message
  result = otrng_send_message(&to_send_1, "hi", notif, NULL, 0, alice);
  assert_msg_sent(result, to_send_1);
  otrng_assert(!alice->keys->old_mac_keys);

  g_assert_cmpint(alice->keys->i, ==, 1);
  g_assert_cmpint(alice->keys->j, ==, 1);
  g_assert_cmpint(alice->keys->k, ==, 0);
  g_assert_cmpint(alice->keys->pn, ==, 0);

  // A corrupted data message
  data_message_s *corrupted_data_msg = otrng_data_message_new();
  corrupted_data_msg->ratchet_id = 7;
  corrupted_data_msg->message_id = 9;
  corrupted_data_msg->previous_chain_n = 1;
  corrupted_data_msg->sender_instance_tag = alice->our_instance_tag;
  corrupted_data_msg->receiver_instance_tag = bob->our_instance_tag;
  corrupted_data_msg->enc_msg = (uint8_t *)otrng_strdup("hduejo");
  corrupted_data_msg->enc_msg_len = 7;
  otrng_ec_point_copy(corrupted_data_msg->ecdh, bob->keys->our_ecdh->pub);
  corrupted_data_msg->dh = otrng_dh_mpi_copy(bob->keys->our_dh->pub);
  memset(corrupted_data_msg->nonce, 0, DATA_MSG_NONCE_BYTES);
  m_mac_key_p mac_key;
  memset(mac_key, 0, sizeof mac_key);
  serialize_and_encode_data_msg(&to_send_2, mac_key, NULL, 0,
                                corrupted_data_msg);

  // Bob receives a data message
  response_to_alice = otrng_response_new();
  result = otrng_receive_message(response_to_alice, notif, to_send_1, bob);
  assert_msg_rec(result, "hi", response_to_alice);
  otrng_assert(bob->keys->old_mac_keys);

  free_message_and_response(response_to_alice, &to_send_1);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  g_assert_cmpint(bob->keys->k, ==, 1);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  // Bob receives the corrupted data message
  response_to_alice = otrng_response_new();
  otrng_assert_is_error(
      otrng_receive_message(response_to_alice, notif, to_send_2, bob));
  free_message_and_response(response_to_alice, &to_send_2);

  g_assert_cmpint(otrng_list_len(bob->keys->old_mac_keys), ==, 1);
  // TODO: @double_ratchet the ratchet indeed moved and stored invalid keys
  g_assert_cmpint(otrng_list_len(bob->keys->skipped_keys), ==, 8);
  g_assert_cmpint(bob->keys->i, ==, 1);
  g_assert_cmpint(bob->keys->j, ==, 0);
  // TODO: @double_ratchet the ratchet indeed moved
  g_assert_cmpint(bob->keys->k, ==, 10);
  g_assert_cmpint(bob->keys->pn, ==, 0);

  otrng_data_message_free(corrupted_data_msg);

  otrng_user_state_free_all(alice_client_state->user_state,
                            bob_client_state->user_state);
  otrng_client_state_free_all(alice_client_state, bob_client_state);
  otrng_free_all(alice, bob);
}
