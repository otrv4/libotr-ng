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

#include "../smp.h"
#include "../tlv.h"

void test_smp_state_machine(void) {
  OTRNG_INIT;

  otrng_client_state_s *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_state, BOB_IDENTITY, 2);

  smp_msg_1_p smp_msg_1;
  smp_msg_2_p smp_msg_2;

  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  do_dake_fixture(alice, bob);

  g_assert_cmpint(alice->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_ZERO_PROGRESS);

  const uint8_t *question = (const uint8_t *)"some-question";

  tlv_s *tlv_smp_1 = otrng_smp_initiate(
      get_my_client_profile(alice), alice->their_client_profile, question, 13,
      (const uint8_t *)"answer", strlen("answer"), alice->keys->ssid,
      alice->smp, alice->conversation);
  otrng_assert(tlv_smp_1);

  otrng_assert_is_success(smp_msg_1_deserialize(smp_msg_1, tlv_smp_1));

  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT2);
  otrng_assert(alice->smp->secret);
  otrng_assert(alice->smp->a2);
  otrng_assert(alice->smp->a3);

  // Bob receives first message
  tlv_s *tlv_smp_2 = process_tlv(tlv_smp_1, bob);
  otrng_tlv_free(tlv_smp_1);
  otrng_assert(!tlv_smp_2);

  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_QUARTER_PROGRESS);

  otrng_smp_event_t event = OTRNG_SMP_EVENT_NONE;
  tlv_smp_2 = otrng_smp_provide_secret(
      &event, bob->smp, get_my_client_profile(bob), bob->their_client_profile,
      bob->keys->ssid, (const uint8_t *)"answer", strlen("answer"));
  otrng_assert(tlv_smp_2);
  g_assert_cmpint(tlv_smp_2->type, ==, OTRNG_TLV_SMP_MSG_2);
  otrng_assert_is_success(smp_msg_2_deserialize(smp_msg_2, tlv_smp_2));
  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_HALF_PROGRESS);

  // Bob should have the correct context after he generates tlv_smp_2
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT3);
  otrng_assert(bob->smp->secret);
  otrng_assert_point_equals(bob->smp->g3a, smp_msg_1->g3a);
  otrng_assert_point_equals(bob->smp->pb, smp_msg_2->pb);
  otrng_assert_point_equals(bob->smp->qb, smp_msg_2->qb);
  otrng_assert_not_zero(bob->smp->b3, ED448_SCALAR_BYTES);
  otrng_assert_not_zero(bob->smp->g2, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob->smp->g3, ED448_POINT_BYTES);

  otrng_smp_msg_1_destroy(smp_msg_1);
  smp_msg_2_destroy(smp_msg_2);

  // Alice receives smp 2
  tlv_s *tlv_smp_3 = process_tlv(tlv_smp_2, alice);
  otrng_tlv_free(tlv_smp_2);
  otrng_assert(tlv_smp_3);

  g_assert_cmpint(tlv_smp_3->type, ==, OTRNG_TLV_SMP_MSG_3);
  g_assert_cmpint(alice->smp->progress, ==, SMP_HALF_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_HALF_PROGRESS);

  // Alice should have correct context after generates tlv_smp_3
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT4);
  otrng_assert(alice->smp->g3b);
  otrng_assert(alice->smp->pa_pb);
  otrng_assert(alice->smp->qa_qb);

  // Bob receives smp 3
  tlv_s *tlv_smp_4 = process_tlv(tlv_smp_3, bob);
  otrng_tlv_free(tlv_smp_3);
  otrng_assert(tlv_smp_4);
  g_assert_cmpint(tlv_smp_4->type, ==, OTRNG_TLV_SMP_MSG_4);

  g_assert_cmpint(alice->smp->progress, ==, SMP_HALF_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_TOTAL_PROGRESS);

  // SMP is finished for Bob
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  // Alice receives smp 4
  process_tlv(tlv_smp_4, alice);
  otrng_tlv_free(tlv_smp_4);

  g_assert_cmpint(alice->smp->progress, ==, SMP_TOTAL_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_TOTAL_PROGRESS);

  // SMP is finished for Alice
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  otrng_assert_cmpmem(alice->smp->secret, bob->smp->secret, HASH_BYTES);

  otrng_user_state_free_all(alice_state->user_state, bob_state->user_state);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);
}

void test_smp_state_machine_abort(void) {
  OTRNG_INIT;

  otrng_client_state_s *alice_state = otrng_client_state_new(NULL);
  otrng_client_state_s *bob_state = otrng_client_state_new(NULL);

  otrng_s *alice = set_up(alice_state, ALICE_IDENTITY, 1);
  otrng_s *bob = set_up(bob_state, BOB_IDENTITY, 2);

  smp_msg_1_p smp_msg_1;
  smp_msg_2_p smp_msg_2;

  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT1);

  do_dake_fixture(alice, bob);

  g_assert_cmpint(alice->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_ZERO_PROGRESS);

  const uint8_t *question = (const uint8_t *)"some-question";

  tlv_s *tlv_smp_1 = otrng_smp_initiate(
      get_my_client_profile(alice), alice->their_client_profile, question, 13,
      (const uint8_t *)"answer", strlen("answer"), alice->keys->ssid,
      alice->smp, alice->conversation);
  otrng_assert(tlv_smp_1);

  otrng_assert_is_success(smp_msg_1_deserialize(smp_msg_1, tlv_smp_1));

  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT2);
  otrng_assert(alice->smp->secret);
  otrng_assert(alice->smp->a2);
  otrng_assert(alice->smp->a3);

  // Bob receives first message
  tlv_s *tlv_smp_2 = process_tlv(tlv_smp_1, bob);
  otrng_tlv_free(tlv_smp_1);
  otrng_assert(!tlv_smp_2);

  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_QUARTER_PROGRESS);

  otrng_smp_event_t event = OTRNG_SMP_EVENT_NONE;
  tlv_smp_2 = otrng_smp_provide_secret(
      &event, bob->smp, get_my_client_profile(bob), bob->their_client_profile,
      bob->keys->ssid, (const uint8_t *)"answer", strlen("answer"));
  otrng_assert(tlv_smp_2);
  g_assert_cmpint(tlv_smp_2->type, ==, OTRNG_TLV_SMP_MSG_2);
  otrng_assert_is_success(smp_msg_2_deserialize(smp_msg_2, tlv_smp_2));
  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_HALF_PROGRESS);

  // Bob should have the correct context after he generates tlv_smp_2
  g_assert_cmpint(bob->smp->state, ==, SMPSTATE_EXPECT3);
  otrng_assert(bob->smp->secret);
  otrng_assert_point_equals(bob->smp->g3a, smp_msg_1->g3a);
  otrng_assert_point_equals(bob->smp->pb, smp_msg_2->pb);
  otrng_assert_point_equals(bob->smp->qb, smp_msg_2->qb);
  otrng_assert_not_zero(bob->smp->b3, ED448_SCALAR_BYTES);
  otrng_assert_not_zero(bob->smp->g2, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob->smp->g3, ED448_POINT_BYTES);

  otrng_smp_msg_1_destroy(smp_msg_1);
  smp_msg_2_destroy(smp_msg_2);

  // To trigger the abort
  alice->smp->state = SMPSTATE_EXPECT1;

  // Alice receives smp 2
  tlv_s *tlv_abort = process_tlv(tlv_smp_2, alice);
  otrng_tlv_free(tlv_smp_2);
  otrng_assert(tlv_abort);

  g_assert_cmpint(tlv_abort->type, ==, OTRNG_TLV_SMP_ABORT);
  g_assert_cmpint(alice->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_HALF_PROGRESS);

  // Alice should have correct context after generates tlv_smp_3
  g_assert_cmpint(alice->smp->state, ==, SMPSTATE_EXPECT1);
  otrng_assert(alice->smp->g3b);
  otrng_assert(alice->smp->pa_pb);
  otrng_assert(alice->smp->qa_qb);

  otrng_tlv_free(tlv_abort);

  otrng_user_state_free_all(alice_state->user_state, bob_state->user_state);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);
}

void test_otrng_generate_smp_secret(void) {
  smp_context_p smp;
  smp->msg1 = NULL;
  otrng_fingerprint_p our = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  };

  otrng_fingerprint_p their = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  };

  uint8_t ssid[8] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  };

  otrng_generate_smp_secret(&smp->secret, our, their, ssid,
                            (const uint8_t *)"the-answer",
                            strlen("the-answer"));
  otrng_assert(smp->secret);

  unsigned char expected_secret[HASH_BYTES] = {
      0xa8, 0x9d, 0xfd, 0xb7, 0x96, 0x25, 0x6f, 0x97, 0xf3, 0x99, 0xb2,
      0x3d, 0x40, 0x34, 0x3c, 0x20, 0x8d, 0x6f, 0x97, 0xb3, 0xa1, 0x3e,
      0xd2, 0xc7, 0x28, 0x21, 0xb9, 0xb1, 0x63, 0x67, 0x89, 0xb1, 0x39,
      0x6a, 0x96, 0x36, 0x5e, 0xff, 0x35, 0x6c, 0x6b, 0x58, 0xb6, 0xd8,
      0x15, 0x2f, 0xb4, 0x3c, 0x0a, 0xfe, 0xa8, 0x6e, 0x35, 0x6d, 0xa0,
      0xed, 0x28, 0xb1, 0x7d, 0x24, 0x3a, 0x54, 0xba, 0x37,
  };

  otrng_assert_cmpmem(expected_secret, smp->secret, HASH_BYTES);
  otrng_smp_destroy(smp);
}

void test_otrng_smp_msg_1_asprintf_null_question(void) {
  smp_msg_1_p msg;
  smp_context_p smp;
  smp->msg1 = NULL;
  uint8_t *buff;
  size_t writen = 0;

  otrng_assert_is_success(otrng_generate_smp_msg_1(msg, smp));

  // data_header + question + 2 points + 4 scalars = 4 + 0 + (2*57) + (4*(56))
  size_t expected_size = 342;
  msg->q_len = 0;
  msg->question = NULL;

  otrng_assert_is_success(otrng_smp_msg_1_asprintf(&buff, &writen, msg));
  g_assert_cmpint(writen, ==, expected_size);
  free(buff);
  buff = NULL;

  msg->question = (uint8_t *)"something";
  msg->q_len = 9;
  size_t expected_len = expected_size + msg->q_len;
  otrng_assert_is_success(otrng_smp_msg_1_asprintf(&buff, &writen, msg));
  g_assert_cmpint(writen, ==, expected_len);

  free(buff);
  buff = NULL;
}
