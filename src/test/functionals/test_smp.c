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

#include "otrng.h"
#include "smp_protocol.h"
#include "tlv.h"

static void test_smp_state_machine(void) {
  OTRNG_INIT;

  otrng_client_s *alice_state = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_state = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_state, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_state, BOB_ACCOUNT, 2);

  smp_message_1_s smp_message_1;
  smp_message_2_s smp_message_2;

  g_assert_cmpint(alice->smp->state_expect, ==, SMP_STATE_EXPECT_1);
  g_assert_cmpint(bob->smp->state_expect, ==, SMP_STATE_EXPECT_1);

  do_dake_fixture(alice, bob);

  g_assert_cmpint(alice->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_ZERO_PROGRESS);

  const uint8_t *question = (const uint8_t *)"some-question";

  tlv_s *tlv_smp_1 = otrng_smp_initiate(
      get_my_client_profile(alice), alice->their_client_profile, question, 13,
      (const uint8_t *)"answer", strlen("answer"), alice->keys->ssid,
      alice->smp, alice);
  otrng_assert(tlv_smp_1);

  otrng_assert_is_success(smp_message_1_deserialize(&smp_message_1, tlv_smp_1));

  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(alice->smp->state_expect, ==, SMP_STATE_EXPECT_2);
  otrng_assert(alice->smp->secret);
  otrng_assert(alice->smp->a2);
  otrng_assert(alice->smp->a3);

  // Bob receives first message
  tlv_s *tlv_smp_2 = process_tlv(tlv_smp_1, bob);
  otrng_tlv_free(tlv_smp_1);
  otrng_assert(!tlv_smp_2);

  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_QUARTER_PROGRESS);

  otrng_smp_event event = OTRNG_SMP_EVENT_NONE;
  tlv_smp_2 = otrng_smp_provide_secret(
      &event, bob->smp, get_my_client_profile(bob), bob->their_client_profile,
      bob->keys->ssid, (const uint8_t *)"answer", strlen("answer"));
  otrng_assert(tlv_smp_2);
  g_assert_cmpint(tlv_smp_2->type, ==, OTRNG_TLV_SMP_MSG_2);
  otrng_assert_is_success(smp_message_2_deserialize(&smp_message_2, tlv_smp_2));
  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_HALF_PROGRESS);

  // Bob should have the correct context after he generates tlv_smp_2
  g_assert_cmpint(bob->smp->state_expect, ==, SMP_STATE_EXPECT_3);
  otrng_assert(bob->smp->secret);
  otrng_assert_point_equals(bob->smp->g3a, smp_message_1.g3a);
  otrng_assert_point_equals(bob->smp->pb, smp_message_2.pb);
  otrng_assert_point_equals(bob->smp->qb, smp_message_2.qb);
  otrng_assert_not_zero(bob->smp->b3, ED448_SCALAR_BYTES);
  otrng_assert_not_zero(bob->smp->g2, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob->smp->g3, ED448_POINT_BYTES);

  otrng_smp_message_1_destroy(&smp_message_1);
  smp_message_2_destroy(&smp_message_2);

  // Alice receives smp 2
  tlv_s *tlv_smp_3 = process_tlv(tlv_smp_2, alice);
  otrng_tlv_free(tlv_smp_2);
  otrng_assert(tlv_smp_3);

  g_assert_cmpint(tlv_smp_3->type, ==, OTRNG_TLV_SMP_MSG_3);
  g_assert_cmpint(alice->smp->progress, ==, SMP_HALF_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_HALF_PROGRESS);

  // Alice should have correct context after generates tlv_smp_3
  g_assert_cmpint(alice->smp->state_expect, ==, SMP_STATE_EXPECT_4);
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
  g_assert_cmpint(bob->smp->state_expect, ==, SMP_STATE_EXPECT_1);

  // Alice receives smp 4
  process_tlv(tlv_smp_4, alice);
  otrng_tlv_free(tlv_smp_4);

  g_assert_cmpint(alice->smp->progress, ==, SMP_TOTAL_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_TOTAL_PROGRESS);

  // SMP is finished for Alice
  g_assert_cmpint(alice->smp->state_expect, ==, SMP_STATE_EXPECT_1);
  otrng_assert_cmpmem(alice->smp->secret, bob->smp->secret, HASH_BYTES);

  otrng_global_state_free(alice_state->global_state);
  otrng_global_state_free(bob_state->global_state);
  otrng_client_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);
}

static void test_smp_state_machine_abort(void) {
  OTRNG_INIT;

  otrng_client_s *alice_state = otrng_client_new(ALICE_IDENTITY);
  otrng_client_s *bob_state = otrng_client_new(BOB_IDENTITY);

  otrng_s *alice = set_up(alice_state, ALICE_ACCOUNT, 1);
  otrng_s *bob = set_up(bob_state, BOB_ACCOUNT, 2);

  smp_message_1_s smp_message_1;
  smp_message_2_s smp_message_2;

  g_assert_cmpint(alice->smp->state_expect, ==, SMP_STATE_EXPECT_1);
  g_assert_cmpint(bob->smp->state_expect, ==, SMP_STATE_EXPECT_1);

  do_dake_fixture(alice, bob);

  g_assert_cmpint(alice->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_ZERO_PROGRESS);

  const uint8_t *question = (const uint8_t *)"some-question";

  tlv_s *tlv_smp_1 = otrng_smp_initiate(
      get_my_client_profile(alice), alice->their_client_profile, question, 13,
      (const uint8_t *)"answer", strlen("answer"), alice->keys->ssid,
      alice->smp, alice);
  otrng_assert(tlv_smp_1);

  otrng_assert_is_success(smp_message_1_deserialize(&smp_message_1, tlv_smp_1));

  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(alice->smp->state_expect, ==, SMP_STATE_EXPECT_2);
  otrng_assert(alice->smp->secret);
  otrng_assert(alice->smp->a2);
  otrng_assert(alice->smp->a3);

  // Bob receives first message
  tlv_s *tlv_smp_2 = process_tlv(tlv_smp_1, bob);
  otrng_tlv_free(tlv_smp_1);
  otrng_assert(!tlv_smp_2);

  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_QUARTER_PROGRESS);

  otrng_smp_event event = OTRNG_SMP_EVENT_NONE;
  tlv_smp_2 = otrng_smp_provide_secret(
      &event, bob->smp, get_my_client_profile(bob), bob->their_client_profile,
      bob->keys->ssid, (const uint8_t *)"answer", strlen("answer"));
  otrng_assert(tlv_smp_2);
  g_assert_cmpint(tlv_smp_2->type, ==, OTRNG_TLV_SMP_MSG_2);
  otrng_assert_is_success(smp_message_2_deserialize(&smp_message_2, tlv_smp_2));
  g_assert_cmpint(alice->smp->progress, ==, SMP_QUARTER_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_HALF_PROGRESS);

  // Bob should have the correct context after he generates tlv_smp_2
  g_assert_cmpint(bob->smp->state_expect, ==, SMP_STATE_EXPECT_3);
  otrng_assert(bob->smp->secret);
  otrng_assert_point_equals(bob->smp->g3a, smp_message_1.g3a);
  otrng_assert_point_equals(bob->smp->pb, smp_message_2.pb);
  otrng_assert_point_equals(bob->smp->qb, smp_message_2.qb);
  otrng_assert_not_zero(bob->smp->b3, ED448_SCALAR_BYTES);
  otrng_assert_not_zero(bob->smp->g2, ED448_POINT_BYTES);
  otrng_assert_not_zero(bob->smp->g3, ED448_POINT_BYTES);

  otrng_smp_message_1_destroy(&smp_message_1);
  smp_message_2_destroy(&smp_message_2);

  // To trigger the abort
  alice->smp->state_expect = SMP_STATE_EXPECT_1;

  // Alice receives smp 2
  tlv_s *tlv_abort = process_tlv(tlv_smp_2, alice);
  otrng_tlv_free(tlv_smp_2);
  otrng_assert(tlv_abort);

  g_assert_cmpint(tlv_abort->type, ==, OTRNG_TLV_SMP_ABORT);
  g_assert_cmpint(alice->smp->progress, ==, SMP_ZERO_PROGRESS);
  g_assert_cmpint(bob->smp->progress, ==, SMP_HALF_PROGRESS);

  // Alice should have correct context after generates tlv_smp_3
  g_assert_cmpint(alice->smp->state_expect, ==, SMP_STATE_EXPECT_1);
  otrng_assert(alice->smp->g3b);
  otrng_assert(alice->smp->pa_pb);
  otrng_assert(alice->smp->qa_qb);

  otrng_tlv_free(tlv_abort);

  otrng_global_state_free(alice_state->global_state);
  otrng_global_state_free(bob_state->global_state);
  otrng_client_free_all(alice_state, bob_state);
  otrng_free_all(alice, bob);
}

static void test_otrng_generate_smp_secret(void) {
  smp_protocol_s smp;
  smp.message1 = NULL;
  otrng_fingerprint our = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  };

  otrng_fingerprint their = {
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

  otrng_generate_smp_secret(&smp.secret, our, their, ssid,
                            (const uint8_t *)"the-answer",
                            strlen("the-answer"));
  otrng_assert(smp.secret);

  unsigned char expected_secret[HASH_BYTES] = {
      0x75, 0x51, 0x36, 0xb9, 0x33, 0xee, 0x8f, 0x87, 0x9a, 0x7b, 0xe6,
      0x3e, 0x44, 0x9a, 0xe4, 0x49, 0xf4, 0x81, 0x13, 0x14, 0xf6, 0xb6,
      0xe5, 0xae, 0x52, 0x5b, 0x24, 0x17, 0xeb, 0x12, 0x0d, 0x0d, 0x47,
      0xd7, 0x53, 0x73, 0xea, 0x3e, 0x02, 0xb3, 0xf8, 0x44, 0xd7, 0x5f,
      0x84, 0xba, 0xfd, 0xe9, 0x32, 0x34, 0x45, 0x0b, 0xa8, 0x01, 0xcc,
      0x78, 0x2b, 0x02, 0x12, 0xa3, 0xef, 0x7d, 0x4f, 0xdc,
  };

  otrng_assert_cmpmem(expected_secret, smp.secret, HASH_BYTES);
  otrng_smp_destroy(&smp);
}

static void test_otrng_smp_message_1_serialize_null_question(void) {
  smp_message_1_s message;
  smp_protocol_s smp;
  smp.message1 = NULL;
  uint8_t *buff;
  size_t writen = 0;

  otrng_assert_is_success(otrng_generate_smp_message_1(&message, &smp));

  // data_header + question + 2 points + 4 scalars = 4 + 0 + (2*57) + (4*(56))
  size_t expected_size = 342;
  message.q_len = 0;
  message.question = NULL;

  otrng_assert_is_success(
      otrng_smp_message_1_serialize(&buff, &writen, &message));
  g_assert_cmpint(writen, ==, expected_size);
  free(buff);

  message.question = (uint8_t *)"something";
  message.q_len = 9;
  size_t expected_len = expected_size + message.q_len;
  otrng_assert_is_success(
      otrng_smp_message_1_serialize(&buff, &writen, &message));
  g_assert_cmpint(writen, ==, expected_len);

  free(buff);
}

void functionals_smp_add_tests(void) {
  g_test_add_func("/smp/state_machine", test_smp_state_machine);
  g_test_add_func("/smp/state_machine_abort", test_smp_state_machine_abort);
  g_test_add_func("/smp/generate_secret", test_otrng_generate_smp_secret);
  g_test_add_func("/smp/message_1_serialize_null_question",
                  test_otrng_smp_message_1_serialize_null_question);
}
