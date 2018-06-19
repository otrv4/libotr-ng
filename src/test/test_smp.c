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

  smp_msg_1_p smp_msg_1;
  smp_msg_2_p smp_msg_2;

  alice_state->account_name = otrng_strdup(ALICE_IDENTITY);
  alice_state->protocol_name = otrng_strdup("otr");
  bob_state->account_name = otrng_strdup(BOB_IDENTITY);
  bob_state->protocol_name = otrng_strdup("otr");

  alice_state->user_state = otrl_userstate_create();
  bob_state->user_state = otrl_userstate_create();

  alice_state->phi = otrng_strdup("alice@jabber.com");
  bob_state->phi = otrng_strdup("alice@jabber.com");

  uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};
  otrng_client_state_add_private_key_v4(alice_state, alice_sym);
  otrng_client_state_add_private_key_v4(bob_state, bob_sym);

  otrng_client_state_add_instance_tag(alice_state, 0x101);
  otrng_client_state_add_instance_tag(bob_state, 0x102);
  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V4};

  otrng_s *alice_otr = otrng_new(alice_state, policy);
  otrng_s *bob_otr = otrng_new(bob_state, policy);

  g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob_otr->smp->state, ==, SMPSTATE_EXPECT1);

  do_dake_fixture(alice_otr, bob_otr);

  g_assert_cmpint(0, ==, alice_otr->smp->progress);
  g_assert_cmpint(0, ==, bob_otr->smp->progress);

  const uint8_t *question = (const uint8_t *)"some-question";
  const uint8_t *answer = (const uint8_t *)"answer";

  tlv_s *tlv_smp_1 = otrng_smp_initiate(
      get_my_client_profile(alice_otr), alice_otr->their_client_profile,
      question, 13, answer, 6, alice_otr->keys->ssid, alice_otr->smp,
      alice_otr->conversation);
  otrng_assert(tlv_smp_1);

  otrng_assert_is_success(smp_msg_1_deserialize(smp_msg_1, tlv_smp_1));

  g_assert_cmpint(25, ==, alice_otr->smp->progress);
  g_assert_cmpint(0, ==, bob_otr->smp->progress);

  g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT2);
  otrng_assert(alice_otr->smp->secret);
  otrng_assert(alice_otr->smp->a2);
  otrng_assert(alice_otr->smp->a3);

  // Receives first message
  tlv_s *tlv_smp_2 = process_tlv(tlv_smp_1, bob_otr);
  otrng_tlv_free(tlv_smp_1);
  otrng_assert(!tlv_smp_2);

  g_assert_cmpint(25, ==, alice_otr->smp->progress);
  g_assert_cmpint(25, ==, bob_otr->smp->progress);

  otrng_smp_event_t event = OTRNG_SMPEVENT_NONE;
  tlv_smp_2 = otrng_smp_provide_secret(
      &event, bob_otr->smp, get_my_client_profile(bob_otr),
      bob_otr->their_client_profile, bob_otr->keys->ssid,
      (const uint8_t *)"answer", strlen("answer"));
  otrng_assert(tlv_smp_2);
  g_assert_cmpint(tlv_smp_2->type, ==, OTRNG_TLV_SMP_MSG_2);
  otrng_assert_is_success(smp_msg_2_deserialize(smp_msg_2, tlv_smp_2));

  g_assert_cmpint(25, ==, alice_otr->smp->progress);
  g_assert_cmpint(50, ==, bob_otr->smp->progress);

  // Should have correct context after generates tlv_smp_2
  g_assert_cmpint(bob_otr->smp->state, ==, SMPSTATE_EXPECT3);
  otrng_assert(bob_otr->smp->secret);
  otrng_assert_point_equals(bob_otr->smp->G3a, smp_msg_1->G3a);
  otrng_assert_point_equals(bob_otr->smp->Pb, smp_msg_2->Pb);
  otrng_assert_point_equals(bob_otr->smp->Qb, smp_msg_2->Qb);
  otrng_assert(bob_otr->smp->b3);
  otrng_assert(bob_otr->smp->G2);
  otrng_assert(bob_otr->smp->G3);

  otrng_smp_msg_1_destroy(smp_msg_1);
  smp_msg_2_destroy(smp_msg_2);

  tlv_s *tlv_smp_3 = process_tlv(tlv_smp_2, alice_otr);
  otrng_tlv_free(tlv_smp_2);
  otrng_assert(tlv_smp_3);

  g_assert_cmpint(tlv_smp_3->type, ==, OTRNG_TLV_SMP_MSG_3);

  g_assert_cmpint(50, ==, alice_otr->smp->progress);
  g_assert_cmpint(50, ==, bob_otr->smp->progress);

  // Should have correct context after generates tlv_smp_3
  g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT4);
  otrng_assert(alice_otr->smp->G3b);
  otrng_assert(alice_otr->smp->Pa_Pb);
  otrng_assert(alice_otr->smp->Qa_Qb);

  // Receives third message
  tlv_s *tlv_smp_4 = process_tlv(tlv_smp_3, bob_otr);
  otrng_tlv_free(tlv_smp_3);
  otrng_assert(tlv_smp_4);
  g_assert_cmpint(tlv_smp_4->type, ==, OTRNG_TLV_SMP_MSG_4);

  g_assert_cmpint(50, ==, alice_otr->smp->progress);
  g_assert_cmpint(100, ==, bob_otr->smp->progress);

  // SMP is finished for Bob
  g_assert_cmpint(bob_otr->smp->state, ==, SMPSTATE_EXPECT1);

  // Receives fourth message
  process_tlv(tlv_smp_4, alice_otr);
  otrng_tlv_free(tlv_smp_4);

  g_assert_cmpint(100, ==, alice_otr->smp->progress);
  g_assert_cmpint(100, ==, bob_otr->smp->progress);

  // SMP is finished for Alice
  g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT1);

  otrng_assert_cmpmem(alice_otr->smp->secret, bob_otr->smp->secret, 64);

  otrng_user_state_free_all(alice_state->user_state, bob_state->user_state);
  otrng_client_state_free_all(alice_state, bob_state);
  otrng_free_all(alice_otr, bob_otr);
};

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
      0xfe, 0xb5, 0x67, 0xf1, 0xdf, 0x2a, 0x9d, 0x47, 0x05, 0x4a, 0xfa,
      0x22, 0xa9, 0x9a, 0x19, 0x71, 0x3d, 0xff, 0x71, 0xca, 0x1b, 0x7b,
      0x88, 0x26, 0x9a, 0x11, 0x95, 0x16, 0x6d, 0x7b, 0x0c, 0xf7, 0x8d,
      0x6b, 0x5a, 0x8c, 0xd8, 0xed, 0x2d, 0x04, 0xb2, 0x3a, 0x11, 0x9b,
      0xe0, 0xda, 0x7e, 0x38, 0x39, 0xec, 0x8f, 0xae, 0x91, 0x83, 0x72,
      0xe1, 0x58, 0x37, 0xcd, 0x0e, 0x21, 0x3d, 0xd5, 0xea,
  };

  otrng_assert_cmpmem(expected_secret, smp->secret, 64);
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
  size_t expected_size_with_question = expected_size + msg->q_len;
  otrng_assert_is_success(otrng_smp_msg_1_asprintf(&buff, &writen, msg));
  g_assert_cmpint(writen, ==, expected_size_with_question);

  free(buff);
  buff = NULL;
}
