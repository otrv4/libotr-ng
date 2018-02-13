#include "../smp.h"
#include "../tlv.h"

void test_smp_state_machine(void) {
  return;
  OTRV4_INIT;

  otrv4_client_state_t *alice_keypair = otrv4_client_state_new(NULL);
  otrv4_client_state_t *bob_keypair = otrv4_client_state_new(NULL);

  smp_msg_1_t smp_msg_1[1];
  smp_msg_2_t smp_msg_2[1];

  uint8_t alice_sym[ED448_PRIVATE_BYTES] = {1};
  uint8_t bob_sym[ED448_PRIVATE_BYTES] = {2};
  otrv4_client_state_add_private_key_v4(alice_keypair, alice_sym);
  otrv4_client_state_add_private_key_v4(bob_keypair, bob_sym);
  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V4};

  otrv4_t *alice_otr = otrv4_new(alice_keypair, policy);
  otrv4_t *bob_otr = otrv4_new(bob_keypair, policy);
  g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT1);
  g_assert_cmpint(bob_otr->smp->state, ==, SMPSTATE_EXPECT1);

  do_dake_fixture(alice_otr, bob_otr);

  g_assert_cmpint(0, ==, alice_otr->smp->progress);
  g_assert_cmpint(0, ==, bob_otr->smp->progress);

  const char *question = "some-question";
  const char *answer = "answer";
  string_t to_send = NULL;
  otrv4_assert(otrv4_smp_start(&to_send, question, strlen(question),
                               (uint8_t *)answer, strlen(answer),
                               alice_otr) == SUCCESS);

  tlv_t *tlv_smp_1 = NULL;
  // otrv4_assert(smp_msg_1_deserialize(smp_msg_1, tlv_smp_1) == true);
  g_assert_cmpint(tlv_smp_1->type, ==, OTRV4_TLV_SMP_MSG_1);

  g_assert_cmpint(25, ==, alice_otr->smp->progress);
  g_assert_cmpint(0, ==, bob_otr->smp->progress);

  free(to_send);
  to_send = NULL;

  // Should have correct context after generates tlv_smp_2
  g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT2);
  otrv4_assert(alice_otr->smp->secret);
  otrv4_assert(alice_otr->smp->a2);
  otrv4_assert(alice_otr->smp->a3);

  // Receives first message
  tlv_t *tlv_smp_2 = NULL; // otrv4_process_smp(bob_otr, tlv_smp_1);
  otrv4_tlv_free(tlv_smp_1);
  otrv4_assert(!tlv_smp_2);

  g_assert_cmpint(25, ==, alice_otr->smp->progress);
  g_assert_cmpint(25, ==, bob_otr->smp->progress);

  tlv_smp_2 = NULL; // otrv4_smp_provide_secret(bob_otr, (const uint8_t
                    // *)"answer", strlen("answer"));
  otrv4_assert(tlv_smp_2);
  g_assert_cmpint(tlv_smp_2->type, ==, OTRV4_TLV_SMP_MSG_2);

  g_assert_cmpint(25, ==, alice_otr->smp->progress);
  g_assert_cmpint(50, ==, bob_otr->smp->progress);

  // Should have correct context after generates tlv_smp_2
  g_assert_cmpint(bob_otr->smp->state, ==, SMPSTATE_EXPECT3);
  otrv4_assert(bob_otr->smp->secret);
  otrv4_assert_point_equals(bob_otr->smp->G3a, smp_msg_1->G3a);
  g_assert_cmpint(smp_msg_2_deserialize(smp_msg_2, tlv_smp_2), ==, 0);
  otrv4_assert_point_equals(bob_otr->smp->Pb, smp_msg_2->Pb);
  otrv4_assert_point_equals(bob_otr->smp->Qb, smp_msg_2->Qb);
  otrv4_assert(bob_otr->smp->b3);
  otrv4_assert(bob_otr->smp->G2);
  otrv4_assert(bob_otr->smp->G3);

  otrv4_smp_msg_1_destroy(smp_msg_1);
  smp_msg_2_destroy(smp_msg_2);

  // Receives second message
  tlv_t *tlv_smp_3 = NULL; // otrv4_process_smp(alice_otr, tlv_smp_2);
  otrv4_tlv_free(tlv_smp_2);
  otrv4_assert(tlv_smp_3);
  g_assert_cmpint(tlv_smp_3->type, ==, OTRV4_TLV_SMP_MSG_3);

  g_assert_cmpint(50, ==, alice_otr->smp->progress);
  g_assert_cmpint(50, ==, bob_otr->smp->progress);

  // Should have correct context after generates tlv_smp_3
  g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT4);
  otrv4_assert(alice_otr->smp->G3b);
  otrv4_assert(alice_otr->smp->Pa_Pb);
  otrv4_assert(alice_otr->smp->Qa_Qb);

  // Receives third message
  tlv_t *tlv_smp_4 = NULL; // otrv4_process_smp(bob_otr, tlv_smp_3);
  otrv4_tlv_free(tlv_smp_3);
  otrv4_assert(tlv_smp_4);
  g_assert_cmpint(tlv_smp_4->type, ==, OTRV4_TLV_SMP_MSG_4);

  g_assert_cmpint(50, ==, alice_otr->smp->progress);
  g_assert_cmpint(100, ==, bob_otr->smp->progress);

  // SMP is finished for Bob
  // TODO: Should this never end or move to a finished state?
  g_assert_cmpint(bob_otr->smp->state, ==, SMPSTATE_EXPECT1);

  // Receives fourth message
  // otrv4_process_smp(alice_otr, tlv_smp_4);
  otrv4_tlv_free(tlv_smp_4);

  g_assert_cmpint(100, ==, alice_otr->smp->progress);
  g_assert_cmpint(100, ==, bob_otr->smp->progress);

  // SMP is finished for Alice
  g_assert_cmpint(alice_otr->smp->state, ==, SMPSTATE_EXPECT1);

  otrv4_assert_cmpmem(alice_otr->smp->secret, bob_otr->smp->secret, 64);

  otrv4_client_state_free(alice_keypair); // destroy keypair in otr?
  otrv4_client_state_free(bob_keypair);
  otrv4_free(alice_otr);
  otrv4_free(bob_otr);

  OTRV4_FREE;
};

void test_otrv4_generate_smp_secret(void) {
  smp_context_t smp;
  smp->msg1 = NULL;
  otrv4_fingerprint_t our = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  };

  otrv4_fingerprint_t their = {
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

  otrv4_generate_smp_secret(&smp->secret, our, their, ssid,
                      (const uint8_t *)"the-answer", strlen("the-answer"));
  otrv4_assert(smp->secret);

  unsigned char expected_secret[HASH_BYTES] = {
      0x45, 0xf6, 0x8c, 0x73, 0xae, 0xf0, 0xdc, 0x3c, 0x73, 0x74, 0xf2,
      0x75, 0x91, 0x5c, 0xbd, 0x65, 0x08, 0x9d, 0x4e, 0xa8, 0x73, 0x8c,
      0xcb, 0x56, 0x11, 0xe1, 0x15, 0xb8, 0x9c, 0xe6, 0xf8, 0xbd, 0x6e,
      0xd7, 0xb1, 0x93, 0xff, 0xf9, 0x9b, 0x96, 0x5b, 0x38, 0x1d, 0xcd,
      0x1b, 0x2f, 0x17, 0xc8, 0xb1, 0x20, 0xd4, 0x48, 0x3a, 0xb5, 0x13,
      0x1f, 0x4d, 0x07, 0x2d, 0x92, 0xea, 0x96, 0x16, 0x25,
  };

  otrv4_assert_cmpmem(expected_secret, smp->secret, 64);
  otrv4_smp_destroy(smp);
}

void test_otrv4_smp_msg_1_asprintf_null_question(void) {
  smp_msg_1_t msg[1];
  smp_context_t smp;
  smp->msg1 = NULL;
  uint8_t *buff;
  size_t writen = 0;

  otrv4_assert(otrv4_generate_smp_msg_1(msg, smp) == SUCCESS);
  // data_header + question + 2 points + 4 scalars = 4 + 0 + (2*57) + (4*(56))
  size_t expected_size = 342;
  msg->q_len = 0;
  msg->question = NULL;

  otrv4_assert(otrv4_smp_msg_1_asprintf(&buff, &writen, msg) == SUCCESS);
  g_assert_cmpint(writen, ==, expected_size);
  free(buff);
  buff = NULL;

  msg->question = "something";
  msg->q_len = strlen(msg->question);
  size_t expected_size_with_question = expected_size + msg->q_len;
  otrv4_assert(otrv4_smp_msg_1_asprintf(&buff, &writen, msg) == SUCCESS);
  g_assert_cmpint(writen, ==, expected_size_with_question);

  free(buff);
  buff = NULL;
}
