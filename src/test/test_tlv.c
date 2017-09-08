#include "../tlv.h"

#define assert_tlv_structure(tlv, tlv_type, tlv_len, tlv_data, next_exists)    \
  do {                                                                         \
    otrv4_assert(tlv->type == tlv_type);                                       \
    otrv4_assert(tlv->len == tlv_len);                                         \
    if (next_exists) {                                                         \
      otrv4_assert(tlv->next != NULL);                                         \
    } else {                                                                   \
      otrv4_assert(tlv->next == NULL);                                         \
    }                                                                          \
    otrv4_assert_cmpmem(tlv->data, tlv_data, tlv_len);                         \
  } while (0)

static bool next_exists = true;

void test_tlv_new() {
  uint8_t data[2] = {0x03, 0x04};
  uint16_t len = 2;

  tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, len, data);

  assert_tlv_structure(tlv, OTRV4_TLV_SMP_MSG_2, len, data, !next_exists);

  otrv4_tlv_free(tlv);
}

void test_tlv_parse() {
  uint8_t msg1[7] = {0x01, 0x02, 0x00, 0x03, 0x08, 0x05, 0x09};
  uint8_t msg2[4] = {0x00, 0x00, 0x00, 0x00};
  uint8_t msg3[15] = {0x00, 0x01, 0x00, 0x03, 0x08, 0x05, 0x09,
                      0x00, 0x02, 0x00, 0xff, 0xac, 0x04, 0x05, 0x06};
  uint8_t msg4[15] = {0x00, 0x06, 0x00, 0x03, 0x08, 0x05, 0x09,
                      0x00, 0x02, 0x00, 0x04, 0xac, 0x04, 0x05, 0x06};
  uint8_t msg5[22] = {0x00, 0x06, 0x00, 0x03, 0x08, 0x05, 0x09,
                      0x00, 0x02, 0x00, 0x04, 0xac, 0x04, 0x05, 0x06,
                      0x00, 0x05, 0x00, 0x03, 0x08, 0x05, 0x09};

  uint8_t data1[3] = {0x08, 0x05, 0x09};
  uint8_t data2[4] = {0xac, 0x04, 0x05, 0x06};

  tlv_t *tlv1 = otrv4_parse_tlvs(msg1, sizeof(msg1));
  assert_tlv_structure(tlv1, OTRV4_TLV_NONE, sizeof(data1), data1,
                       !next_exists);

  tlv_t *tlv2 = otrv4_parse_tlvs(msg2, sizeof(msg2));
  otrv4_assert(tlv2->type == OTRV4_TLV_PADDING);
  otrv4_assert(tlv2->len == 0);
  otrv4_assert(tlv2->next == NULL);

  tlv_t *tlv3 = otrv4_parse_tlvs(msg3, sizeof(msg3));
  assert_tlv_structure(tlv3, OTRV4_TLV_DISCONNECTED, sizeof(data1), data1,
                       !next_exists);

  tlv_t *tlv4 = otrv4_parse_tlvs(msg4, sizeof(msg4));
  assert_tlv_structure(tlv4, OTRV4_TLV_SMP_ABORT, sizeof(data1), data1,
                       next_exists);
  assert_tlv_structure(tlv4->next, OTRV4_TLV_SMP_MSG_1, sizeof(data2), data2,
                       !next_exists);

  tlv_t *tlv5 = otrv4_parse_tlvs(msg5, sizeof(msg5));
  assert_tlv_structure(tlv5, OTRV4_TLV_SMP_ABORT, sizeof(data1), data1,
                       next_exists);
  assert_tlv_structure(tlv5->next, OTRV4_TLV_SMP_MSG_1, sizeof(data2), data2,
                       next_exists);
  assert_tlv_structure(tlv5->next->next, OTRV4_TLV_SMP_MSG_4, sizeof(data1), data1,
                       !next_exists);

  otrv4_tlv_free_all(5, tlv1, tlv2, tlv3, tlv4, tlv5);
}

void test_tlv_new_padding() {
  uint16_t len = 2;
  uint8_t data[2] = {0x00, 0x00};

  tlv_t *tlv = otrv4_padding_tlv_new(len);

  assert_tlv_structure(tlv, OTRV4_TLV_PADDING, len, data, !next_exists);

  otrv4_tlv_free(tlv);
}

void test_tlv_new_disconnected() {
  tlv_t *tlv = otrv4_disconnected_tlv_new();

  otrv4_assert(tlv->type == OTRV4_TLV_DISCONNECTED);
  otrv4_assert(tlv->len == 0);
  otrv4_assert(tlv->next == NULL);
  otrv4_assert(tlv->data == NULL);

  otrv4_tlv_free(tlv);
}

void test_create_tlv_chain() {
  uint8_t smp2_data[2] = {0x03, 0x04};
  uint8_t smp3_data[3] = {0x05, 0x04, 0x03};
  uint8_t pad_data[5] = {0x00, 0x00, 0x00, 0x00, 0x00};

  tlv_t *tlvs = NULL;
  tlv_t *tlv_smp2 = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data);
  tlv_t *tlv_smp3 = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_3, sizeof(smp3_data), smp3_data);
  tlv_t *tlv_pad = otrv4_padding_tlv_new(sizeof(pad_data));

  tlvs = create_tlv_chain(tlvs, tlv_smp2);

  assert_tlv_structure(tlvs, OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data, !next_exists);

  tlvs = create_tlv_chain(tlvs, tlv_smp3);

  assert_tlv_structure(tlvs, OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data, next_exists);
  assert_tlv_structure(tlvs->next, OTRV4_TLV_SMP_MSG_3, sizeof(smp3_data), smp3_data, !next_exists);

  tlvs = create_tlv_chain(tlvs, tlv_pad);

  assert_tlv_structure(tlvs, OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data, next_exists);
  assert_tlv_structure(tlvs->next, OTRV4_TLV_SMP_MSG_3, sizeof(smp3_data), smp3_data, next_exists);
  assert_tlv_structure(tlvs->next->next, OTRV4_TLV_PADDING, sizeof(pad_data), pad_data, !next_exists);

  otrv4_tlv_free(tlv_pad);
}
