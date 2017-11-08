#include "../tlv.h"

void test_tlv_parse() {
  uint8_t msg[22] = {0x00, 0x06, 0x00, 0x03, 0x08, 0x05, 0x09, 0x00,
                      0x02, 0x00, 0x04, 0xac, 0x04, 0x05, 0x06, 0x00,
                      0x05, 0x00, 0x03, 0x08, 0x05, 0x09};

  uint8_t data[3] = {0x08, 0x05, 0x09};
  uint8_t data2[4] = {0xac, 0x04, 0x05, 0x06};

  tlv_t *tlv = otrv4_parse_tlvs(msg, sizeof(msg));
  assert_tlv_structure(tlv, OTRV4_TLV_SMP_ABORT, sizeof(data), data, true);
  assert_tlv_structure(tlv->next, OTRV4_TLV_SMP_MSG_1, sizeof(data2), data2,
                       true);
  assert_tlv_structure(tlv->next->next, OTRV4_TLV_SMP_MSG_4, sizeof(data),
                       data, false);

  otrv4_tlv_free(tlv);
}

void test_append_tlv() {
  uint8_t smp2_data[2] = {0x03, 0x04};
  uint8_t smp3_data[3] = {0x05, 0x04, 0x03};

  tlv_t *tlvs = NULL;
  tlv_t *smp_msg2_tlv =
      otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data);
  tlv_t *smp_msg3_tlv =
      otrv4_tlv_new(OTRV4_TLV_SMP_MSG_3, sizeof(smp3_data), smp3_data);

  tlvs = append_tlv(tlvs, smp_msg2_tlv);

  assert_tlv_structure(tlvs, OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data,
                       false);

  tlvs = append_tlv(tlvs, smp_msg3_tlv);

  assert_tlv_structure(tlvs, OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data,
                       true);
  assert_tlv_structure(tlvs->next, OTRV4_TLV_SMP_MSG_3, sizeof(smp3_data),
                       smp3_data, false);

  assert_tlv_structure(tlvs, OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data,
                       true);

  otrv4_tlv_free(tlvs);
}

void test_append_padding_tlv() {
  uint8_t smp2_data[2] = {0x03, 0x04};

  tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data);

  otr4_err_t err = append_padding_tlv(tlv, 6);

  otrv4_assert(err == OTR4_SUCCESS);
  assert_tlv_structure(tlv->next, OTRV4_TLV_PADDING, 245, smp2_data,
                       false);

  otrv4_tlv_free(tlv);

  tlv = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data);

  err = append_padding_tlv(tlv, 500);

  assert_tlv_structure(tlv->next, OTRV4_TLV_PADDING, 7, smp2_data,
                       false);

  otrv4_tlv_free(tlv);
}
