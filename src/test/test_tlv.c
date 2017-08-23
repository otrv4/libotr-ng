#include "../tlv.h"

void test_tlv_new() {
	uint8_t data[2] = {0x03, 0x04};
	uint16_t len = 2;

	tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, len, data);

	otrv4_assert(tlv->type == OTRV4_TLV_SMP_MSG_2);
	otrv4_assert(tlv->len == len);
	otrv4_assert(tlv->next == NULL);
	otrv4_assert_cmpmem(tlv->data, data, len);

	otrv4_tlv_free(tlv);
}

void test_tlv_parse() {
	uint8_t msg1[7] = {0x01, 0x02, 0x00, 0x03, 0x08, 0x05, 0x09};
	uint8_t msg2[4] = {0x00, 0x00, 0x00, 0x00};
	uint8_t msg3[15] = {0x00, 0x01, 0x00, 0x03, 0x08, 0x05, 0x09, 0x00, 0x02, 0x00, 0xff, 0xac, 0x04, 0x05, 0x06};
	uint8_t msg4[15] = {0x00, 0x06, 0x00, 0x03, 0x08, 0x05, 0x09, 0x00, 0x02, 0x00, 0x04, 0xac, 0x04, 0x05, 0x06};

	uint8_t data2[3] = {0x08, 0x05, 0x09};
	uint8_t data3[4] = {0xac, 0x04, 0x05, 0x06};

	tlv_t *tlv1 = otrv4_parse_tlvs(msg1, sizeof(msg1));
	otrv4_assert(tlv1->type == OTRV4_TLV_NONE);
	otrv4_assert(tlv1->len == sizeof(data2));
	otrv4_assert(tlv1->next == NULL);
	otrv4_assert_cmpmem(tlv1->data, data2, sizeof(data2));

	tlv_t *tlv2 = otrv4_parse_tlvs(msg2, sizeof(msg2));
	otrv4_assert(tlv2->type == OTRV4_TLV_PADDING);
	otrv4_assert(tlv2->len == 0);
	otrv4_assert(tlv2->next == NULL);

	tlv_t *tlv3 = otrv4_parse_tlvs(msg3, sizeof(msg3));
	otrv4_assert(tlv3->type == OTRV4_TLV_DISCONNECTED);
	otrv4_assert(tlv3->len == sizeof(data2));
	otrv4_assert(tlv3->next == NULL);
	otrv4_assert_cmpmem(tlv3->data, data2, sizeof(data2));

	tlv_t *tlv4 = otrv4_parse_tlvs(msg4, sizeof(msg4));
	otrv4_assert(tlv4->type == OTRV4_TLV_SMP_ABORT);
	otrv4_assert(tlv4->len == sizeof(data2));
	otrv4_assert(tlv4->next != NULL);
	otrv4_assert_cmpmem(tlv4->data, data2, sizeof(data2));

	otrv4_assert(tlv4->next->type == OTRV4_TLV_SMP_MSG_1);
	otrv4_assert(tlv4->next->len == sizeof(data3));
	otrv4_assert_cmpmem(tlv4->next->data, data3, sizeof(data3));

	otrv4_tlv_free_all(4, tlv1, tlv2, tlv3, tlv4);
}

void test_tlv_new_padding() {
	uint16_t len = 2;
	uint8_t data[2] = {0x00, 0x00};

	tlv_t *tlv = otrv4_padding_tlv_new(len);

	otrv4_assert(tlv->type == OTRV4_TLV_PADDING);
	otrv4_assert(tlv->len == len);
	otrv4_assert(tlv->next == NULL);
	otrv4_assert_cmpmem(tlv->data, data, len);

	otrv4_tlv_free(tlv);
}
