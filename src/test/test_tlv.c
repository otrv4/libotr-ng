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
