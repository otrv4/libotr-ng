#ifndef TLV_H
#define TLV_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
	OTRV4_TLV_PADDING = 0,
	OTRV4_TLV_DISCONNECTED = 1,
	OTRV4_TLV_SMP_MSG_1 = 2,
	OTRV4_TLV_SMP_MSG_2 = 3
} tlv_type_t;

typedef struct tlv_s {
	tlv_type_t type;
	uint16_t len;
	uint8_t *data;
	struct tlv_s *next;
} tlv_t;

tlv_t *otrv4_tlv_free(tlv_t * tlv);
tlv_t *otrv4_tlv_new(uint16_t type, uint16_t len, uint8_t * data);

tlv_t *otrv4_padding_tlv_new(size_t len);
tlv_t *otrv4_disconnected_tlv_new(void);

tlv_t *otrv4_parse_tlvs(const uint8_t * src, size_t len);

#endif
