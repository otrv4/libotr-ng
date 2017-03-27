#ifndef TLV_H
#define TLV_H

#include <stddef.h>
#include <stdint.h>

#define OTRV4_TLV_PADDING 0
#define OTRV4_TLV_DISCONNECTED 1

typedef struct tlv_s {
	uint16_t type;
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
