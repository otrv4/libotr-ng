#ifndef OTRV4_TLV_H
#define OTRV4_TLV_H

#include <stddef.h>
#include <stdint.h>

#include "shared.h"

typedef enum {
  OTRV4_TLV_NONE = -1,
  OTRV4_TLV_PADDING = 0,
  OTRV4_TLV_DISCONNECTED = 1,
  OTRV4_TLV_SMP_MSG_1 = 2,
  OTRV4_TLV_SMP_MSG_2 = 3,
  OTRV4_TLV_SMP_MSG_3 = 4,
  OTRV4_TLV_SMP_MSG_4 = 5,
  OTRV4_TLV_SMP_ABORT = 6,
  OTRV4_TLV_SYM_KEY = 7
} tlv_type_t;

typedef struct tlv_s {
  tlv_type_t type;
  uint16_t len;
  uint8_t *data;
  struct tlv_s *next;
} tlv_t;

INTERNAL void otrv4_tlv_free(tlv_t *tlv);

INTERNAL tlv_t *otrv4_tlv_new(uint16_t type, uint16_t len, uint8_t *data);

INTERNAL tlv_t *otrv4_disconnected_tlv_new(void);

INTERNAL tlv_t *otrv4_parse_tlvs(const uint8_t *src, size_t len);

INTERNAL tlv_t *otrv4_append_tlv(tlv_t *tlvs, tlv_t *new_tlv);

INTERNAL otrv4_err_t otrv4_append_padding_tlv(tlv_t **tlvs, int message_len);


#ifdef OTRV4_TLV_PRIVATE
#endif

#endif
