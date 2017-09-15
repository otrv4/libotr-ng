#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "deserialize.h"
#include "tlv.h"

const tlv_type_t tlv_types[] = {OTRV4_TLV_PADDING,   OTRV4_TLV_DISCONNECTED,
                                OTRV4_TLV_SMP_MSG_1, OTRV4_TLV_SMP_MSG_2,
                                OTRV4_TLV_SMP_MSG_3, OTRV4_TLV_SMP_MSG_4,
                                OTRV4_TLV_SMP_ABORT};

void set_tlv_type(tlv_t *tlv, uint16_t tlv_type) {
  tlv_type_t type = OTRV4_TLV_NONE;

  if (tlv_type >= 0 && tlv_type < 7) {
    type = tlv_types[tlv_type];
  }

  tlv->type = type;
}

static tlv_t *extract_tlv(const uint8_t *src, size_t len, size_t *written) {
  size_t w = 0;
  tlv_t *tlv = NULL;
  uint16_t tlv_type = -1;
  const uint8_t *start = src + *written;
  const uint8_t *cursor = start;

  do {

    tlv = malloc(sizeof(tlv_t));
    if (!tlv)
      continue;

    if (deserialize_uint16(&tlv_type, cursor, len, &w))
      continue;

    set_tlv_type(tlv, tlv_type);

    len -= w;
    cursor += w;

    if (deserialize_uint16(&tlv->len, cursor, len, &w))
      continue;

    len -= w;
    cursor += w;

    if (len < tlv->len)
      continue;

    tlv->data = malloc(tlv->len);
    if (!tlv->data)
      continue;

    memcpy(tlv->data, cursor, tlv->len);
    len -= tlv->len;
    cursor += tlv->len;

    *written += cursor - start;

    tlv->next = NULL;

    return tlv;
  } while (0);

  free(tlv);
  return NULL;
}

tlv_t *create_tlv_chain(tlv_t *head, tlv_t *tlv) {
  if (!head)
    return tlv;

  tlv_t *current = head;

  while (current->next)
    current = current->next;

  tlv_t *last_tlv = current;
  last_tlv -> next = tlv;

  return head;
}

tlv_t *otrv4_parse_tlvs(const uint8_t *src, size_t len) {
  size_t written = 0;
  tlv_t *tlv = NULL, *ret = NULL;

  int data_to_parse = len;

  while (data_to_parse > 0) {

    tlv = extract_tlv(src, data_to_parse, &written);
    if (!tlv)
      break;

    ret = create_tlv_chain(ret, tlv);

    data_to_parse = len - written;
  }

  return ret;
}

void tlv_foreach(tlv_t *head) {
  tlv_t *current = head;
  while (current) {
    tlv_t *next = current->next;

    free(current->data);
    current->data = NULL;
    free(current);

    current = next;
  }
}

void otrv4_tlv_free(tlv_t *tlv) { tlv_foreach(tlv); }

tlv_t *otrv4_tlv_new(uint16_t type, uint16_t len, uint8_t *data) {
  tlv_t *tlv = malloc(sizeof(tlv_t));
  if (!tlv)
    return NULL;

  tlv->type = type;
  tlv->len = len;
  tlv->next = NULL;
  tlv->data = NULL;

  if (len != 0) {
    tlv->data = malloc(tlv->len);
    if (!tlv->data) {
      otrv4_tlv_free(tlv);
      return NULL;
    }
    memcpy(tlv->data, data, tlv->len);
  }

  return tlv;
}

tlv_t *otrv4_padding_tlv_new(size_t len) {
  uint8_t *data = malloc(len);
  if (!data)
    return NULL;

  memset(data, 0, len);
  tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_PADDING, len, data);
  free(data);

  return tlv;
}

tlv_t *otrv4_disconnected_tlv_new(void) {
  return otrv4_tlv_new(OTRV4_TLV_DISCONNECTED, 0, NULL);
}

void append_padding_tlv(tlv_t *tlvs, int message_len) {
  int padding_factor = 256;
  int padding_len = padding_factor - ((message_len + 4) % padding_factor);

  tlv_t *padding = otrv4_padding_tlv_new(padding_len);

  tlvs = create_tlv_chain(tlvs, padding);
}
