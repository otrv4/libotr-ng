#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "deserialize.h"
#include "random.h"
#include "tlv.h"

const tlv_type_t tlv_types[] = {OTRV4_TLV_PADDING,   OTRV4_TLV_DISCONNECTED,
                                OTRV4_TLV_SMP_MSG_1, OTRV4_TLV_SMP_MSG_2,
                                OTRV4_TLV_SMP_MSG_3, OTRV4_TLV_SMP_MSG_4,
                                OTRV4_TLV_SMP_ABORT, OTRV4_TLV_SYM_KEY};

void set_tlv_type(tlv_t *tlv, uint16_t tlv_type) {
  tlv_type_t type = OTRV4_TLV_NONE;

  if (tlv_type >= 0 && tlv_type < 8) {
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

tlv_t *append_tlv(tlv_t *head, tlv_t *tlv) {
  if (!head)
    return tlv;

  tlv_t *current = head;

  while (current->next)
    current = current->next;

  tlv_t *last_tlv = current;
  last_tlv->next = tlv;

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

    ret = append_tlv(ret, tlv);

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

tlv_t *otrv4_disconnected_tlv_new(void) {
  return otrv4_tlv_new(OTRV4_TLV_DISCONNECTED, 0, NULL);
}

tlv_t *otrv4_padding_tlv_new(size_t len) {
  uint8_t *data = malloc(len);
  if (!data)
    return NULL;

  random_bytes(data, sizeof(data));
  tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_PADDING, len, data);
  free(data); // TODO: this shouldn't be the case.
  // Maybe this is a potential mem leak.

  return tlv;
}

otr4_err_t append_padding_tlv(tlv_t *tlvs, int message_len) {
  int padding_granularity = 256;
  int header_len = 4;
  // TODO: check this
  int padding = padding_granularity -
                ((message_len + header_len + 1) % padding_granularity);

  tlv_t *padding_tlv = otrv4_padding_tlv_new(padding);
  if (!padding_tlv)
    return OTR4_ERROR;

  tlvs = append_tlv(tlvs, padding_tlv);

  return OTR4_SUCCESS;
}
