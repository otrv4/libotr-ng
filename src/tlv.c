/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

#define OTRNG_TLV_PRIVATE

#include "deserialize.h"
#include "random.h"
#include "tlv.h"

const tlv_type_t tlv_types[] = {OTRNG_TLV_PADDING,   OTRNG_TLV_DISCONNECTED,
                                OTRNG_TLV_SMP_MSG_1, OTRNG_TLV_SMP_MSG_2,
                                OTRNG_TLV_SMP_MSG_3, OTRNG_TLV_SMP_MSG_4,
                                OTRNG_TLV_SMP_ABORT, OTRNG_TLV_SYM_KEY};

const size_t TLV_TYPES_LENGTH = OTRNG_TLV_SYM_KEY + 1;

tstatic void set_tlv_type(tlv_s *tlv, uint16_t tlv_type) {
  tlv->type = OTRNG_TLV_NONE;

  if (tlv_type >= 0 && tlv_type < TLV_TYPES_LENGTH) {
    tlv->type = tlv_types[tlv_type];
  }
}

tstatic tlv_s *parse_tlv(const uint8_t *src, size_t len, size_t *written) {
  tlv_s *tlv = malloc(sizeof(tlv_s));
  if (!tlv)
    return NULL;

  size_t w = 0;
  uint16_t tlv_type = -1;
  const uint8_t *start = src + *written;
  const uint8_t *cursor = start;

  if (!otrng_deserialize_uint16(&tlv_type, cursor, len, &w)) {
    tlv_free(tlv);
    return NULL;
  }

  set_tlv_type(tlv, tlv_type);

  len -= w;
  cursor += w;

  if (!otrng_deserialize_uint16(&tlv->len, cursor, len, &w)) {
    tlv_free(tlv);
    return NULL;
  }

  len -= w;
  cursor += w;

  if (len < tlv->len) {
    tlv_free(tlv);
    return NULL;
  }

  tlv->data = malloc(tlv->len);

  if (!tlv->data) {
    tlv_free(tlv);
    return NULL;
  }

  memcpy(tlv->data, cursor, tlv->len);
  *written += (cursor + tlv->len) - start;

  return tlv;
}

INTERNAL tlv_list_s *otrng_append_tlv(tlv_list_s *head, tlv_s *tlv) {
  tlv_list_s *n = otrng_tlv_list_one(tlv);
  if (!n)
    return NULL;

  if (!head)
    return n;

  tlv_list_s *current = head;

  while (current->next)
    current = current->next;

  current->next = n;

  return head;
}

INTERNAL tlv_list_s *otrng_parse_tlvs(const uint8_t *src, size_t len) {
  size_t written = 0;
  tlv_list_s *ret = NULL;
  int data_to_parse = len;

  while (data_to_parse > 0) {
    tlv_s *tlv = parse_tlv(src, data_to_parse, &written);
    if (!tlv)
      break;

    ret = otrng_append_tlv(ret, tlv);
    data_to_parse = len - written;
  }

  return ret;
}

tstatic void tlv_free(tlv_s *tlv) {
  free(tlv->data);
  tlv->data = NULL;
  free(tlv);
}

INTERNAL void otrng_tlv_list_free(tlv_list_s *head) {
  tlv_list_s *current = head;
  while (current) {
    tlv_list_s *next = current->next;

    tlv_free(current->data);
    current->data = NULL;
    free(current);
    current = next;
  }
}

INTERNAL tlv_s *otrng_tlv_new(const uint16_t type, const uint16_t len,
                              const uint8_t *data) {
  tlv_s *tlv = malloc(sizeof(tlv_s));
  if (!tlv)
    return NULL;

  tlv->type = type;
  tlv->len = len;
  tlv->data = NULL;

  if (len != 0) {
    if (!data) {
      tlv_free(tlv);
      return NULL;
    }

    tlv->data = malloc(tlv->len);
    if (!tlv->data) {
      tlv_free(tlv);
      return NULL;
    }
    memcpy(tlv->data, data, tlv->len);
  }

  return tlv;
}

INTERNAL tlv_s *otrng_tlv_disconnected_new(void) {
  return otrng_tlv_new(OTRNG_TLV_DISCONNECTED, 0, NULL);
}

tstatic tlv_s *otrng_tlv_padding_new(size_t len) {
  uint8_t *data = malloc(len);
  if (!data)
    return NULL;

  random_bytes(data, len);
  tlv_s *tlv = otrng_tlv_new(OTRNG_TLV_PADDING, len, data);
  free(data);

  return tlv;
}

tstatic size_t needed_padding(size_t message_len) {
  const int padding_granularity = 256;
  const int header_len = 4;
  const int nul_byte_len = 1;

  return padding_granularity -
         ((message_len + header_len + nul_byte_len) % padding_granularity);
}

INTERNAL tlv_list_s *otrng_append_padding_tlv(tlv_list_s *tlvs,
                                              int message_len) {
  tlv_s *padding_tlv = otrng_tlv_padding_new(needed_padding(message_len));
  if (!padding_tlv)
    return NULL;

  return otrng_append_tlv(tlvs, padding_tlv);
}

INTERNAL tlv_list_s *otrng_tlv_list_one(tlv_s *tlv) {
  if (!tlv)
    return NULL;

  tlv_list_s *tlvs = malloc(sizeof(tlv_list_s));
  if (!tlvs)
    return NULL;

  tlvs->data = tlv;
  tlvs->next = NULL;

  return tlvs;
}
