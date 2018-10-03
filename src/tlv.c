/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
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

#include "alloc.h"
#include "deserialize.h"
#include "random.h"
#include "serialize.h"
#include "tlv.h"

const otrng_tlv_type_t tlv_types[] = {
    OTRNG_TLV_PADDING,       OTRNG_TLV_DISCONNECTED,  OTRNG_TLV_SMP_MESSAGE_1,
    OTRNG_TLV_SMP_MESSAGE_2, OTRNG_TLV_SMP_MESSAGE_3, OTRNG_TLV_SMP_MESSAGE_4,
    OTRNG_TLV_SMP_ABORT,     OTRNG_TLV_SYM_KEY};

const size_t TLV_TYPES_LENGTH = OTRNG_TLV_SYM_KEY + 1;

tstatic void set_tlv_type(tlv_s *tlv, uint16_t tlv_type) {
  tlv->type = OTRNG_TLV_NONE;

  if (tlv_type >= 0 && tlv_type < TLV_TYPES_LENGTH) {
    tlv->type = tlv_types[tlv_type];
  }
}

tstatic tlv_s *parse_tlv(const uint8_t *src, size_t len, size_t *read) {
  tlv_s *tlv = otrng_tlv_new(OTRNG_TLV_NONE, 0, NULL);
  size_t w = 0;
  uint16_t tlv_type = -1;
  const uint8_t *cursor = src;

  if (!tlv) {
    return NULL;
  }

  if (!otrng_deserialize_uint16(&tlv_type, cursor, len, &w)) {
    otrng_tlv_free(tlv);
    return NULL;
  }

  set_tlv_type(tlv, tlv_type);

  len -= w;
  cursor += w;

  if (!otrng_deserialize_uint16(&tlv->len, cursor, len, &w)) {
    otrng_tlv_free(tlv);
    return NULL;
  }

  len -= w;
  cursor += w;

  if (len < tlv->len) {
    otrng_tlv_free(tlv);
    return NULL;
  }

  tlv->data = otrng_xmalloc_z(tlv->len);

  memcpy(tlv->data, cursor, tlv->len);
  cursor += tlv->len;

  if (read) {
    *read = cursor - src;
  }

  return tlv;
}

INTERNAL tlv_list_s *otrng_append_tlv(tlv_list_s *head, tlv_s *tlv) {
  tlv_list_s *current;
  tlv_list_s *n = otrng_tlv_list_one(tlv);
  if (!n) {
    return NULL;
  }

  if (!head) {
    return n;
  }

  current = head;

  while (current->next) {
    current = current->next;
  }

  current->next = n;

  return head;
}

INTERNAL tlv_list_s *otrng_parse_tlvs(const uint8_t *src, size_t len) {
  tlv_list_s *ret = NULL, *tmp = NULL;
  while (len > 0) {
    size_t read = 0;
    tlv_s *tlv = parse_tlv(src, len, &read);
    if (!tlv) {
      break;
    }

    tmp = otrng_append_tlv(ret, tlv);
    if (tmp != NULL) {
      ret = tmp;
    }
    src += read;
    len -= read;
  }

  return ret;
}

INTERNAL void otrng_tlv_free(tlv_s *tlv) {
  if (!tlv) {
    return;
  }

  free(tlv->data);
  free(tlv);
}

INTERNAL void otrng_tlv_list_free(tlv_list_s *head) {
  tlv_list_s *current = head;
  while (current) {
    tlv_list_s *next = current->next;

    otrng_tlv_free(current->data);
    current->data = NULL;
    free(current);
    current = next;
  }
}

INTERNAL tlv_s *otrng_tlv_new(const uint16_t type, const uint16_t len,
                              const uint8_t *data) {
  tlv_s *tlv = otrng_xmalloc_z(sizeof(tlv_s));

  tlv->type = type;
  tlv->len = len;

  if (len != 0) {
    if (!data) {
      otrng_tlv_free(tlv);
      return NULL;
    }

    tlv->data = otrng_xmalloc_z(tlv->len);
    memcpy(tlv->data, data, tlv->len);
  }

  return tlv;
}

INTERNAL tlv_s *otrng_tlv_disconnected_new(void) {
  return otrng_tlv_new(OTRNG_TLV_DISCONNECTED, 0, NULL);
}

INTERNAL tlv_s *otrng_tlv_padding_new(size_t len) {
  uint8_t *data = otrng_xmalloc_z(len);
  tlv_s *tlv;

  tlv = otrng_tlv_new(OTRNG_TLV_PADDING, len, data);
  free(data);

  return tlv;
}

INTERNAL tlv_list_s *otrng_tlv_list_one(tlv_s *tlv) {
  tlv_list_s *tlvs;
  if (!tlv) {
    return NULL;
  }

  tlvs = otrng_xmalloc_z(sizeof(tlv_list_s));

  tlvs->data = tlv;

  return tlvs;
}

INTERNAL size_t otrng_tlv_serialize(uint8_t *destination, const tlv_s *tlv) {
  size_t w = 0;
  w += otrng_serialize_uint16(destination + w, tlv->type);
  w += otrng_serialize_uint16(destination + w, tlv->len);
  w += otrng_serialize_bytes_array(destination + w, tlv->data, tlv->len);
  return w;
}
