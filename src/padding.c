/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

#include "padding.h"
#include "alloc.h"
#include "client.h"
#include "tlv.h"

static size_t calculate_padding_len(size_t msg_len, size_t max) {
  size_t tlv_header_len = 4;

  if (max == 0) {
    return 0;
  }

  return max - ((msg_len + tlv_header_len + 1) % max);
}

INTERNAL otrng_result generate_padding(uint8_t **dst, size_t *dst_len,
                                       size_t msg_len, const otrng_s *otr) {
  tlv_s *padding_tlv;
  size_t ret;
  size_t padding_len = calculate_padding_len(msg_len, otr->client->padding);

  if (!padding_len) {
    return OTRNG_SUCCESS;
  }

  padding_tlv = otrng_tlv_padding_new(padding_len);
  if (!padding_tlv) {
    return OTRNG_ERROR;
  }

  *dst_len = padding_tlv->len + 4;
  *dst = otrng_xmalloc_z(*dst_len);

  ret = otrng_tlv_serialize(*dst, padding_tlv);
  otrng_tlv_free(padding_tlv);

  if (ret == 0) {
    return OTRNG_ERROR;
  }
  return OTRNG_SUCCESS;
}
