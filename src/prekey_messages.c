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

#include "prekey_messages.h"
#include "prekey_client.h"

#include "deserialize.h"

INTERNAL otrng_result otrng_prekey_success_message_deserialize(
    otrng_prekey_success_message_s *dst, const uint8_t *src, size_t src_len) {
  const uint8_t *cursor = src;
  int64_t len = src_len;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if (!otrng_deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (protocol_version != OTRNG_PROTOCOL_VERSION_4) {
    return OTRNG_ERROR;
  }

  uint8_t message_type = 0;
  if (!otrng_deserialize_uint8(&message_type, cursor, len, &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  if (message_type != OTRNG_PREKEY_SUCCESS_MSG) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint32(&dst->client_instance_tag, cursor, len,
                                &read)) {
    return OTRNG_ERROR;
  }

  cursor += read;
  len -= read;

  return otrng_deserialize_bytes_array(dst->success_mac, HASH_BYTES, cursor,
                                       len);
}
