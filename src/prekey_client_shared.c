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

#include <assert.h>

#include "deserialize.h"
#include "prekey_client_shared.h"
#include "serialize.h"

INTERNAL otrng_result otrng_prekey_parse_header(uint8_t *msg_type,
                                                const uint8_t *buf,
                                                size_t buflen,
                                                /*@null@*/ size_t *read) {
  size_t r = 0; /* read */
  size_t w = 0; /* walked */

  uint16_t protocol_version = 0;

  if (!otrng_deserialize_uint16(&protocol_version, buf, buflen, &r)) {
    return OTRNG_ERROR;
  }

  w += r;

  if (protocol_version != OTRNG_PROTOCOL_VERSION_4) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint8(msg_type, buf + w, buflen - w, &r)) {
    return OTRNG_ERROR;
  }

  w += r;

  if (read) {
    *read = w;
  }

  return OTRNG_SUCCESS;
}

INTERNAL uint8_t *otrng_prekey_client_get_expected_composite_phi(
    size_t *len, const xyz_otrng_prekey_client_s *client) {
  uint8_t *dst = NULL;
  size_t size, w = 0;

  if (!client->server_identity || !client->our_identity) {
    return NULL;
  }

  size = 4 + strlen(client->server_identity) + 4 + strlen(client->our_identity);
  dst = otrng_xmalloc(size);

  w += otrng_serialize_data(dst + w, (const uint8_t *)client->our_identity,
                            strlen(client->our_identity));
  if (otrng_serialize_data(dst + w, (const uint8_t *)client->server_identity,
                           strlen(client->server_identity)) == 0) {
    otrng_free(dst);
    return NULL;
  }

  if (len) {
    *len = size;
  }

  return dst;
}
