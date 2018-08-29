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

#include <libotr/b64.h>
#include <string.h>

#define OTRNG_DESERIALIZE_PRIVATE

#include "deserialize.h"
#include "mpi.h"

INTERNAL otrng_result otrng_deserialize_uint64(uint64_t *n, const uint8_t *buffer,
                                            size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint64_t)) {
    return OTRNG_ERROR;
  }

  *n = ((uint64_t)buffer[7]) | ((uint64_t)buffer[6]) << 8 |
       ((uint64_t)buffer[5]) << 16 | ((uint64_t)buffer[4]) << 24 |
       ((uint64_t)buffer[3]) << 32 | ((uint64_t)buffer[2]) << 40 |
       ((uint64_t)buffer[1]) << 48 | ((uint64_t)buffer[0]) << 56;

  if (nread) {
    *nread = sizeof(uint64_t);
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_deserialize_uint32(uint32_t *n, const uint8_t *buffer,
                                            size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint32_t)) {
    return OTRNG_ERROR;
  }

  *n = buffer[3] | buffer[2] << 8 | buffer[1] << 16 | buffer[0] << 24;

  if (nread) {
    *nread = sizeof(uint32_t);
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_deserialize_uint16(uint16_t *n, const uint8_t *buffer,
                                            size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint16_t)) {
    return OTRNG_ERROR;
  }

  *n = buffer[1] | buffer[0] << 8;

  if (nread != NULL) {
    *nread = sizeof(uint16_t);
  }
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_deserialize_uint8(uint8_t *n, const uint8_t *buffer,
                                           size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint8_t)) {
    return OTRNG_ERROR;
  }

  *n = buffer[0];

  if (nread != NULL) {
    *nread = sizeof(uint8_t);
  }
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_deserialize_data(uint8_t **dst, size_t *dstlen,
                                          const uint8_t *buffer, size_t buflen,
                                          size_t *read) {
  size_t r = 0;
  uint32_t s = 0;

  /* 4 bytes len */
  if (!otrng_deserialize_uint32(&s, buffer, buflen, &r)) {
    if (read != NULL) {
      *read = r;
    }

    return OTRNG_ERROR;
  }

  if (read) {
    *read = r;
  }

  if (!s) {
    return OTRNG_SUCCESS;
  }

  buflen -= r;
  if (buflen < s) {
    return OTRNG_ERROR;
  }

  uint8_t *t = malloc(s);
  if (!t) {
    return OTRNG_ERROR;
  }

  memcpy(t, buffer + r, s);

  *dst = t;
  if (read) {
    *read += s;
  }

  if (dstlen) {
    *dstlen = s;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_deserialize_bytes_array(uint8_t *dst, size_t dstlen,
                                                 const uint8_t *buffer,
                                                 size_t buflen) {
  if (buflen < dstlen) {
    return OTRNG_ERROR;
  }

  memcpy(dst, buffer, dstlen);
  return OTRNG_SUCCESS;
}

otrng_result otrng_deserialize_dh_mpi_otr(dh_mpi_p *dst, const uint8_t *buffer,
                                       size_t buflen, size_t *read) {
  otrng_mpi_p mpi; // no need to free, because nothing is copied now

  if (!otrng_mpi_deserialize_no_copy(mpi, buffer, buflen, NULL)) {
    return OTRNG_ERROR;
  }

  size_t w = 0;
  otrng_result ret = otrng_dh_mpi_deserialize(dst, mpi->data, mpi->len, &w);

  if (read) {
    *read = w + 4;
  }

  return ret;
}

INTERNAL otrng_result otrng_deserialize_ec_point(ec_point_p point,
                                              const uint8_t *serialized,
                                              size_t buflen) {
  if (buflen < ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  return otrng_ec_point_decode(point, serialized);
}

INTERNAL otrng_result otrng_deserialize_public_key(otrng_public_key_p pub,
                                                const uint8_t *serialized,
                                                size_t ser_len, size_t *read) {
  const uint8_t *cursor = serialized;
  size_t r = 0;
  uint16_t pubkey_type = 0;

  if (ser_len < ED448_PUBKEY_BYTES) {
    return OTRNG_ERROR;
  }

  otrng_deserialize_uint16(&pubkey_type, cursor, ser_len, &r);
  cursor += r;
  ser_len -= r;

  if (ED448_PUBKEY_TYPE != pubkey_type) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_ec_point(pub, cursor, ser_len)) {
    return OTRNG_ERROR;
  }

  if (read) {
    *read = ED448_PUBKEY_BYTES;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_deserialize_shared_prekey(
    otrng_shared_prekey_pub_p shared_prekey, const uint8_t *serialized,
    size_t ser_len, size_t *read) {
  const uint8_t *cursor = serialized;
  size_t r = 0;
  uint16_t shared_prekey_type = 0;

  // TODO: @refactoring prob unneccessary
  if (ser_len < ED448_PUBKEY_BYTES) {
    return OTRNG_ERROR;
  }

  otrng_deserialize_uint16(&shared_prekey_type, cursor, ser_len, &r);
  cursor += r;
  ser_len -= r;

  if (ED448_SHARED_PREKEY_TYPE != shared_prekey_type) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_ec_point(shared_prekey, cursor, ser_len)) {
    return OTRNG_ERROR;
  }

  if (read) {
    *read = ED448_SHARED_PREKEY_BYTES;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_deserialize_ec_scalar(ec_scalar_p scalar,
                                               const uint8_t *serialized,
                                               size_t ser_len) {
  if (ser_len < ED448_SCALAR_BYTES) {
    return OTRNG_ERROR;
  }

  otrng_ec_scalar_decode(scalar, serialized);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_deserialize_ring_sig(ring_sig_s *proof,
                                              const uint8_t *serialized,
                                              size_t ser_len, size_t *read) {
  if (ser_len < RING_SIG_BYTES) {
    return OTRNG_ERROR;
  }

  const uint8_t *cursor = serialized;

  if (!otrng_deserialize_ec_scalar(proof->c1, cursor, ser_len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(proof->r1, cursor, ser_len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(proof->c2, cursor, ser_len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(proof->r2, cursor, ser_len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(proof->c3, cursor, ser_len)) {
    return OTRNG_ERROR;
  }

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (!otrng_deserialize_ec_scalar(proof->r3, cursor, ser_len)) {
    return OTRNG_ERROR;
  }

  if (read) {
    *read = RING_SIG_BYTES;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_symmetric_key_deserialize(otrng_keypair_s *pair,
                                                   const char *buff,
                                                   size_t len) {
  /* (((base64len+3) / 4) * 3) */
  unsigned char *dec = malloc(((len + 3) / 4) * 3);
  if (!dec) {
    return OTRNG_ERROR;
  }

  size_t written = otrl_base64_decode(dec, buff, len);

  if (written == ED448_PRIVATE_BYTES) {
    otrng_keypair_generate(pair, dec);
    free(dec);
    return OTRNG_SUCCESS;
  }

  free(dec);
  return OTRNG_ERROR;
}
