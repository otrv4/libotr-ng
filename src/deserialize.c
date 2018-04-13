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

INTERNAL otrng_err otrng_deserialize_uint64(uint64_t *n, const uint8_t *buffer,
                                            size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint64_t)) {
    return ERROR;
  }

  *n = ((uint64_t)buffer[7]) | ((uint64_t)buffer[6]) << 8 |
       ((uint64_t)buffer[5]) << 16 | ((uint64_t)buffer[4]) << 24 |
       ((uint64_t)buffer[3]) << 32 | ((uint64_t)buffer[2]) << 40 |
       ((uint64_t)buffer[1]) << 48 | ((uint64_t)buffer[0]) << 56;

  if (nread)
    *nread = sizeof(uint64_t);

  return SUCCESS;
}

INTERNAL otrng_err otrng_deserialize_uint32(uint32_t *n, const uint8_t *buffer,
                                            size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint32_t)) {
    return ERROR;
  }

  *n = buffer[3] | buffer[2] << 8 | buffer[1] << 16 | buffer[0] << 24;

  if (nread)
    *nread = sizeof(uint32_t);

  return SUCCESS;
}

INTERNAL otrng_err otrng_deserialize_uint16(uint16_t *n, const uint8_t *buffer,
                                            size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint16_t)) {
    return ERROR;
  }

  *n = buffer[1] | buffer[0] << 8;

  if (nread != NULL) {
    *nread = sizeof(uint16_t);
  }
  return SUCCESS;
}

INTERNAL otrng_err otrng_deserialize_uint8(uint8_t *n, const uint8_t *buffer,
                                           size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint8_t)) {
    return ERROR;
  }

  *n = buffer[0];

  if (nread != NULL) {
    *nread = sizeof(uint8_t);
  }
  return SUCCESS;
}

INTERNAL otrng_err otrng_deserialize_data(uint8_t **dst, const uint8_t *buffer,
                                          size_t buflen, size_t *read) {
  size_t r = 0;
  uint32_t s = 0;

  /* 4 bytes len */
  if (otrng_deserialize_uint32(&s, buffer, buflen, &r)) {
    if (read != NULL)
      *read = r;

    return ERROR;
  }

  if (read)
    *read = r;

  if (!s)
    return SUCCESS;

  buflen -= r;
  if (buflen < s)
    return ERROR;

  uint8_t *t = malloc(s);
  if (!t)
    return ERROR;

  memcpy(t, buffer + r, s);

  *dst = t;
  if (read)
    *read += s;

  return SUCCESS;
}

INTERNAL otrng_err otrng_deserialize_bytes_array(uint8_t *dst, size_t dstlen,
                                                 const uint8_t *buffer,
                                                 size_t buflen) {
  if (buflen < dstlen) {
    return ERROR;
  }

  memcpy(dst, buffer, dstlen);
  return SUCCESS;
}

/* otrng_err deserialize_mpi_data(uint8_t *dst, const uint8_t *buffer, */
/*                                  size_t buflen, size_t *read) { */
/*   otrng_mpi_p mpi; // no need to free, because nothing is copied now */

/*   if (otrng_mpi_deserialize_no_copy(mpi, buffer, buflen, read)) { */
/*     return ERROR; /\* only mpi len has been read *\/ */
/*   } */

/*   size_t r = otrng_mpi_memcpy(dst, mpi); */
/*   if (read != NULL) { */
/*     *read += r; */
/*   } */
/*   return SUCCESS; */
/* } */

INTERNAL otrng_err otrng_deserialize_ec_point(ec_point_p point,
                                              const uint8_t *serialized) {
  return otrng_ec_point_decode(point, serialized);
}

INTERNAL otrng_err otrng_deserialize_otrng_public_key(otrng_public_key_p pub,
                                                      const uint8_t *serialized,
                                                      size_t ser_len,
                                                      size_t *read) {
  const uint8_t *cursor = serialized;
  size_t r = 0;
  uint16_t pubkey_type = 0;

  // TODO: prob unneccessary
  if (ser_len < ED448_PUBKEY_BYTES)
    return ERROR;

  otrng_deserialize_uint16(&pubkey_type, cursor, ser_len, &r);
  cursor += r;

  if (ED448_PUBKEY_TYPE != pubkey_type)
    return ERROR;

  if (otrng_deserialize_ec_point(pub, cursor))
    return ERROR;

  if (read)
    *read = ED448_PUBKEY_BYTES;

  return SUCCESS;
}

INTERNAL otrng_err otrng_deserialize_otrng_shared_prekey(
    otrng_shared_prekey_pub_p shared_prekey, const uint8_t *serialized,
    size_t ser_len, size_t *read) {
  const uint8_t *cursor = serialized;
  size_t r = 0;
  uint16_t shared_prekey_type = 0;

  // TODO: prob unneccessary
  if (ser_len < ED448_PUBKEY_BYTES)
    return ERROR;

  otrng_deserialize_uint16(&shared_prekey_type, cursor, ser_len, &r);
  cursor += r;

  if (ED448_SHARED_PREKEY_TYPE != shared_prekey_type)
    return ERROR;

  if (otrng_deserialize_ec_point(shared_prekey, cursor))
    return ERROR;

  if (read)
    *read = ED448_SHARED_PREKEY_BYTES;

  return SUCCESS;
}

INTERNAL otrng_err otrng_deserialize_ec_scalar(ec_scalar_p scalar,
                                               const uint8_t *serialized,
                                               size_t ser_len) {
  if (ser_len < ED448_SCALAR_BYTES)
    return ERROR;

  otrng_ec_scalar_decode(scalar, serialized);

  return SUCCESS;
}

INTERNAL otrng_err otrng_deserialize_ring_sig(ring_sig_s *proof,
                                              const uint8_t *serialized,
                                              size_t ser_len, size_t *read) {
  if (ser_len < RING_SIG_BYTES)
    return ERROR;

  const uint8_t *cursor = serialized;
  if (otrng_deserialize_ec_scalar(proof->c1, cursor, ser_len))
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(proof->r1, cursor, ser_len))
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(proof->c2, cursor, ser_len))
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(proof->r2, cursor, ser_len))
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(proof->c3, cursor, ser_len))
    return ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (otrng_deserialize_ec_scalar(proof->r3, cursor, ser_len))
    return ERROR;

  if (read)
    *read = RING_SIG_BYTES;

  return SUCCESS;
}

INTERNAL otrng_err otrng_symmetric_key_deserialize(otrng_keypair_s *pair,
                                                   const char *buff,
                                                   size_t len) {
  otrng_err err = ERROR;

  /* (((base64len+3) / 4) * 3) */
  unsigned char *dec = malloc(((len + 3) / 4) * 3);
  if (!dec)
    return err;

  size_t written = otrl_base64_decode(dec, buff, len);

  if (written == ED448_PRIVATE_BYTES) {
    err = SUCCESS;
  }

  if (err == SUCCESS)
    otrng_keypair_generate(pair, dec);

  free(dec);
  dec = NULL;
  return err;
}
