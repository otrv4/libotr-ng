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

#include <string.h>

#define OTRNG_SERIALIZE_PRIVATE

#include "serialize.h"

INTERNAL size_t serialize_uint(uint8_t *target, const uint64_t data,
                               const size_t offset) {
  size_t i;
  size_t shift = offset;

  for (i = 0; i < offset; i++) {
    shift--;
    target[i] = (data >> shift * 8) & 0xFF;
  }

  return offset;
}

INTERNAL size_t otrng_serialize_uint64(uint8_t *dst, const uint64_t data) {
  return serialize_uint(dst, data, sizeof(uint64_t));
}

INTERNAL size_t otrng_serialize_uint32(uint8_t *dst, const uint32_t data) {
  return serialize_uint(dst, data, sizeof(uint32_t));
}

INTERNAL size_t otrng_serialize_uint8(uint8_t *dst, const uint8_t data) {
  return serialize_uint(dst, data, sizeof(uint8_t));
}

INTERNAL size_t otrng_serialize_uint16(uint8_t *dst, const uint16_t data) {
  return serialize_uint(dst, data, sizeof(uint16_t));
}

INTERNAL size_t otrng_serialize_bytes_array(uint8_t *target,
                                            const uint8_t *data, size_t len) {
  if (!data)
    return 0;

  // this is just a memcpy thar returns the ammount copied for convenience
  memcpy(target, data, len);
  return len;
}

INTERNAL size_t otrng_serialize_data(uint8_t *dst, const uint8_t *data,
                                     size_t len) {
  uint8_t *cursor = dst;

  cursor += otrng_serialize_uint32(cursor, len);
  cursor += otrng_serialize_bytes_array(cursor, data, len);

  return cursor - dst;
}

INTERNAL size_t otrng_serialize_mpi(uint8_t *dst, const otrng_mpi_p mpi) {
  return otrng_serialize_data(dst, mpi->data, mpi->len);
}

INTERNAL int otrng_serialize_ec_point(uint8_t *dst, const ec_point_p point) {
  otrng_ec_point_encode(dst, point);
  return ED448_POINT_BYTES;
}

INTERNAL size_t otrng_serialize_ec_scalar(uint8_t *dst,
                                          const ec_scalar_p scalar) {
  otrng_ec_scalar_encode(dst, scalar);
  return ED448_SCALAR_BYTES;
}

INTERNAL otrng_err otrng_serialize_dh_public_key(uint8_t *dst, size_t *len,
                                                 const dh_public_key_p pub) {
  /* From gcrypt MPI */
  uint8_t buf[DH3072_MOD_LEN_BYTES] = {0};
  memset(buf, 0, DH3072_MOD_LEN_BYTES);
  size_t written = 0;
  otrng_err err =
      otrng_dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, &written, pub);
  if (err)
    return err;

  // To OTR MPI
  // TODO: Maybe gcrypt MPI already has some API for this.
  // gcry_mpi_print with a different format, maybe?
  otrng_mpi_p mpi;
  otrng_mpi_set(mpi, buf, written);
  *len = otrng_serialize_mpi(dst, mpi);
  otrng_mpi_free(mpi);

  return SUCCESS;
}

INTERNAL size_t otrng_serialize_otrng_public_key(uint8_t *dst,
                                                 const otrng_public_key_p pub) {
  uint8_t *cursor = dst;
  cursor += otrng_serialize_uint16(cursor, ED448_PUBKEY_TYPE);
  cursor += otrng_serialize_ec_point(cursor, pub);

  return cursor - dst;
}

INTERNAL size_t otrng_serialize_otrng_shared_prekey(
    uint8_t *dst, const otrng_shared_prekey_pub_p shared_prekey) {
  uint8_t *cursor = dst;
  cursor += otrng_serialize_uint16(cursor, ED448_SHARED_PREKEY_TYPE);
  cursor += otrng_serialize_ec_point(cursor, shared_prekey);

  return cursor - dst;
}

INTERNAL size_t otrng_serialize_ring_sig(uint8_t *dst,
                                         const ring_sig_s *proof) {
  uint8_t *cursor = dst;
  cursor += otrng_serialize_ec_scalar(cursor, proof->c1);
  cursor += otrng_serialize_ec_scalar(cursor, proof->r1);
  cursor += otrng_serialize_ec_scalar(cursor, proof->c2);
  cursor += otrng_serialize_ec_scalar(cursor, proof->r2);
  cursor += otrng_serialize_ec_scalar(cursor, proof->c3);
  cursor += otrng_serialize_ec_scalar(cursor, proof->r3);

  return cursor - dst;
}
