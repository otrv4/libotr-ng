#include <string.h>

#define OTRV4_SERIALIZE_PRIVATE

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

INTERNAL size_t serialize_uint64(uint8_t *dst, const uint64_t data) {
  return serialize_uint(dst, data, sizeof(uint64_t));
}

INTERNAL size_t serialize_uint32(uint8_t *dst, const uint32_t data) {
  return serialize_uint(dst, data, sizeof(uint32_t));
}

INTERNAL size_t serialize_uint8(uint8_t *dst, const uint8_t data) {
  return serialize_uint(dst, data, sizeof(uint8_t));
}

INTERNAL size_t serialize_uint16(uint8_t *dst, const uint16_t data) {
  return serialize_uint(dst, data, sizeof(uint16_t));
}

INTERNAL size_t serialize_bytes_array(uint8_t *target, const uint8_t *data, size_t len) {
  if (!data)
    return 0;

  // this is just a memcpy thar returns the ammount copied for convenience
  memcpy(target, data, len);
  return len;
}

INTERNAL size_t serialize_data(uint8_t *dst, const uint8_t *data, size_t len) {
  uint8_t *cursor = dst;

  cursor += serialize_uint32(cursor, len);
  cursor += serialize_bytes_array(cursor, data, len);

  return cursor - dst;
}

INTERNAL size_t serialize_mpi(uint8_t *dst, const otr_mpi_t mpi) {
  return serialize_data(dst, mpi->data, mpi->len);
}

INTERNAL int serialize_ec_point(uint8_t *dst, const ec_point_t point) {
  ec_point_serialize(dst, point);
  return ED448_POINT_BYTES;
}

INTERNAL size_t serialize_ec_scalar(uint8_t *dst, const ec_scalar_t scalar) {
  if (ec_scalar_serialize(dst, ED448_SCALAR_BYTES, scalar))
    return 0;

  return ED448_SCALAR_BYTES;
}

INTERNAL otrv4_err_t serialize_dh_public_key(uint8_t *dst, size_t *len,
                                    const dh_public_key_t pub) {
  /* From gcrypt MPI */
  uint8_t buf[DH3072_MOD_LEN_BYTES] = {0};
  memset(buf, 0, DH3072_MOD_LEN_BYTES);
  size_t written = 0;
  otrv4_err_t err = dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, &written, pub);
  if (err)
    return err;

  // To OTR MPI
  // TODO: Maybe gcrypt MPI already has some API for this.
  // gcry_mpi_print with a different format, maybe?
  otr_mpi_t mpi;
  otr_mpi_set(mpi, buf, written);
  *len = serialize_mpi(dst, mpi);
  otr_mpi_free(mpi);

  return SUCCESS;
}

INTERNAL size_t serialize_otrv4_public_key(uint8_t *dst, const otrv4_public_key_t pub) {
  uint8_t *cursor = dst;
  cursor += serialize_uint16(cursor, ED448_PUBKEY_TYPE);
  cursor += serialize_ec_point(cursor, pub);

  return cursor - dst;
}

INTERNAL size_t
serialize_otrv4_shared_prekey(uint8_t *dst,
                              const otrv4_shared_prekey_pub_t shared_prekey) {
  uint8_t *cursor = dst;
  cursor += serialize_uint16(cursor, ED448_SHARED_PREKEY_TYPE);
  cursor += serialize_ec_point(cursor, shared_prekey);

  return cursor - dst;
}

INTERNAL size_t serialize_snizkpk_proof(uint8_t *dst, const snizkpk_proof_t *proof) {
  uint8_t *cursor = dst;
  cursor += serialize_ec_scalar(cursor, proof->c1);
  cursor += serialize_ec_scalar(cursor, proof->r1);
  cursor += serialize_ec_scalar(cursor, proof->c2);
  cursor += serialize_ec_scalar(cursor, proof->r2);
  cursor += serialize_ec_scalar(cursor, proof->c3);
  cursor += serialize_ec_scalar(cursor, proof->r3);

  return cursor - dst;
}
