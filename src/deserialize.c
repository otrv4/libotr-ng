#include <string.h>
#include <libotr/b64.h>

#include "deserialize.h"
#include "mpi.h"

INTERNAL otrv4_err_t deserialize_uint64(uint64_t *n, const uint8_t *buffer,
                               size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint64_t)) {
    return OTR4_ERROR;
  }

  *n = ((uint64_t)buffer[7]) | ((uint64_t)buffer[6]) << 8 |
       ((uint64_t)buffer[5]) << 16 | ((uint64_t)buffer[4]) << 24 |
       ((uint64_t)buffer[3]) << 32 | ((uint64_t)buffer[2]) << 40 |
       ((uint64_t)buffer[1]) << 48 | ((uint64_t)buffer[0]) << 56;

  if (nread)
    *nread = sizeof(uint64_t);

  return OTR4_SUCCESS;
}

INTERNAL otrv4_err_t deserialize_uint32(uint32_t *n, const uint8_t *buffer,
                               size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint32_t)) {
    return OTR4_ERROR;
  }

  *n = buffer[3] | buffer[2] << 8 | buffer[1] << 16 | buffer[0] << 24;

  if (nread)
    *nread = sizeof(uint32_t);

  return OTR4_SUCCESS;
}

INTERNAL otrv4_err_t deserialize_uint16(uint16_t *n, const uint8_t *buffer,
                               size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint16_t)) {
    return OTR4_ERROR;
  }

  *n = buffer[1] | buffer[0] << 8;

  if (nread != NULL) {
    *nread = sizeof(uint16_t);
  }
  return OTR4_SUCCESS;
}

INTERNAL otrv4_err_t deserialize_uint8(uint8_t *n, const uint8_t *buffer, size_t buflen,
                              size_t *nread) {
  if (buflen < sizeof(uint8_t)) {
    return OTR4_ERROR;
  }

  *n = buffer[0];

  if (nread != NULL) {
    *nread = sizeof(uint8_t);
  }
  return OTR4_SUCCESS;
}

INTERNAL otrv4_err_t deserialize_data(uint8_t **dst, const uint8_t *buffer,
                             size_t buflen, size_t *read) {
  size_t r = 0;
  uint32_t s = 0;

  /* 4 bytes len */
  if (deserialize_uint32(&s, buffer, buflen, &r)) {
    if (read != NULL)
      *read = r;

    return OTR4_ERROR;
  }

  if (read)
    *read = r;

  if (!s)
    return OTR4_SUCCESS;

  buflen -= r;
  if (buflen < s)
    return OTR4_ERROR;

  uint8_t *t = malloc(s);
  if (!t)
    return OTR4_ERROR;

  memcpy(t, buffer + r, s);

  *dst = t;
  if (read)
    *read += s;

  return OTR4_SUCCESS;
}

INTERNAL otrv4_err_t deserialize_bytes_array(uint8_t *dst, size_t dstlen,
                                    const uint8_t *buffer, size_t buflen) {
  if (buflen < dstlen) {
    return OTR4_ERROR;
  }

  memcpy(dst, buffer, dstlen);
  return OTR4_SUCCESS;
}

/* otrv4_err_t deserialize_mpi_data(uint8_t *dst, const uint8_t *buffer, */
/*                                  size_t buflen, size_t *read) { */
/*   otr_mpi_t mpi; // no need to free, because nothing is copied now */

/*   if (otr_mpi_deserialize_no_copy(mpi, buffer, buflen, read)) { */
/*     return OTR4_ERROR; /\* only mpi len has been read *\/ */
/*   } */

/*   size_t r = otr_mpi_memcpy(dst, mpi); */
/*   if (read != NULL) { */
/*     *read += r; */
/*   } */
/*   return OTR4_SUCCESS; */
/* } */

INTERNAL otrv4_err_t deserialize_ec_point(ec_point_t point, const uint8_t *serialized) {
  return ec_point_deserialize(point, serialized);
}

INTERNAL otrv4_err_t deserialize_otrv4_public_key(otrv4_public_key_t pub,
                                         const uint8_t *serialized,
                                         size_t ser_len, size_t *read) {
  const uint8_t *cursor = serialized;
  size_t r = 0;
  uint16_t pubkey_type = 0;

  // TODO: prob unneccessary
  if (ser_len < ED448_PUBKEY_BYTES)
    return OTR4_ERROR;

  deserialize_uint16(&pubkey_type, cursor, ser_len, &r);
  cursor += r;

  if (ED448_PUBKEY_TYPE != pubkey_type)
    return OTR4_ERROR;

  if (deserialize_ec_point(pub, cursor))
    return OTR4_ERROR;

  if (read)
    *read = ED448_PUBKEY_BYTES;

  return OTR4_SUCCESS;
}

INTERNAL otrv4_err_t
deserialize_otrv4_shared_prekey(otrv4_shared_prekey_pub_t shared_prekey,
                                const uint8_t *serialized, size_t ser_len,
                                size_t *read) {
  const uint8_t *cursor = serialized;
  size_t r = 0;
  uint16_t shared_prekey_type = 0;

  // TODO: prob unneccessary
  if (ser_len < ED448_PUBKEY_BYTES)
    return OTR4_ERROR;

  deserialize_uint16(&shared_prekey_type, cursor, ser_len, &r);
  cursor += r;

  if (ED448_SHARED_PREKEY_TYPE != shared_prekey_type)
    return OTR4_ERROR;

  if (deserialize_ec_point(shared_prekey, cursor))
    return OTR4_ERROR;

  if (read)
    *read = ED448_SHARED_PREKEY_BYTES;

  return OTR4_SUCCESS;
}

// TODO: check if return is necessesary
INTERNAL otrv4_err_t deserialize_ec_scalar(ec_scalar_t scalar, const uint8_t *serialized,
                                  size_t ser_len) {
  if (ser_len < ED448_SCALAR_BYTES)
    return OTR4_ERROR;

  ec_scalar_deserialize(scalar, serialized);

  return OTR4_SUCCESS;
}

INTERNAL otrv4_err_t deserialize_snizkpk_proof(snizkpk_proof_t *proof,
                                      const uint8_t *serialized, size_t ser_len,
                                      size_t *read) {
  if (ser_len < SNIZKPK_BYTES)
    return OTR4_ERROR;

  const uint8_t *cursor = serialized;
  if (deserialize_ec_scalar(proof->c1, cursor, ser_len))
    return OTR4_ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (deserialize_ec_scalar(proof->r1, cursor, ser_len))
    return OTR4_ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (deserialize_ec_scalar(proof->c2, cursor, ser_len))
    return OTR4_ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (deserialize_ec_scalar(proof->r2, cursor, ser_len))
    return OTR4_ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (deserialize_ec_scalar(proof->c3, cursor, ser_len))
    return OTR4_ERROR;

  cursor += ED448_SCALAR_BYTES;
  ser_len -= ED448_SCALAR_BYTES;

  if (deserialize_ec_scalar(proof->r3, cursor, ser_len))
    return OTR4_ERROR;

  if (read)
    *read = SNIZKPK_BYTES;

  return OTR4_SUCCESS;
}

INTERNAL otrv4_err_t otrv4_symmetric_key_deserialize(otrv4_keypair_t *pair,
                                            const char *buff, size_t len) {
  otrv4_err_t err = OTR4_ERROR;

  /* (((base64len+3) / 4) * 3) */
  unsigned char *dec = malloc(((len + 3) / 4) * 3);
  if (!dec)
    return err;

  size_t written = otrl_base64_decode(dec, buff, len);

  if (written == ED448_PRIVATE_BYTES) {
    err = OTR4_SUCCESS;
  }

  if (err == OTR4_SUCCESS)
    otrv4_keypair_generate(pair, dec);

  free(dec);
  dec = NULL;
  return err;
}
