#ifndef OTRV4_DESERIALIZE_H
#define OTRV4_DESERIALIZE_H

#include "shared.h"
#include "auth.h"
#include "ed448.h"
#include "error.h"

INTERNAL otrv4_err_t deserialize_uint64(uint64_t *n, const uint8_t *buffer,
                               size_t buflen, size_t *nread);

INTERNAL otrv4_err_t deserialize_uint32(uint32_t *n, const uint8_t *buffer,
                               size_t buflen, size_t *nread);

INTERNAL otrv4_err_t deserialize_uint16(uint16_t *n, const uint8_t *buffer,
                               size_t buflen, size_t *nread);

INTERNAL otrv4_err_t deserialize_uint8(uint8_t *n, const uint8_t *buffer, size_t buflen,
                              size_t *nread);

INTERNAL otrv4_err_t deserialize_data(uint8_t **dst, const uint8_t *buffer,
                             size_t buflen, size_t *read);

INTERNAL otrv4_err_t deserialize_bytes_array(uint8_t *dst, size_t dstlen,
                                    const uint8_t *buffer, size_t buflen);

/* otrv4_err_t deserialize_mpi_data(uint8_t *dst, const uint8_t *buffer, */
/*                                  size_t buflen, size_t *read); */

INTERNAL otrv4_err_t deserialize_ec_point(ec_point_t point, const uint8_t *serialized);

INTERNAL otrv4_err_t deserialize_otrv4_public_key(otrv4_public_key_t pub,
                                         const uint8_t *serialized,
                                         size_t ser_len, size_t *read);

INTERNAL otrv4_err_t
deserialize_otrv4_shared_prekey(otrv4_shared_prekey_pub_t shared_prekey,
                                const uint8_t *serialized, size_t ser_len,
                                size_t *read);

INTERNAL otrv4_err_t deserialize_ec_scalar(ec_scalar_t scalar, const uint8_t *serialized,
                                  size_t ser_len);

INTERNAL otrv4_err_t deserialize_snizkpk_proof(snizkpk_proof_t *proof,
                                      const uint8_t *serialized, size_t ser_len,
                                      size_t *read);

INTERNAL otrv4_err_t otrv4_symmetric_key_deserialize(otrv4_keypair_t *pair,
                                            const char *buff, size_t len);


#ifdef OTRV4_DESERIALIZE_PRIVATE
#endif

#endif
