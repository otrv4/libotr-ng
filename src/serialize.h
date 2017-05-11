#ifndef SERIALIZE_H
#define SERIALIZE_H

#include <stdint.h>

#include "dh.h"
#include "ed448.h"
#include "mpi.h"
#include "auth.h"

#define CRAMER_SHOUP_PUBKEY_BYTES 170

size_t serialize_uint64(uint8_t * dst, const uint64_t data);

size_t serialize_uint32(uint8_t * dst, const uint32_t data);

size_t serialize_uint16(uint8_t * dst, const uint16_t data);

size_t serialize_uint8(uint8_t * dst, const uint8_t data);

size_t serialize_bytes_array(uint8_t * target, const uint8_t data[], size_t len);

size_t serialize_data(uint8_t * target, const uint8_t * data, size_t len);

size_t serialize_mpi(uint8_t * dst, const otr_mpi_t mpi);

bool serialize_ec_point(uint8_t * dst, const ec_point_t point);

size_t serialize_ec_scalar(uint8_t * dst, const ec_scalar_t scalar);

gcry_error_t serialize_dh_public_key(uint8_t * dst, size_t * len,
				   const dh_public_key_t pub);

size_t serialize_snizkpk_proof(uint8_t * dst, const snizkpk_proof_t * proof);

size_t serialize_otrv4_public_key(uint8_t * dst, const otrv4_public_key_t);

#endif
