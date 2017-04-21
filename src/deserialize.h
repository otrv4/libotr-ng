#include "ed448.h"
#include "auth.h"

bool
deserialize_uint64(uint64_t * n, const uint8_t * buffer, size_t buflen,
		   size_t * nread);

bool
deserialize_uint32(uint32_t * n, const uint8_t * buffer, size_t buflen,
		   size_t * nread);

bool
deserialize_uint16(uint16_t * n, const uint8_t * buffer, size_t buflen,
		   size_t * nread);

bool
deserialize_uint8(uint8_t * n, const uint8_t * buffer, size_t buflen,
		  size_t * nread);

bool
deserialize_data(uint8_t ** dst, const uint8_t * buffer, size_t buflen,
		 size_t * read);

bool
deserialize_bytes_array(uint8_t * dst, size_t dstlen, const uint8_t * buffer,
			size_t buflen);

bool
deserialize_mpi_data(uint8_t * dst, const uint8_t * buffer, size_t buflen,
		     size_t * read);

bool deserialize_ec_point(ec_point_t point, const uint8_t * serialized);

bool
deserialize_otrv4_public_key(otrv4_public_key_t pub, const uint8_t * serialized,
			     size_t ser_len, size_t * read);

bool
deserialize_snizkpk_proof(snizkpk_proof_t * proof, const uint8_t * serialized,
			  size_t ser_len, size_t * read);

bool decode_b64_ec_scalar(ec_scalar_t s, const char *buff, size_t len);

bool decode_b64_ec_point(ec_point_t s, const char *buff, size_t len);
