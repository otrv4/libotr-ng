#include <string.h>

#include "deserialize.h"
#include "mpi.h"
#include "b64.h"

bool
deserialize_uint64(uint64_t * n, const uint8_t * buffer, size_t buflen,
		   size_t * nread)
{
	if (buflen < sizeof(uint64_t)) {
		return false;
	}

	*n = ((uint64_t) buffer[7]) |
	    ((uint64_t) buffer[6]) << 8 |
	    ((uint64_t) buffer[5]) << 16 |
	    ((uint64_t) buffer[4]) << 24 |
	    ((uint64_t) buffer[3]) << 32 |
	    ((uint64_t) buffer[2]) << 40 |
	    ((uint64_t) buffer[1]) << 48 | ((uint64_t) buffer[0]) << 56;

	if (nread)
		*nread = sizeof(uint64_t);

	return true;
}

bool
deserialize_uint32(uint32_t * n, const uint8_t * buffer, size_t buflen,
		   size_t * nread)
{
	if (buflen < sizeof(uint32_t)) {
		return false;
	}

	*n = buffer[3] | buffer[2] << 8 | buffer[1] << 16 | buffer[0] << 24;

	if (nread)
		*nread = sizeof(uint32_t);

	return true;
}

bool
deserialize_uint16(uint16_t * n, const uint8_t * buffer, size_t buflen,
		   size_t * nread)
{
	if (buflen < sizeof(uint16_t)) {
		return false;
	}

	*n = buffer[1] | buffer[0] << 8;

	if (nread != NULL) {
		*nread = sizeof(uint16_t);
	}
	return true;
}

bool
deserialize_uint8(uint8_t * n, const uint8_t * buffer, size_t buflen,
		  size_t * nread)
{
	if (buflen < sizeof(uint8_t)) {
		return false;
	}

	*n = buffer[0];

	if (nread != NULL) {
		*nread = sizeof(uint8_t);
	}
	return true;
}

bool
deserialize_data(uint8_t ** dst, const uint8_t * buffer, size_t buflen,
		 size_t * read)
{
	size_t r = 0;
	uint32_t s = 0;

	//4 bytes len
	if (!deserialize_uint32(&s, buffer, buflen, &r)) {
		if (read != NULL) {
			*read = r;
		}
		return false;
	}

	if (read)
		*read = r;

        if (!s)
            return true;

	buflen -= r;
	if (buflen < s)
		return false;

	uint8_t *t = malloc(s);
	if (!t)
		return false;

	memcpy(t, buffer + r, s);

	*dst = t;
	if (read)
		*read += s;

	return true;
}

bool
deserialize_bytes_array(uint8_t * dst, size_t dstlen, const uint8_t * buffer,
			size_t buflen)
{
	if (buflen < dstlen) {
		return false;
	}

	memcpy(dst, buffer, dstlen);
	return true;
}

bool
deserialize_mpi_data(uint8_t * dst, const uint8_t * buffer, size_t buflen,
		     size_t * read)
{
	otr_mpi_t mpi;		// no need to free, because nothing is copied now

	if (!otr_mpi_deserialize_no_copy(mpi, buffer, buflen, read)) {
		return false;	// only mpi len has been read
	}

	size_t r = otr_mpi_memcpy(dst, mpi);
	if (read != NULL) {
		*read += r;
	}
	return true;
}

bool deserialize_ec_point(ec_point_t point, const uint8_t * serialized)
{
	return ec_point_deserialize(point, serialized);
}

bool
deserialize_otrv4_public_key(otrv4_public_key_t pub, const uint8_t * serialized,
			     size_t ser_len, size_t * read)
{
	const uint8_t *cursor = serialized;
	size_t r = 0;
	uint16_t pubkey_type = 0;

	if (ser_len < ED448_PUBKEY_BYTES)
		return false;

	deserialize_uint16(&pubkey_type, cursor, ser_len, &r);
	cursor += r;

	if (ED448_PUBKEY_TYPE != pubkey_type)
		return false;

	if (!deserialize_ec_point(pub, cursor))
		return false;

	if (read)
		*read = ED448_PUBKEY_BYTES;

	return true;
}

// TODO: check me
bool decode_b64_ec_scalar(ec_scalar_t s, const char *buff, size_t len)
{
	//((base64len+3) / 4) * 3
	unsigned char *dec = malloc(((len + 3) / 4) * 3);
	if (!dec)
		return false;

	bool ok = false;
	do {
		size_t written = otrl_base64_decode(dec, buff, len);
		if (written != ED448_SCALAR_BYTES)
			continue;

		ok = DECAF_SUCCESS == decaf_448_scalar_decode(s, dec);
	} while (0);

	free(dec);
	return ok;
}

// XXX: check me
bool decode_b64_ec_point(ec_point_t s, const char *buff, size_t len)
{
	//((base64len+3) / 4) * 3
	unsigned char *dec = malloc(((len + 3) / 4) * 3);
	if (!dec)
		return false;

	bool ok = false;
	do {
		size_t written = otrl_base64_decode(dec, buff, len);
		if (written != ED448_POINT_BYTES)
			continue;

		ok = DECAF_SUCCESS == decaf_448_point_decode(s, dec,
							     DECAF_FALSE);
	} while (0);

	free(dec);
	return ok;
}

bool
deserialize_ec_scalar(ec_scalar_t scalar, const uint8_t * serialized,
		      size_t ser_len)
{
	if (ser_len < ED448_SCALAR_BYTES)
		return false;

	return ec_scalar_deserialize(scalar, serialized);
}

bool
deserialize_snizkpk_proof(snizkpk_proof_t * proof, const uint8_t * serialized,
			  size_t ser_len, size_t * read)
{
	if (ser_len < SNIZKPK_BYTES)
		return false;

	const uint8_t *cursor = serialized;
	if (!deserialize_ec_scalar(proof->c1, cursor, ser_len))
		return false;

	cursor += ED448_SCALAR_BYTES;
	ser_len -= ED448_SCALAR_BYTES;

	if (!deserialize_ec_scalar(proof->r1, cursor, ser_len))
		return false;

	cursor += ED448_SCALAR_BYTES;
	ser_len -= ED448_SCALAR_BYTES;

	if (!deserialize_ec_scalar(proof->c2, cursor, ser_len))
		return false;

	cursor += ED448_SCALAR_BYTES;
	ser_len -= ED448_SCALAR_BYTES;

	if (!deserialize_ec_scalar(proof->r2, cursor, ser_len))
		return false;

	cursor += ED448_SCALAR_BYTES;
	ser_len -= ED448_SCALAR_BYTES;

	if (!deserialize_ec_scalar(proof->c3, cursor, ser_len))
		return false;

	cursor += ED448_SCALAR_BYTES;
	ser_len -= ED448_SCALAR_BYTES;

	if (!deserialize_ec_scalar(proof->r3, cursor, ser_len))
		return false;

	if (read)
		*read = SNIZKPK_BYTES;

	return true;
}

int otrv4_symmetric_key_deserialize(otrv4_keypair_t * pair, const char *buff,
				    size_t len)
{
	//((base64len+3) / 4) * 3
	unsigned char *dec = malloc(((len + 3) / 4) * 3);
	if (!dec)
		return -1;

	size_t written = otrl_base64_decode(dec, buff, len);
	int err = (written != ED448_PRIVATE_BYTES);

	if (!err)
		otrv4_keypair_generate(pair, dec);

	free(dec);
	return err;
}
