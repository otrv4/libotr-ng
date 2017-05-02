#include <string.h>

#include "serialize.h"
#include "b64.h"

static int
serialize_int(uint8_t * target, const uint64_t data, const int offset)
{
	int i;
	int shift = offset;

	for (i = 0; i < offset; i++) {
		shift--;
		target[i] = (data >> shift * 8) & 0xFF;
	}

	return offset;
}

int serialize_uint64(uint8_t * dst, const uint64_t data)
{
	return serialize_int(dst, data, sizeof(uint64_t));
}

int serialize_uint32(uint8_t * dst, const uint32_t data)
{
	return serialize_int(dst, data, sizeof(uint32_t));
}

int serialize_uint16(uint8_t * dst, const uint16_t data)
{
	return serialize_int(dst, data, sizeof(uint16_t));
}

int serialize_uint8(uint8_t * dst, const uint8_t data)
{
	return serialize_int(dst, data, sizeof(uint8_t));
}

int serialize_bytes_array(uint8_t * target, const uint8_t * data, int len)
{
	//this is just a memcpy thar returns the ammount copied for convenience
	memcpy(target, data, len);
	return len;
}

int serialize_data(uint8_t * dst, const uint8_t * data, int len)
{
	uint8_t *cursor = dst;

	cursor += serialize_uint32(cursor, len);
	cursor += serialize_bytes_array(cursor, data, len);

	return cursor - dst;
}

int serialize_mpi(uint8_t * dst, const otr_mpi_t mpi)
{
	return serialize_data(dst, mpi->data, mpi->len);
}

int serialize_ec_point(uint8_t * dst, const ec_point_t point)
{
	ec_point_serialize(dst, ED448_POINT_BYTES, point);
	return ED448_POINT_BYTES;
}

int serialize_ec_scalar(uint8_t * dst, const ec_scalar_t scalar)
{
	ec_scalar_serialize(dst, ED448_SCALAR_BYTES, scalar);
	return ED448_SCALAR_BYTES;
}

int serialize_dh_public_key(uint8_t * dst, const dh_public_key_t pub)
{
	//From gcrypt MPI
	uint8_t buf[DH3072_MOD_LEN_BYTES] = { 0 };
	memset(buf, 0, DH3072_MOD_LEN_BYTES);
	size_t written = dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, pub);

	//To OTR MPI
	//TODO: Maybe gcrypt MPI already has some API for this.
	//gcry_mpi_print with a different format, maybe?
	otr_mpi_t mpi;
	otr_mpi_set(mpi, buf, written);
	int s = serialize_mpi(dst, mpi);
	otr_mpi_free(mpi);
	return s;
}

int serialize_otrv4_public_key(uint8_t * dst, const otrv4_public_key_t pub)
{
	uint8_t *cursor = dst;
	cursor += serialize_uint16(cursor, ED448_PUBKEY_TYPE);
	cursor += serialize_ec_point(cursor, pub);

	return cursor - dst;
}

int serialize_snizkpk_proof(uint8_t * dst, const snizkpk_proof_t * proof)
{
	uint8_t *cursor = dst;
	cursor += serialize_ec_scalar(cursor, proof->c1);
	cursor += serialize_ec_scalar(cursor, proof->r1);
	cursor += serialize_ec_scalar(cursor, proof->c2);
	cursor += serialize_ec_scalar(cursor, proof->r2);
	cursor += serialize_ec_scalar(cursor, proof->c3);
	cursor += serialize_ec_scalar(cursor, proof->r3);

	return cursor - dst;
}

int
otrv4_symmetric_key_serialize(char **buffer, size_t * buffer_size,
			      uint8_t sym[ED448_PRIVATE_BYTES])
{
	*buffer = malloc((ED448_PRIVATE_BYTES + 2) / 3 * 4);
	if (!*buffer)
		return -1;

	*buffer_size = otrl_base64_encode(*buffer, sym, ED448_PRIVATE_BYTES);
	return 0;
}

