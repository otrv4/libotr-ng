#include "ed448.h"
#include "random.h"

bool ec_scalar_eq(const ec_scalar_t a, const ec_scalar_t b)
{
	return DECAF_TRUE == decaf_448_scalar_eq(a, b);
}

void ec_point_copy(ec_point_t dst, const ec_point_t src)
{
	decaf_448_point_copy(dst, src);
}

void ec_keypair_generate(ec_keypair_t keypair)
{
	random_bytes(keypair->sym, DECAF_448_SYMMETRIC_KEY_BYTES);
	decaf_448_derive_private_key(keypair, keypair->sym);
}

void ec_keypair_destroy(ec_keypair_t keypair)
{
	decaf_448_destroy_private_key(keypair);
}

bool
ecdh_shared_secret(uint8_t * shared,
		   size_t shared_bytes,
		   const ec_keypair_t our_priv, const ec_public_key_t their_pub)
{
	if (!decaf_448_shared_secret(shared, shared_bytes, our_priv, their_pub)) {
		return false;
	}

	return true;
}

bool
ec_public_key_serialize(uint8_t * dst, size_t dst_bytes,
			const ec_public_key_t pub)
{
	if (sizeof(ec_public_key_t) > dst_bytes) {
		return false;
	}

	memcpy(dst, pub, sizeof(ec_public_key_t));
	return true;
}

void
ec_public_key_copy(ec_public_key_t dst, const ec_public_key_t src)
{
	memcpy(dst, src, sizeof(ec_public_key_t));
}

void
ec_point_serialize(uint8_t * dst, size_t dst_len, const ec_point_t point)
{
	//TODO: error
	decaf_448_point_encode(dst, point);
}

void
ec_scalar_serialize(uint8_t * dst, size_t dst_len, const ec_scalar_t scalar)
{
	//TODO: error
	decaf_448_scalar_encode(dst, scalar);
}

bool
ec_scalar_deserialize(ec_scalar_t scalar,
		      const uint8_t serialized[DECAF_448_SCALAR_BYTES])
{
	return DECAF_SUCCESS == decaf_448_scalar_decode(scalar, serialized);
}

bool
ec_point_deserialize(ec_point_t point,
		     const uint8_t serialized[DECAF_448_SER_BYTES])
{
	if (DECAF_TRUE !=
	    decaf_448_point_decode(point, serialized, DECAF_FALSE)) {
		return false;
	}

	return true;
}

void
ec_sign(ec_signature_t dst, const ec_keypair_t keypair, const uint8_t * msg,
	size_t msg_len)
{
	decaf_448_sign(dst, keypair, msg, msg_len);
}

bool
ec_verify(const ec_signature_t sig, const ec_public_key_t pub,
	  const uint8_t * msg, size_t msg_len)
{
	if (DECAF_TRUE == decaf_448_verify(sig, pub, msg, msg_len)) {
		return true;
	}

	return false;
}

void ec_scalar_copy(ec_scalar_t dst, const ec_scalar_t src)
{
	decaf_448_scalar_copy(dst, src);
}

void ec_scalar_destroy(ec_scalar_t dst)
{
	decaf_448_scalar_destroy(dst);
}

bool ec_point_valid(ec_point_t point)
{
	if (DECAF_TRUE == decaf_448_point_valid(point)) {
		return true;
	}

	return false;
}
