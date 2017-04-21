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

void ec_point_destroy(ec_point_t dst)
{
	decaf_448_point_destroy(dst);
}

void ecdh_keypair_generate(ecdh_keypair_t *keypair, uint8_t sym[ED448_PRIVATE_BYTES])
{
    ec_scalar_derive_from_secret(keypair->priv, sym);

    uint8_t pub[ED448_POINT_BYTES];
    ec_derive_public_key(pub, sym);
    ec_point_deserialize(keypair->pub, pub);

    decaf_bzero(pub, ED448_POINT_BYTES);
}

void ecdh_keypair_destroy(ecdh_keypair_t *keypair)
{
    ec_scalar_destroy(keypair->priv);
    ec_point_destroy(keypair->pub);
}

void ec_scalar_derive_from_secret(ec_scalar_t s, uint8_t secret[ED448_PRIVATE_BYTES])
{
    //Hash and clamp the secret into a scalar
    decaf_ed448_derive_secret_scalar(s, secret);
}

void ec_derive_public_key(uint8_t pub[ED448_POINT_BYTES], const uint8_t sym[ED448_PRIVATE_BYTES])
{
    decaf_ed448_derive_public_key(pub, sym);
}

bool
ecdh_shared_secret(uint8_t * shared,
		   size_t shared_bytes,
		   const ecdh_keypair_t *our_priv, const ec_point_t their_pub)
{
    decaf_448_point_t s;
    decaf_448_point_scalarmul(s, their_pub, our_priv->priv);
    return ec_point_serialize(shared, shared_bytes, s);
}

void
ec_public_key_copy(ec_public_key_t dst, const ec_public_key_t src)
{
	memcpy(dst, src, sizeof(ec_public_key_t));
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
ec_point_serialize(uint8_t * dst, size_t dst_len, const ec_point_t point)
{
    if (dst_len < ED448_POINT_BYTES)
        return false;

    decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(dst, point);

    return true;
}

bool
ec_point_deserialize(ec_point_t point,
		     const uint8_t serialized[ED448_POINT_BYTES])
{
    decaf_448_point_t p;
    decaf_error_t err = decaf_448_point_decode_like_eddsa_and_ignore_cofactor(p, serialized);
    if (DECAF_SUCCESS != err)
        return false;

    //The decoded point is equal to the original point * 2^2
    decaf_448_scalar_t r;
    decaf_448_scalar_copy(r, decaf_448_scalar_one);
    decaf_448_scalar_halve(r, r);
    decaf_448_scalar_halve(r, r);

    decaf_448_point_scalarmul(point, p, r);

    return true;
}

static const char *ctx = "OTRv4_profile_signature";

void
ec_sign(eddsa_signature_t dst,
    uint8_t sym[ED448_PRIVATE_BYTES],
    uint8_t pubkey[ED448_POINT_BYTES],
    const uint8_t * msg, size_t msg_len)
{
    decaf_ed448_sign(dst, sym, pubkey, msg, msg_len, 0, (uint8_t*)ctx, strlen(ctx));
}

bool
ec_verify(const eddsa_signature_t sig, const ec_public_key_t pub,
	  const uint8_t * msg, size_t msg_len)
{
	//if (DECAF_TRUE == decaf_448_verify(sig, pub, msg, msg_len)) {
	//	return true;
	//}

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

bool ec_point_valid(const ec_point_t point)
{
	if (DECAF_TRUE == decaf_448_point_valid(point)) {
		return true;
	}

	return false;
}

bool ec_point_eq(const ec_point_t p, const ec_point_t q)
{
    return DECAF_TRUE == decaf_448_point_eq(p, q);
}
