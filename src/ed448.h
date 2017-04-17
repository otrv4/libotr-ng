#ifndef ED448_H
#define ED448_H

#include <stdbool.h>
#include <stdint.h>
#include <libdecaf/decaf_crypto.h>

#define EC_SIGNATURE_BYTES DECAF_448_SER_BYTES + DECAF_448_SCALAR_BYTES

typedef decaf_448_private_key_t ec_keypair_t;
typedef decaf_448_public_key_t ec_public_key_t;
typedef decaf_448_signature_t ec_signature_t;
typedef decaf_448_scalar_t ec_scalar_t;
typedef decaf_448_point_t ec_point_t;
typedef decaf_448_symmetric_key_t ec_symmetric_key_t;

bool ec_scalar_eq(const ec_scalar_t a, const ec_scalar_t b);

void ec_point_copy(ec_point_t dst, const ec_point_t src);

void ec_keypair_generate(ec_keypair_t keypair);

void ec_keypair_destroy(ec_keypair_t keypair);

bool
ecdh_shared_secret(uint8_t * shared,
		   size_t shared_bytes,
		   const ec_keypair_t our_priv, const ec_public_key_t their_pub);

bool
ec_public_key_serialize(uint8_t * dst, size_t dst_bytes,
			const ec_public_key_t pub);

void
ec_public_key_copy(ec_public_key_t dst, const ec_public_key_t src);

void
ec_point_serialize(uint8_t * dst, size_t dst_len, const ec_point_t point);

void
ec_scalar_serialize(uint8_t * dst, size_t dst_len, const ec_scalar_t scalar);

bool
ec_scalar_deserialize(ec_scalar_t scalar,
		      const uint8_t serialized[DECAF_448_SCALAR_BYTES]);

bool
ec_point_deserialize(ec_point_t point,
		     const uint8_t serialized[DECAF_448_SER_BYTES]);

void
ec_sign(ec_signature_t dst, const ec_keypair_t keypair, const uint8_t * msg,
	size_t msg_len);

bool
ec_verify(const ec_signature_t sig, const ec_public_key_t pub,
	  const uint8_t * msg, size_t msg_len);

void ec_scalar_copy(ec_scalar_t dst, const ec_scalar_t src);

void ec_scalar_destroy(ec_scalar_t dst);

bool ec_point_valid(ec_point_t point);

#endif
