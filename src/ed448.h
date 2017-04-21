#ifndef ED448_H
#define ED448_H

#include <stdbool.h>
#include <stdint.h>
#include <decaf.h>
#include <decaf/ed448.h>

// ATTENTION, PLEASE! decaf_448_point_t is in the twisted ed448-goldilocks.
typedef decaf_448_scalar_t ec_scalar_t;
typedef decaf_448_point_t ec_point_t;

// We have decided to serialize points and scalars using EdDSA wire format.
#define ED448_POINT_BYTES DECAF_EDDSA_448_PUBLIC_BYTES
#define ED448_SCALAR_BYTES DECAF_448_SCALAR_BYTES
#define ED448_PRIVATE_BYTES DECAF_EDDSA_448_PRIVATE_BYTES

//decaf_448_point_mul_by_cofactor_and_encode_like_eddsa

#define EC_SIGNATURE_BYTES ED448_POINT_BYTES + DECAF_448_SCALAR_BYTES
#define DECAF_448_SYMMETRIC_KEY_BYTES 32

typedef uint8_t decaf_448_symmetric_key_t[DECAF_448_SYMMETRIC_KEY_BYTES];
typedef uint8_t decaf_448_public_key_t[ED448_POINT_BYTES];
typedef uint8_t eddsa_signature_t[DECAF_EDDSA_448_SIGNATURE_BYTES];

//ECDH keypair
typedef struct {
	ec_scalar_t priv;
	ec_point_t pub;
} ecdh_keypair_t;

typedef decaf_448_public_key_t ec_public_key_t;
typedef decaf_448_symmetric_key_t ec_symmetric_key_t;

bool ec_scalar_eq(const ec_scalar_t a, const ec_scalar_t b);

void
ec_scalar_serialize(uint8_t * dst, size_t dst_len, const ec_scalar_t scalar);

bool
ec_scalar_deserialize(ec_scalar_t scalar,
		      const uint8_t serialized[DECAF_448_SCALAR_BYTES]);

void ec_scalar_copy(ec_scalar_t dst, const ec_scalar_t src);

void ec_scalar_destroy(ec_scalar_t dst);

void ec_point_copy(ec_point_t dst, const ec_point_t src);

void ec_point_destroy(ec_point_t dst);

bool ec_point_eq(const ec_point_t, const ec_point_t);

bool ec_point_valid(const ec_point_t point);

bool ec_point_serialize(uint8_t * dst, size_t dst_len, const ec_point_t point);

bool
ec_point_deserialize(ec_point_t point,
		     const uint8_t serialized[ED448_POINT_BYTES]);

//This is ed448 crypto
void ec_scalar_derive_from_secret(ec_scalar_t, uint8_t[ED448_PRIVATE_BYTES]);

void ec_derive_public_key(uint8_t pub[ED448_POINT_BYTES],
			  const uint8_t priv[ED448_PRIVATE_BYTES]);

void ecdh_keypair_generate(ecdh_keypair_t * keypair,
			   uint8_t sym[ED448_PRIVATE_BYTES]);
void ecdh_keypair_destroy(ecdh_keypair_t * keypair);

bool
ecdh_shared_secret(uint8_t * shared,
		   size_t shared_bytes,
		   const ecdh_keypair_t * our_priv, const ec_point_t their_pub);

void ec_public_key_copy(ec_public_key_t dst, const ec_public_key_t src);

void
ec_sign(eddsa_signature_t dst,
	uint8_t sym[ED448_PRIVATE_BYTES],
	uint8_t pubkey[ED448_POINT_BYTES], const uint8_t * msg, size_t msg_len);

bool
ec_verify(const eddsa_signature_t sig, const ec_public_key_t pub,
	  const uint8_t * msg, size_t msg_len);

#endif
