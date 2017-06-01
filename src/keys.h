#ifndef KEYS_H
#define KEYS_H

#include "ed448.h"

#define ED448_PUBKEY_TYPE 0x0010
#define ED448_PUBKEY_BYTES 2 + ED448_POINT_BYTES

typedef ec_point_t otrv4_public_key_t;
typedef ec_scalar_t otrv4_private_key_t;

typedef struct {
	//the private key is this symmetric key, and not the scalar serialized
	uint8_t sym[ED448_PRIVATE_BYTES];

	otrv4_public_key_t pub;
	otrv4_private_key_t priv;
} otrv4_keypair_t;

otrv4_keypair_t *
otrv4_keypair_new(void);

void
otrv4_keypair_generate(otrv4_keypair_t * keypair,
                       const uint8_t sym[ED448_PRIVATE_BYTES]);

void
otrv4_keypair_destroy(otrv4_keypair_t * keypair);

void
otrv4_keypair_free(otrv4_keypair_t * keypair);

otr4_err_t
otrv4_symmetric_key_serialize(char **buffer, size_t * buffer_size,
			      uint8_t sym[ED448_PRIVATE_BYTES]);

#endif
