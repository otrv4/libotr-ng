#include <stdlib.h>
#include <assert.h>

#include "keys.h"
#include "random.h"

otrv4_keypair_t *otrv4_keypair_new(void)
{
	otrv4_keypair_t *ret = malloc(sizeof(otrv4_keypair_t));
	if (!ret)
		return NULL;

	ec_scalar_destroy(ret->priv);
	ec_point_destroy(ret->pub);
	return ret;
}

void otrv4_keypair_generate(otrv4_keypair_t * keypair,
			    const uint8_t sym[ED448_PRIVATE_BYTES])
{
	//TODO: generating EdDSA keypair is not working
	memcpy(keypair->sym, sym, ED448_PRIVATE_BYTES);
	ec_scalar_derive_from_secret(keypair->priv, keypair->sym);

	uint8_t pub[ED448_POINT_BYTES];
	ec_derive_public_key(pub, keypair->sym);
	ec_point_deserialize(keypair->pub, pub);

	decaf_bzero(pub, ED448_POINT_BYTES);
}

void otrv4_keypair_destroy(otrv4_keypair_t * keypair)
{
	decaf_bzero(keypair->sym, ED448_PRIVATE_BYTES);
	ec_scalar_destroy(keypair->priv);
	ec_point_destroy(keypair->pub);
}

void otrv4_keypair_free(otrv4_keypair_t * keypair)
{
	otrv4_keypair_destroy(keypair);
	free(keypair);
}
