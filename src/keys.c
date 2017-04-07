#include <stdlib.h>

#include "keys.h"
#include "random.h"

otrv4_keypair_t*
otrv4_keypair_new(void)
{
        otrv4_keypair_t* ret = malloc(sizeof(otrv4_keypair_t));
        if (ret)
            otrv4_keypair_generate(ret);

        return ret;
}

void otrv4_keypair_generate(otrv4_keypair_t *keypair)
{
	random_bytes(keypair->sym, DECAF_448_SYMMETRIC_KEY_BYTES);
	decaf_448_derive_private_key(keypair, keypair->sym);
}

void otrv4_keypair_destroy(otrv4_keypair_t *keypair)
{
	decaf_448_destroy_private_key(keypair);
}
