#include <stdlib.h>
#include <assert.h>

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
  uint8_t proto[DECAF_448_SYMMETRIC_KEY_BYTES];
  random_bytes(proto, DECAF_448_SYMMETRIC_KEY_BYTES);

  decaf_448_private_key_t private;
  decaf_448_derive_private_key(private, proto);

  //From Decaf private to OTR long term key
  //Public-key must be deserialized into a Point
  //Private-key is already a deserialized Scalar
  decaf_bool_t ok = decaf_448_point_decode(keypair->pub, private->pub, DECAF_FALSE);
  assert(ok == DECAF_SUCCESS);

  decaf_448_scalar_copy(keypair->priv, private->secret_scalar);
  
  decaf_448_destroy_private_key(private);
}

void otrv4_keypair_destroy(otrv4_keypair_t *keypair)
{
  decaf_448_point_destroy(keypair->pub);
  decaf_448_scalar_destroy(keypair->priv);
}
