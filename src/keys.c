#include "keys.h"

void otrv4_keypair_destroy(otrv4_keypair_t *key_pair)
{
       memset(key_pair->pub, 0, sizeof(otrv4_public_key_t));
       memset(key_pair->priv, 0, sizeof(otrv4_private_key_t));
}
