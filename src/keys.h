#ifndef KEYS_H
#define KEYS_H

#include <libdecaf/decaf_crypto.h>

typedef decaf_448_public_key_t otrv4_public_key_t;
typedef decaf_448_private_key_s otrv4_keypair_t;

otrv4_keypair_t*
otrv4_keypair_new(void);

void
otrv4_keypair_generate(otrv4_keypair_t *keypair);

void
otrv4_keypair_destroy(otrv4_keypair_t *keypair);

#endif
