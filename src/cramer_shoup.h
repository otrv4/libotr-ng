#ifndef CRAMER_SHOUP_H
#define CRAMER_SHOUP_H

#include <cramershoup.h>
#include "ed448.h"

#define CRAMER_SHOUP_PUBKEY_TYPE 0x0010

typedef cramershoup_448_public_key_t cs_public_key_t;
typedef cramershoup_448_private_key_t cs_private_key_t;

typedef struct {
  cs_public_key_t pub[1];
  cs_private_key_t priv[1];
} cs_keypair_t[1];

void
cs_generate_keypair(cs_keypair_t key_par);

void
cs_public_key_copy(cs_public_key_t *dst, const cs_public_key_t *src);

#endif
