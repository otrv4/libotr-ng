#ifndef KEYS_H
#define KEYS_H

#include "ed448.h"

typedef ec_point_t otrv4_public_key_t;
typedef ec_scalar_t otrv4_private_key_t;

typedef struct {
  otrv4_public_key_t pub;
  otrv4_private_key_t priv;
} otrv4_keypair_t;

otrv4_keypair_t*
otrv4_keypair_new(void);

void
otrv4_keypair_generate(otrv4_keypair_t *keypair);

void
otrv4_keypair_destroy(otrv4_keypair_t *keypair);

#endif
