#include <libdecaf/decaf_crypto.h>

#ifndef ED448_H
#define ED448_H

typedef decaf_448_private_key_t     ec_keypair_t;
typedef decaf_448_public_key_t      ec_public_key_t;
//typedef decaf_448_symmetric_key_t   ec_symmetric_key_t;

//typedef struct {
//  //TODO should we really have these 3 or storing only the symmetric is enough?
//  ec_private_key_t priv;
//  ec_public_key_t pub;
//} ec_keypair_t[1];

typedef struct {
  uint8_t data[56];
} ed448_point_t;


void
ec_gen_keypair(ec_keypair_t keypair);

int
ecdh_shared_secret(uint8_t *shared, size_t shared_bytes, const ec_keypair_t our_priv, const ec_public_key_t their_pub);

void
ec_keypair_destroy(ec_keypair_t keypair);


ed448_point_t *
ed448_point_new();

void
ed448_point_free(ed448_point_t *point);


#endif
