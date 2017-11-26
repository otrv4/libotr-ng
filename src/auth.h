#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

#include "ed448.h"
#include "keys.h"

#define SNIZKPK_BYTES 6 * ED448_SCALAR_BYTES

typedef ec_scalar_t snizkpk_privkey_t;
typedef ec_point_t snizkpk_pubkey_t;
typedef otrv4_keypair_t snizkpk_keypair_t;

typedef struct {
  ec_scalar_t c1;
  ec_scalar_t r1;
  ec_scalar_t c2;
  ec_scalar_t r2;
  ec_scalar_t c3;
  ec_scalar_t r3;
} snizkpk_proof_t;

void snizkpk_keypair_generate(snizkpk_keypair_t *pair);

void snizkpk_authenticate(snizkpk_proof_t *dst, const snizkpk_keypair_t *pair1,
                          const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3,
                          const unsigned char *msg, size_t msglen);

otrv4_bool_t snizkpk_verify(const snizkpk_proof_t *src,
                            const snizkpk_pubkey_t A1,
                            const snizkpk_pubkey_t A2,
                            const snizkpk_pubkey_t A3, const unsigned char *msg,
                            size_t msglen);

void generate_keypair(snizkpk_pubkey_t pub, snizkpk_privkey_t priv);

void snizkpk_proof_destroy(snizkpk_proof_t *src);

#endif
