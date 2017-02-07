#ifndef CRAMER_SHOUP_H
#define CRAMER_SHOUP_H

#include <cramershoup.h>
#include "ed448.h"

//TODO: rename and keep consistent cramershoup naming (no underscore)
#define CRAMER_SHOUP_PUBKEY_TYPE 0x0010

typedef cramershoup_448_public_key_t cs_public_key_t;
typedef cramershoup_448_private_key_t cs_private_key_t;
typedef cramershoup_448_symmetric_key_t dr_cs_symmetric_key_t;
typedef cramershoup_448_dr_encrypted_key_t dr_cs_encrypted_symmetric_key_t;
typedef cramershoup_448_rs_auth_t rs_auth_t;

typedef struct {
  cs_public_key_t pub[1];
  cs_private_key_t priv[1];
} cs_keypair_s, cs_keypair_t[1];

void
cs_generate_keypair(cs_keypair_t key_par);

void
cs_public_key_copy(cs_public_key_t *dst, const cs_public_key_t *src);

static inline void
dr_cs_generate_symmetric_key(dr_cs_symmetric_key_t k) {
  cramershoup_448_random_symmetric_key(k);
}

static inline bool
dr_cs_encrypt(dr_cs_encrypted_symmetric_key_t gamma, const dr_cs_symmetric_key_t k, const cs_public_key_t *our_pub, const cs_public_key_t *their_pub) {
  if (dr_cramershoup_448_enc(gamma, k, our_pub, their_pub) == 0) {
    return true;
  }

  return false;
}

static inline void
ring_signature_auth(rs_auth_t dst,
                    const uint8_t *msg,
                    const cs_keypair_t keypair,
                    const cs_public_key_t *their_pub,
                    const ec_point_t their_ephemeral
                    ) {
  rs_448_auth(dst, (char*) msg,
              keypair->priv->z, keypair->pub->h,
              their_pub->h, their_ephemeral);
}

#endif
