#include <stdbool.h>
#include <sodium.h>

#include "dh.h"
#include "ed448.h"
#include "user_profile.h"
#include "cramer_shoup.h"

#define NONCE_BYTES crypto_secretbox_NONCEBYTES
#define AUTH_BYTES (6*DECAF_448_SCALAR_BYTES)
#define DAKE_HEADER_BYTES (2+1+4+4)

//size of PRE_KEY_MESSAGE without user_profile
#define PRE_KEY_MIN_BYTES DAKE_HEADER_BYTES \
                          + DECAF_448_SER_BYTES \
                          + 4+DH3072_MOD_LEN_BYTES

//size of DRE_AUTH_MESSAGE without user_profile and phi
#define DRE_AUTH_MIN_BYTES DAKE_HEADER_BYTES \
                           + sizeof(dr_cs_encrypted_symmetric_key_t) \
                           + AUTH_BYTES \
                           + NONCE_BYTES

#ifndef DAKE_H
#define DAKE_H

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  user_profile_t profile[1];
  ec_public_key_t Y;
  dh_public_key_t B;
} dake_pre_key_t;

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  user_profile_t profile[1];

  dr_cs_encrypted_symmetric_key_t gamma;
  rs_auth_t sigma;
  uint8_t nonce[NONCE_BYTES];
  uint8_t *phi;
  size_t phi_len;

} dake_dre_auth_t;

typedef struct {
  user_profile_t receiver_profile[1];
  user_profile_t sender_profile[1];

  ec_public_key_t receiver_ecdh;
  ec_public_key_t sender_ecdh;

  dh_public_key_t receiver_dh;
  dh_public_key_t sender_dh;
} dake_dre_auth_phi_msg_t;

dake_pre_key_t *
dake_pre_key_new(const user_profile_t *profile);

void
dake_pre_key_free(dake_pre_key_t *pre_key);

bool
dake_pre_key_deserialize(dake_pre_key_t *dst, const uint8_t *src, size_t src_len);

bool
dake_pre_key_aprint(uint8_t **dst, size_t *nbytes, const dake_pre_key_t *pre_key);

bool
dake_pre_key_validate(const dake_pre_key_t *pre_key);



dake_dre_auth_t *
dake_dre_auth_new(const user_profile_t *profile);

void
dake_dre_auth_free(dake_dre_auth_t *dre_auth);

bool
dake_dre_auth_aprint(uint8_t **dst, size_t *nbytes, const dake_dre_auth_t *dre_auth);

bool
dake_dre_auth_deserialize(dake_dre_auth_t *dst, uint8_t *buffer, size_t buflen);

bool
dake_dre_auth_generate_gamma_phi_sigma(const cs_keypair_t our_keypair,
                                       const ec_public_key_t our_ecdh,
                                       const dh_mpi_t our_dh,
                                       const user_profile_t *their_profile,
                                       const ec_public_key_t their_ecdh,
                                       const dh_mpi_t their_dh,
                                       dake_dre_auth_t *dre_auth);

bool
dake_dre_auth_validate(ec_public_key_t their_ecdh,
                       dh_public_key_t *their_dh,
                       const user_profile_t *our_profile,
                       const cs_keypair_t our_cs_keypair,
                       const ec_public_key_t our_ecdh_pub,
                       const dh_mpi_t our_dh_pub,
                       const dake_dre_auth_t *dre_auth);

#endif
