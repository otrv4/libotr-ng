#include <stdbool.h>
#include <sodium.h>

#include "dh.h"
#include "ed448.h"
#include "user_profile.h"
#include "cramer_shoup.h"

#define OTR_VERSION 4 //TODO: move
#define OTR_PRE_KEY_MSG_TYPE 0x0F
#define OTR_DRE_AUTH_MSG_TYPE 0x00
#define OTR_DATA_MSG_TYPE 0x03

#define NONCE_BYTES crypto_secretbox_NONCEBYTES

#define AUTH_BYTES 6*DECAF_448_SCALAR_BYTES

#define PRE_KEY_MIN_BYTES 2+1+4+4 \
                          + DECAF_448_SER_BYTES \
                          + 4+DH3072_MOD_LEN_BYTES

#define DRE_AUTH_MIN_BYTES PRE_KEY_MIN_BYTES \
                           + sizeof(dr_cs_encrypted_symmetric_key_t) \
                           + AUTH_BYTES \
                           + NONCE_BYTES

#ifndef DAKE_H
#define DAKE_H

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  user_profile_t sender_profile[1];
  ec_public_key_t Y;
  dh_public_key_t B;
} dake_pre_key_t;

typedef struct {
  uint8_t version_protocol;
  uint8_t type;
  uint8_t sender_instance_tag;
  uint8_t receiver_instance_tag;
  user_profile_t sender_profile[1], our_profile[1];
  ec_public_key_t X;
  dh_public_key_t A;

  dr_cs_encrypted_symmetric_key_t gamma;
  rs_auth_t sigma;
  uint8_t nonce[NONCE_BYTES];
} dake_dre_auth_t;

dake_pre_key_t *
dake_pre_key_new(const user_profile_t *profile);

void
dake_pre_key_free(dake_pre_key_t *pre_key);

bool
dake_pre_key_deserialize(dake_pre_key_t *dst, const uint8_t *src, size_t src_len);

bool
dake_pre_key_aprint(uint8_t **dst, size_t *nbytes, const dake_pre_key_t *pre_key);

dake_dre_auth_t *
dake_dre_auth_new();

void
dake_dre_auth_free(dake_dre_auth_t *dre_auth);

bool
dake_dre_auth_aprint(uint8_t **dst, size_t *nbytes, const dake_dre_auth_t *dre_auth);

void
dake_dre_auth_deserialize(dake_dre_auth_t *target, uint8_t *data);

bool
dake_pre_key_validate(const dake_pre_key_t *pre_key);

#endif
