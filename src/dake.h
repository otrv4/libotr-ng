#ifndef DAKE_H
#define DAKE_H

#include <sodium.h>
#include <stdbool.h>

#include "auth.h"
#include "constants.h"
#include "dh.h"
#include "ed448.h"
#include "user_profile.h"

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  user_profile_t profile[1];
  ec_point_t Y;
  dh_public_key_t B;
} dake_identity_message_t;

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  user_profile_t profile[1];
  ec_point_t X;
  dh_public_key_t A;
  snizkpk_proof_t sigma[1];
} dake_auth_r_t;

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  snizkpk_proof_t sigma[1];
} dake_auth_i_t;

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  user_profile_t profile[1];
  ec_point_t Y;
  dh_public_key_t B;
} dake_prekey_message_t;

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  user_profile_t profile[1];
  ec_point_t X;
  dh_public_key_t A;
  snizkpk_proof_t sigma[1];
  uint8_t auth_mac[HASH_BYTES];
  uint8_t *enc_msg;
  size_t enc_msg_len;
} dake_non_interactive_auth_message_t;

dake_identity_message_t *
dake_identity_message_new(const user_profile_t *profile);

void dake_identity_message_free(dake_identity_message_t *identity_message);

void dake_identity_message_destroy(dake_identity_message_t *identity_message);

otr4_err_t dake_identity_message_deserialize(dake_identity_message_t *dst,
                                             const uint8_t *src,
                                             size_t src_len);

otr4_err_t
dake_identity_message_asprintf(uint8_t **dst, size_t *nbytes,
                               const dake_identity_message_t *identity_message);

void dake_auth_r_destroy(dake_auth_r_t *auth_r);

otr4_err_t dake_auth_r_asprintf(uint8_t **dst, size_t *nbytes,
                                const dake_auth_r_t *auth_r);
otr4_err_t dake_auth_r_deserialize(dake_auth_r_t *dst, const uint8_t *buffer,
                                   size_t buflen);

void dake_auth_i_destroy(dake_auth_i_t *auth_i);

otr4_err_t dake_auth_i_asprintf(uint8_t **dst, size_t *nbytes,
                                const dake_auth_i_t *auth_i);
otr4_err_t dake_auth_i_deserialize(dake_auth_i_t *dst, const uint8_t *buffer,
                                   size_t buflen);

bool valid_received_values(const ec_point_t their_ecdh, const dh_mpi_t their_dh,
                           const user_profile_t *profile);

dake_prekey_message_t *dake_prekey_message_new(const user_profile_t *profile);

void dake_prekey_message_free(dake_prekey_message_t *prekey_message);

void dake_prekey_message_destroy(dake_prekey_message_t *prekey_message);

otr4_err_t dake_prekey_message_deserialize(dake_prekey_message_t *dst,
                                           const uint8_t *src, size_t src_len);

otr4_err_t
dake_prekey_message_asprintf(uint8_t **dst, size_t *nbytes,
                             const dake_prekey_message_t *prekey_message);

void dake_non_interactive_auth_message_destroy(
    dake_non_interactive_auth_message_t *non_interactive_auth);

otr4_err_t dake_non_interactive_auth_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_non_interactive_auth_message_t *non_interactive_auth);

otr4_err_t dake_non_interactive_auth_message_deserialize(
    dake_non_interactive_auth_message_t *dst, const uint8_t *buffer,
    size_t buflen);

#endif
