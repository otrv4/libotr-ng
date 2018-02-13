#ifndef OTRV4_DAKE_H
#define OTRV4_DAKE_H

#include <sodium.h>

#include "shared.h"
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
  /* only used if an ecrypted message is attached */
  uint32_t message_id;
  uint8_t nonce[DATA_MSG_NONCE_BYTES];
  uint8_t *enc_msg;
  size_t enc_msg_len;
  uint8_t auth_mac[HASH_BYTES];
} dake_non_interactive_auth_message_t;

INTERNAL otrv4_bool_t otrv4_valid_received_values(const ec_point_t their_ecdh,
                                   const dh_mpi_t their_dh,
                                   const user_profile_t *profile);

INTERNAL otrv4_err_t otrv4_dake_non_interactive_auth_message_deserialize(
    dake_non_interactive_auth_message_t *dst, const uint8_t *buffer,
    size_t buflen);

INTERNAL otrv4_err_t otrv4_dake_non_interactive_auth_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_non_interactive_auth_message_t *non_interactive_auth);

INTERNAL void otrv4_dake_non_interactive_auth_message_destroy(
    dake_non_interactive_auth_message_t *non_interactive_auth);

INTERNAL dake_identity_message_t *
otrv4_dake_identity_message_new(const user_profile_t *profile);

INTERNAL void otrv4_dake_identity_message_free(dake_identity_message_t *identity_message);

INTERNAL void otrv4_dake_identity_message_destroy(dake_identity_message_t *identity_message);

INTERNAL otrv4_err_t otrv4_dake_identity_message_deserialize(dake_identity_message_t *dst,
                                              const uint8_t *src,
                                              size_t src_len);

INTERNAL otrv4_err_t
otrv4_dake_identity_message_asprintf(uint8_t **dst, size_t *nbytes,
                               const dake_identity_message_t *identity_message);

INTERNAL void otrv4_dake_auth_r_destroy(dake_auth_r_t *auth_r);

INTERNAL otrv4_err_t otrv4_dake_auth_r_asprintf(uint8_t **dst, size_t *nbytes,
                                 const dake_auth_r_t *auth_r);
INTERNAL otrv4_err_t otrv4_dake_auth_r_deserialize(dake_auth_r_t *dst, const uint8_t *buffer,
                                    size_t buflen);

INTERNAL void otrv4_dake_auth_i_destroy(dake_auth_i_t *auth_i);

INTERNAL otrv4_err_t otrv4_dake_auth_i_asprintf(uint8_t **dst, size_t *nbytes,
                                 const dake_auth_i_t *auth_i);
INTERNAL otrv4_err_t otrv4_dake_auth_i_deserialize(dake_auth_i_t *dst, const uint8_t *buffer,
                                    size_t buflen);

INTERNAL dake_prekey_message_t *otrv4_dake_prekey_message_new(const user_profile_t *profile);

INTERNAL void otrv4_dake_prekey_message_free(dake_prekey_message_t *prekey_message);

INTERNAL void otrv4_dake_prekey_message_destroy(dake_prekey_message_t *prekey_message);

INTERNAL otrv4_err_t otrv4_dake_prekey_message_deserialize(dake_prekey_message_t *dst,
                                            const uint8_t *src, size_t src_len);

INTERNAL otrv4_err_t
otrv4_dake_prekey_message_asprintf(uint8_t **dst, size_t *nbytes,
                             const dake_prekey_message_t *prekey_message);


#ifdef OTRV4_DAKE_PRIVATE
#endif


#endif
