/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OTRNG_DAKE_H
#define OTRNG_DAKE_H

#include "auth.h"
#include "client_profile.h"
#include "constants.h"
#include "dh.h"
#include "ed448.h"
#include "prekey_message.h"
#include "prekey_profile.h"
#include "shared.h"

typedef struct dake_identity_message_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  otrng_client_profile_s *profile;
  ec_point Y;
  dh_public_key B;
  ec_point Y_first;
  dh_public_key B_first;
} dake_identity_message_s;

typedef struct dake_auth_r_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  otrng_client_profile_s *profile;
  ec_point X;
  dh_public_key A;
  ring_sig_s *sigma;
} dake_auth_r_s;

typedef struct dake_auth_i_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  ring_sig_s *sigma;
} dake_auth_i_s;

typedef struct dake_non_interactive_auth_message_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  otrng_client_profile_s *profile;
  ec_point X;
  dh_public_key A;
  ring_sig_s *sigma;
  uint32_t prekey_message_id;
  uint8_t auth_mac[DATA_MSG_MAC_BYTES];
} dake_non_interactive_auth_message_s;

typedef struct {
  otrng_client_profile_s *client_profile;
  otrng_client_profile_s *exp_client_profile;
  otrng_prekey_profile_s *prekey_profile;
  otrng_prekey_profile_s *exp_prekey_profile;
  goldilocks_448_point_s ecdh;
  dh_mpi dh;
} otrng_dake_participant_data_s;

INTERNAL otrng_bool otrng_valid_received_values(
    const uint32_t sender_instance_tag, const ec_point their_ecdh,
    const dh_mpi their_dh, const otrng_client_profile_s *profile);

INTERNAL otrng_result otrng_dake_non_interactive_auth_message_deserialize(
    dake_non_interactive_auth_message_s *dst, const uint8_t *buffer,
    size_t buflen);

INTERNAL otrng_result otrng_dake_non_interactive_auth_message_serialize(
    uint8_t **dst, size_t *nbytes,
    const dake_non_interactive_auth_message_s *non_interactive_auth);

INTERNAL dake_non_interactive_auth_message_s *
otrng_dake_non_interactive_auth_message_new(void);
INTERNAL void otrng_dake_non_interactive_auth_message_init(
    dake_non_interactive_auth_message_s *non_interactive_auth);
INTERNAL void otrng_dake_non_interactive_auth_message_destroy(
    dake_non_interactive_auth_message_s *non_interactive_auth);

INTERNAL /*@null@*/ dake_identity_message_s *
otrng_dake_identity_message_new(const otrng_client_profile_s *profile);

INTERNAL void
otrng_dake_identity_message_free(dake_identity_message_s *identity_msg);

INTERNAL void
otrng_dake_identity_message_destroy(dake_identity_message_s *identity_msg);

INTERNAL otrng_result otrng_dake_identity_message_deserialize(
    dake_identity_message_s *dst, const uint8_t *src, size_t src_len);

INTERNAL otrng_result otrng_dake_identity_message_serialize(
    uint8_t **dst, size_t *nbytes, const dake_identity_message_s *identity_msg);

INTERNAL dake_auth_r_s *otrng_dake_auth_r_new(void);
INTERNAL void otrng_dake_auth_r_init(dake_auth_r_s *auth_r);

INTERNAL void otrng_dake_auth_r_destroy(dake_auth_r_s *auth_r);

INTERNAL otrng_result otrng_dake_auth_r_serialize(uint8_t **dst, size_t *nbytes,
                                                  const dake_auth_r_s *auth_r);
INTERNAL otrng_result otrng_dake_auth_r_deserialize(dake_auth_r_s *dst,
                                                    const uint8_t *buffer,
                                                    size_t buflen);

INTERNAL dake_auth_i_s *otrng_dake_auth_i_new(void);
INTERNAL void otrng_dake_auth_i_init(dake_auth_i_s *auth_i);
INTERNAL void otrng_dake_auth_i_destroy(dake_auth_i_s *auth_i);

INTERNAL otrng_result otrng_dake_auth_i_serialize(uint8_t **dst, size_t *nbytes,
                                                  const dake_auth_i_s *auth_i);
INTERNAL otrng_result otrng_dake_auth_i_deserialize(dake_auth_i_s *dst,
                                                    const uint8_t *buffer,
                                                    size_t buflen);

/*
 * @param auth_tag_type if 'i' is for the auth_i message, if 'r' for the auth_r
 * message. any other value will result in an assertion failure
 */
INTERNAL otrng_result build_interactive_rsign_tag(
    uint8_t **msg, size_t *msg_len, const char auth_tag_type,
    const otrng_dake_participant_data_s *initiator,
    const otrng_dake_participant_data_s *responder, const uint8_t *phi,
    size_t phi_len);

INTERNAL otrng_result
build_non_interactive_rsign_tag(uint8_t **msg, size_t *msg_len,
                                const otrng_dake_participant_data_s *initiator,
                                const otrng_dake_participant_data_s *responder,
                                const otrng_shared_prekey_pub r_shared_prekey,
                                const uint8_t *phi, size_t phi_len);

INTERNAL otrng_result build_fallback_non_interactive_rsign_tag(
    uint8_t **msg, size_t *msg_len,
    const otrng_dake_participant_data_s *initiator,
    const otrng_dake_participant_data_s *responder,
    const otrng_shared_prekey_pub r_shared_prekey, const uint8_t *phi,
    size_t phi_len);

INTERNAL otrng_result otrng_dake_non_interactive_auth_message_authenticator(
    uint8_t dst[HASH_BYTES], const dake_non_interactive_auth_message_s *auth,
    const uint8_t *t, size_t t_len, uint8_t tmp_key[HASH_BYTES]);

#ifdef OTRNG_DAKE_PRIVATE

#endif

#endif
