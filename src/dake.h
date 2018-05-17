/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
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

#include <sodium.h>

#include "auth.h"
#include "client_profile.h"
#include "constants.h"
#include "dh.h"
#include "ed448.h"
#include "shared.h"

typedef struct dake_identity_message_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  client_profile_p profile;
  ec_point_p Y;
  dh_public_key_p B;
} dake_identity_message_s, dake_identity_message_p[1];

typedef struct dake_auth_r_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  client_profile_p profile;
  ec_point_p X;
  dh_public_key_p A;
  ring_sig_p sigma;
} dake_auth_r_s, dake_auth_r_p[1];

typedef struct dake_auth_i_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  ring_sig_p sigma;
} dake_auth_i_s, dake_auth_i_p[1];

typedef struct dake_prekey_message_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  client_profile_p profile;
  ec_point_p Y;
  dh_public_key_p B;
} dake_prekey_message_s, dake_prekey_message_p[1];

typedef struct dake_non_interactive_auth_message_s {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  client_profile_p profile;
  ec_point_p X;
  dh_public_key_p A;
  ring_sig_p sigma;

  // TODO: Extract this to a data structure that can be shared with
  // data_message_s
  /* only used if an ecrypted message is attached */
  uint32_t ratchet_id;
  uint32_t message_id;
  ec_point_p ecdh;
  dh_public_key_p dh;
  uint8_t nonce[DATA_MSG_NONCE_BYTES];
  uint8_t *enc_msg;
  size_t enc_msg_len;
  uint8_t auth_mac[DATA_MSG_MAC_BYTES];
} dake_non_interactive_auth_message_s, dake_non_interactive_auth_message_p[1];

INTERNAL otrng_bool otrng_valid_received_values(
    const ec_point_p their_ecdh, const dh_mpi_p their_dh,
    const client_profile_s *profile);

INTERNAL otrng_err otrng_dake_non_interactive_auth_message_deserialize(
    dake_non_interactive_auth_message_s *dst, const uint8_t *buffer,
    size_t buflen);

INTERNAL otrng_err otrng_dake_non_interactive_auth_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_non_interactive_auth_message_s *non_interactive_auth);

INTERNAL void otrng_dake_non_interactive_auth_message_destroy(
    dake_non_interactive_auth_message_s *non_interactive_auth);

INTERNAL dake_identity_message_s *
otrng_dake_identity_message_new(const client_profile_s *profile);

INTERNAL void
otrng_dake_identity_message_free(dake_identity_message_s *identity_message);

INTERNAL void
otrng_dake_identity_message_destroy(dake_identity_message_s *identity_message);

INTERNAL otrng_err otrng_dake_identity_message_deserialize(
    dake_identity_message_s *dst, const uint8_t *src, size_t src_len);

INTERNAL otrng_err otrng_dake_identity_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_identity_message_s *identity_message);

INTERNAL void otrng_dake_auth_r_destroy(dake_auth_r_s *auth_r);

INTERNAL otrng_err otrng_dake_auth_r_asprintf(uint8_t **dst, size_t *nbytes,
                                              const dake_auth_r_s *auth_r);
INTERNAL otrng_err otrng_dake_auth_r_deserialize(dake_auth_r_s *dst,
                                                 const uint8_t *buffer,
                                                 size_t buflen);

INTERNAL void otrng_dake_auth_i_destroy(dake_auth_i_s *auth_i);

INTERNAL otrng_err otrng_dake_auth_i_asprintf(uint8_t **dst, size_t *nbytes,
                                              const dake_auth_i_s *auth_i);
INTERNAL otrng_err otrng_dake_auth_i_deserialize(dake_auth_i_s *dst,
                                                 const uint8_t *buffer,
                                                 size_t buflen);

INTERNAL dake_prekey_message_s *
otrng_dake_prekey_message_new(const client_profile_s *profile);

INTERNAL void
otrng_dake_prekey_message_free(dake_prekey_message_s *prekey_message);

INTERNAL void
otrng_dake_prekey_message_destroy(dake_prekey_message_s *prekey_message);

INTERNAL otrng_err otrng_dake_prekey_message_deserialize(
    dake_prekey_message_s *dst, const uint8_t *src, size_t src_len);

INTERNAL otrng_err otrng_dake_prekey_message_asprintf(
    uint8_t **dst, size_t *nbytes, const dake_prekey_message_s *prekey_message);

INTERNAL otrng_err build_interactive_rsign_tag(
    uint8_t **msg, size_t *msg_len, const uint8_t type,
    const client_profile_s *i_profile, const client_profile_s *r_profile,
    const ec_point_p i_ecdh, const ec_point_p r_ecdh, const dh_mpi_p i_dh,
    const dh_mpi_p r_dh, const char *phi);

INTERNAL otrng_err build_non_interactive_rsig_tag(
    uint8_t **msg, size_t *msg_len, const client_profile_s *i_profile,
    const client_profile_s *r_profile, const ec_point_p i_ecdh,
    const ec_point_p r_ecdh, const dh_mpi_p i_dh, const dh_mpi_p r_dh,
    const otrng_shared_prekey_pub_p r_shared_prekey, char *phi);

INTERNAL otrng_err otrng_dake_non_interactive_auth_message_authenticator(
    uint8_t dst[HASH_BYTES], const dake_non_interactive_auth_message_p auth,
    const uint8_t *t, size_t t_len, uint8_t tmp_key[HASH_BYTES]);

#ifdef OTRNG_DAKE_PRIVATE

tstatic otrng_err
xzdh_encrypted_message_asprintf(uint8_t **dst, size_t *dst_len,
                                const dake_non_interactive_auth_message_s *msg);

tstatic size_t xzdh_encrypted_message_deserialize(
    dake_non_interactive_auth_message_s *dst, const uint8_t *buffer, size_t len,
    size_t *read);

#endif

#endif
