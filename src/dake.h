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
#include "constants.h"
#include "dh.h"
#include "ed448.h"
#include "shared.h"
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
  ring_sig_t sigma[1];
} dake_auth_r_t;

typedef struct {
  uint32_t sender_instance_tag;
  uint32_t receiver_instance_tag;
  ring_sig_t sigma[1];
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
  ring_sig_t sigma[1];
  /* only used if an ecrypted message is attached */
  uint32_t message_id;
  uint8_t nonce[DATA_MSG_NONCE_BYTES];
  uint8_t *enc_msg;
  size_t enc_msg_len;
  uint8_t auth_mac[HASH_BYTES];
} dake_non_interactive_auth_message_t;

INTERNAL otrng_bool_t otrng_valid_received_values(
    const ec_point_t their_ecdh, const dh_mpi_t their_dh,
    const user_profile_t *profile);

INTERNAL otrng_err_t otrng_dake_non_interactive_auth_message_deserialize(
    dake_non_interactive_auth_message_t *dst, const uint8_t *buffer,
    size_t buflen);

INTERNAL otrng_err_t otrng_dake_non_interactive_auth_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_non_interactive_auth_message_t *non_interactive_auth);

INTERNAL void otrng_dake_non_interactive_auth_message_destroy(
    dake_non_interactive_auth_message_t *non_interactive_auth);

INTERNAL dake_identity_message_t *
otrng_dake_identity_message_new(const user_profile_t *profile);

INTERNAL void
otrng_dake_identity_message_free(dake_identity_message_t *identity_message);

INTERNAL void
otrng_dake_identity_message_destroy(dake_identity_message_t *identity_message);

INTERNAL otrng_err_t otrng_dake_identity_message_deserialize(
    dake_identity_message_t *dst, const uint8_t *src, size_t src_len);

INTERNAL otrng_err_t otrng_dake_identity_message_asprintf(
    uint8_t **dst, size_t *nbytes,
    const dake_identity_message_t *identity_message);

INTERNAL void otrng_dake_auth_r_destroy(dake_auth_r_t *auth_r);

INTERNAL otrng_err_t otrng_dake_auth_r_asprintf(uint8_t **dst, size_t *nbytes,
                                                const dake_auth_r_t *auth_r);
INTERNAL otrng_err_t otrng_dake_auth_r_deserialize(dake_auth_r_t *dst,
                                                   const uint8_t *buffer,
                                                   size_t buflen);

INTERNAL void otrng_dake_auth_i_destroy(dake_auth_i_t *auth_i);

INTERNAL otrng_err_t otrng_dake_auth_i_asprintf(uint8_t **dst, size_t *nbytes,
                                                const dake_auth_i_t *auth_i);
INTERNAL otrng_err_t otrng_dake_auth_i_deserialize(dake_auth_i_t *dst,
                                                   const uint8_t *buffer,
                                                   size_t buflen);

INTERNAL dake_prekey_message_t *
otrng_dake_prekey_message_new(const user_profile_t *profile);

INTERNAL void
otrng_dake_prekey_message_free(dake_prekey_message_t *prekey_message);

INTERNAL void
otrng_dake_prekey_message_destroy(dake_prekey_message_t *prekey_message);

INTERNAL otrng_err_t otrng_dake_prekey_message_deserialize(
    dake_prekey_message_t *dst, const uint8_t *src, size_t src_len);

INTERNAL otrng_err_t otrng_dake_prekey_message_asprintf(
    uint8_t **dst, size_t *nbytes, const dake_prekey_message_t *prekey_message);

#ifdef OTRNG_DAKE_PRIVATE
#endif

#endif
