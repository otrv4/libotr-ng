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

/**
 * The functions in this file only operate on their arguments, and doesn't touch
 * any global state. It is safe to call these functions concurrently from
 * different threads, as long as arguments pointing to the same memory areas are
 * not used from different threads.
 */

#ifndef OTRNG_PROTOCOL_H
#define OTRNG_PROTOCOL_H

#include "client_profile.h"
#include "key_management.h"
#include "prekey_profile.h"
#include "smp_protocol.h"
#include "v3.h"

typedef enum {
  OTRNG_STATE_NONE = 0,
  OTRNG_STATE_START = 1,
  OTRNG_STATE_WAITING_AUTH_R = 2,
  OTRNG_STATE_WAITING_AUTH_I = 3,
  OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE = 4,
  OTRNG_STATE_ENCRYPTED_MESSAGES = 5,
  OTRNG_STATE_FINISHED = 6
} otrng_state_e;

#define OTRNG_ALLOW_NONE 0x00
#define OTRNG_ALLOW_V3 0x01
#define OTRNG_ALLOW_V4 0x02
#define OTRNG_ALLOW_V34 0x03
#define OTRNG_SEND_WHITESPACE_TAG 0x10
#define OTRNG_REQUIRE_ENCRYPTION 0x40
#define OTRNG_WHITESPACE_START_DAKE 0x80
#define OTRNG_ERROR_START_DAKE 0x20
#define OTRNG_REQUIRE_INTERACTIVE 0x08
#define OTRNG_IDENTITY_START_DAKE 0x12
#define OTRNG_REQUIRE_AUTHENTICATED 0x0B

#define OTRNG_POLICY_NEVER OTRNG_ALLOW_NONE
#define OTRNG_POLICY_DEFAULT OTRNG_POLICY_NEVER
#define OTRNG_POLICY_MANUAL OTRNG_ALLOW_V34
#define OTRNG_POLICY_NORMAL                                                    \
  (OTRNG_WHITESPACE_START_DAKE | OTRNG_ERROR_START_DAKE)
#define OTRNG_POLICY_OPPORTUNISTIC                                             \
  (OTRNG_WHITESPACE_START_DAKE | OTRNG_SEND_WHITESPACE_TAG |                   \
   OTRNG_ERROR_START_DAKE)
#define OTRNG_POLICY_ALWAYS                                                    \
  (OTRNG_REQUIRE_ENCRYPTION | OTRNG_ERROR_START_DAKE |                         \
   OTRNG_IDENTITY_START_DAKE)

typedef struct otrng_s {
  struct otrng_client_s *client;

  char *peer;

  otrng_v3_conn_s *v3_conn;

  otrng_state_e state;

  uint8_t supported_versions;
  uint8_t policy_type;

  uint32_t their_prekeys_id;

  uint32_t their_instance_tag;

  otrng_client_profile_s *their_client_profile;
  otrng_prekey_profile_s *their_prekey_profile;

  uint8_t running_version;

  key_manager_s *keys;
  smp_protocol_s *smp;

  list_element_s *pending_fragments;

  time_t last_sent; // TODO: @refactoring not sure if the best place to put

  char *shared_session_state;
} otrng_s;

INTERNAL void maybe_create_keys(struct otrng_client_s *client);

INTERNAL const otrng_client_profile_s *get_my_client_profile(otrng_s *otr);

INTERNAL const otrng_client_profile_s *get_my_exp_client_profile(otrng_s *otr);

INTERNAL const otrng_prekey_profile_s *get_my_prekey_profile(otrng_s *otr);

INTERNAL const otrng_prekey_profile_s *get_my_exp_prekey_profile(otrng_s *otr);

INTERNAL struct goldilocks_448_point_s *our_ecdh(const otrng_s *otr);

INTERNAL dh_public_key our_dh(const otrng_s *otr);

INTERNAL struct goldilocks_448_point_s *our_ecdh_first(const otrng_s *otr);

INTERNAL dh_public_key our_dh_first(const otrng_s *otr);

INTERNAL uint32_t our_instance_tag(const otrng_s *otr);

INTERNAL otrng_result otrng_prepare_to_send_data_message(string_p *to_send,
                                                         const string_p msg,
                                                         const tlv_list_s *tlvs,
                                                         otrng_s *otr,
                                                         unsigned char flags);

INTERNAL void otrng_error_message(string_p *to_send, otrng_err_code err_code);

#ifdef OTRNG_PROTOCOL_PRIVATE

tstatic otrng_result serialize_and_encode_data_message(
    string_p *dst, const k_msg_mac mac_key, uint8_t *to_reveal_mac_keys,
    size_t to_reveal_mac_keys_len, const data_message_s *data_msg);
#endif

#endif
