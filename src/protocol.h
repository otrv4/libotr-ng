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

#ifndef OTRNG_PROTOCOL_H
#define OTRNG_PROTOCOL_H

#include "key_management.h"
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
} otrng_state;

#define OTRNG_ALLOW_NONE 0
#define OTRNG_ALLOW_V3 1
#define OTRNG_ALLOW_V4 2

typedef struct otrng_policy_s {
  uint8_t allows;
} otrng_policy_s, otrng_policy_p[1];

typedef struct otrng_conversation_state_s {
  otrng_client_state_s *client;

  char *peer;
  uint16_t their_instance_tag;
} otrng_conversation_state_s, otrng_conversation_state_p[1];

typedef struct otrng_s {
  /* Contains: client (private key, instance tag, and callbacks) and
   conversation state */
  otrng_conversation_state_s *conversation;
  otrng_v3_conn_s *v3_conn;

  otrng_state state;
  uint8_t supported_versions;

  uint32_t their_prekeys_id;

  uint32_t their_instance_tag;

  client_profile_s *their_client_profile;
  otrng_prekey_profile_s *their_prekey_profile;

  uint8_t running_version;

  key_manager_s *keys;
  smp_protocol_p smp;

  list_element_s *pending_fragments;

  string_p sending_init_msg;
  string_p receiving_init_msg;

  time_t last_sent; // TODO: @refactoring not sure if the best place to put

  char *shared_session_state;
} otrng_s, otrng_p[1];

INTERNAL void maybe_create_keys(const otrng_client_state_s *state);

INTERNAL const client_profile_s *get_my_client_profile(otrng_s *otr);

INTERNAL struct goldilocks_448_point_s *our_ecdh(const otrng_s *otr);

INTERNAL dh_public_key_p our_dh(const otrng_s *otr);

INTERNAL uint32_t our_instance_tag(const otrng_s *otr);

INTERNAL otrng_err otrng_prepare_to_send_data_message(
    string_p *to_send, otrng_notif notif, const string_p message,
    const tlv_list_s *tlvs, otrng_s *otr, unsigned char flags);

INTERNAL void otrng_error_message(string_p *to_send, otrng_err_code err_code);

#ifdef OTRNG_PROTOCOL_PRIVATE

tstatic otrng_err serialize_and_encode_data_msg(string_p *dst,
                                                const msg_mac_key_p mac_key,
                                                uint8_t *to_reveal_mac_keys,
                                                size_t to_reveal_mac_keys_len,
                                                const data_message_s *data_msg);
#endif

#endif
