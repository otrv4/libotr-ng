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

#ifndef OTRNG_OTRNG_H
#define OTRNG_OTRNG_H

#include "client_profile.h"
#include "client_state.h"
#include "data_message.h"
#include "fragment.h"
#include "key_management.h"
#include "keys.h"
#include "prekey_ensemble.h"
#include "prekey_profile.h"
#include "protocol.h"
#include "shared.h"
#include "smp.h"
#include "str.h"
#include "v3.h"

#define UNUSED_ARG(x) (void)(x)

#define OTRNG_INIT                                                             \
  do {                                                                         \
    otrng_v3_init();                                                           \
    otrng_dh_init();                                                           \
  } while (0)

#define OTRNG_FREE                                                             \
  do {                                                                         \
    otrng_dh_free();                                                           \
  } while (0)

// clang-format off
// TODO: @non_interactive this a mock
typedef struct otrng_server_s {
  string_p prekey_message;
} otrng_server_s, otrng_server_p[1];
// clang-format on

typedef enum {
  OTRNG_WARN_NONE = 0,
  OTRNG_WARN_RECEIVED_UNENCRYPTED,
  OTRNG_WARN_RECEIVED_NOT_VALID,
} otrng_warning;

// TODO: @refactoring The use of "response" as the type name is confusing:
// - to_display is the RECEIVED plaintext
// - tlvs is the RECEIVED list of TLVs
// - warning is a warning due the RECEIVAL of the message
// - to_send is the RESPONSE we send in response to the RECEIVED tlvs.
typedef struct otrng_response_s {
  string_p to_display;
  string_p to_send;
  tlv_list_s *tlvs;
  otrng_warning warning;
} otrng_response_s, otrng_response_p[1];

typedef struct otrng_header_s {
  uint16_t version;
  uint8_t type;
} otrng_header_s, otrng_header_p[1];

INTERNAL otrng_s *otrng_new(struct otrng_client_state_s *state,
                            otrng_policy_s policy);

INTERNAL void otrng_free(/*@only@ */ otrng_s *otr);

INTERNAL otrng_err otrng_build_query_message(string_p *dst,
                                             const string_p message,
                                             otrng_s *otr);

INTERNAL otrng_response_s *otrng_response_new(void);

INTERNAL void otrng_response_free(otrng_response_s *response);

INTERNAL otrng_err otrng_receive_defragmented_message(
    otrng_response_s *response, otrng_notif notif, const string_p message,
    otrng_s *otr);

INTERNAL otrng_err otrng_receive_message(otrng_response_s *response,
                                         otrng_notif notif,
                                         const string_p message, otrng_s *otr);

INTERNAL otrng_err otrng_send_message(string_p *to_send, const string_p message,
                                      otrng_notif notif, const tlv_list_s *tlvs,
                                      uint8_t flags, otrng_s *otr);

INTERNAL otrng_err otrng_close(string_p *to_send, otrng_s *otr);

INTERNAL otrng_err otrng_expire_session(string_p *to_send, otrng_s *otr);

API otrng_err otrng_build_whitespace_tag(string_p *whitespace_tag,
                                         const string_p message, otrng_s *otr);

API otrng_err otrng_send_symkey_message(string_p *to_send, unsigned int use,
                                        const unsigned char *usedata,
                                        size_t usedatalen, uint8_t *extra_key,
                                        otrng_s *otr);

API otrng_err otrng_send_offline_message(string_p *dst,
                                         const prekey_ensemble_s *ensemble,
                                         otrng_s *otr);

API void otrng_v3_init(void);

INTERNAL prekey_ensemble_s *otrng_build_prekey_ensemble(otrng_s *otr);

INTERNAL void otrng_destroy(otrng_s *otr);

char *
otrng_generate_session_state_string(const otrng_shared_session_state_s *state);

#ifdef OTRNG_OTRNG_PRIVATE

tstatic otrng_shared_session_state_s
otrng_get_shared_session_state(otrng_s *otr);

tstatic int get_message_type(const string_p message);

API otrng_err extract_header(otrng_header_s *dst, const uint8_t *buffer,
                             const size_t bufflen);

tstatic tlv_s *process_tlv(const tlv_s *tlv, otrng_s *otr);

#endif

#endif
