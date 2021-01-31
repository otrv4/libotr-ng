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

#include "otrng.h"

#ifndef S_SPLINT_S
#include <gcrypt.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/b64.h>
#include <libotr/mem.h>
#pragma clang diagnostic pop
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OTRNG_OTRNG_PRIVATE

#include "constants.h"
#include "dake.h"
#include "data_message.h"
#include "deserialize.h"
#include "instance_tag.h"
#include "messaging.h"
#include "padding.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"
#include "smp.h"
#include "tlv.h"

#include "debug.h"

static inline struct goldilocks_448_point_s *their_ecdh(const otrng_s *otr) {
  return &otr->keys->their_ecdh[0];
}

static inline dh_public_key their_dh(const otrng_s *otr) {
  return otr->keys->their_dh;
}

static const char tag_base[] = {'\x20', '\x09', '\x20', '\x20', '\x09', '\x09',
                                '\x09', '\x09', '\x20', '\x09', '\x20', '\x09',
                                '\x20', '\x09', '\x20', '\x20', '\0'};

static const char tag_version_v4[] = {'\x20', '\x20', '\x09', '\x09', '\x20',
                                      '\x09', '\x20', '\x20', '\0'};

static const char tag_version_v3[] = {'\x20', '\x20', '\x09', '\x09', '\x20',
                                      '\x20', '\x09', '\x09', '\0'};

static const string_p query_header = "?OTRv";
static const string_p otr_error_header = "?OTR Error:";
static const string_p otr_header = "?OTR:";

tstatic void gone_secure_cb_v4(const otrng_s *conv) {
  otrng_client_callbacks_gone_secure(conv->client->global_state->callbacks,
                                     conv);
}

tstatic void gone_insecure_cb_v4(const otrng_s *conv) {
  otrng_client_callbacks_gone_insecure(conv->client->global_state->callbacks,
                                       conv);
}

tstatic void fingerprint_seen_cb_v4(const otrng_fingerprint fp,
                                    const otrng_s *conv) {
  otrng_client_callbacks_fingerprint_seen(conv->client->global_state->callbacks,
                                          fp, conv);
}

tstatic void display_error_message_cb(const otrng_error_event event,
                                      string_p *to_display,
                                      const otrng_s *conv) {
  otrng_client_callbacks_display_error_message(
      conv->client->global_state->callbacks, event, to_display, conv);
}

tstatic void received_extra_sym_key(const otrng_s *conv, unsigned int use,
                                    const unsigned char *use_data,
                                    size_t use_data_len,
                                    const unsigned char *extra_sym_key) {

  if (!conv->client->global_state->callbacks->received_extra_symm_key) {
    return;
  }

  conv->client->global_state->callbacks->received_extra_symm_key(
      conv, use, use_data, use_data_len, extra_sym_key);

#ifdef DEBUG
  debug_print("\n");
  debug_print("Received symkey use: %08x\n", use);
  debug_print("Usedata lenght: %zu\n", use_data_len);
  debug_print("Usedata = ");
  for (int i = 0; i < use_data_len; i++) {
    debug_print("%02x", use_data[i]);
  }
  debug_print("\n");
  /* debug_print("Symkey = "); */
  /* for (int i = 0; i < EXTRA_SYMMETRIC_KEY_BYTES; i++) { */
  /*   debug_print("%02x", extra_symm_key[i]); */
  /* } */
#endif
}

tstatic otrng_shared_session_state_s
otrng_get_shared_session_state(otrng_s *otr) {
  return otr->client->global_state->callbacks->get_shared_session_state(otr);
}

tstatic int allow_version(const otrng_s *otr, uint8_t version) {
  return (otr->supported_versions & version);
}

/* dst must be at least 3 bytes long. */
tstatic void allowed_versions(string_p dst, const otrng_s *otr) {
  if (allow_version(otr, OTRNG_ALLOW_V4)) {
    *dst++ = '4';
  }

  if (allow_version(otr, OTRNG_ALLOW_V3)) {
    *dst++ = '3';
  }

  *dst = '\0';
}

tstatic const otrng_shared_prekey_pair_s *
our_shared_prekey(const otrng_s *otr) {
  return otr->client->prekey_profile->keys;
}

INTERNAL otrng_s *otrng_new(otrng_client_s *client, otrng_policy_s policy) {
  otrng_s *otr = otrng_xmalloc_z(sizeof(otrng_s));

  otr->client = client;
  otr->state = OTRNG_STATE_START;
  otr->supported_versions = policy.allows;
  otr->policy_type = policy.type;

  otr->running_version = OTRNG_PROTOCOL_VERSION_NONE;

  otr->keys = otrng_key_manager_new();
  otr->smp = otrng_secure_alloc(sizeof(smp_protocol_s));

  otrng_smp_protocol_init(otr->smp);

  return otr;
}

static void free_fragment_context(void *p) { otrng_fragment_context_free(p); }

tstatic void otrng_destroy(/*@only@ */ otrng_s *otr) {
  otrng_free(otr->peer);

  otrng_key_manager_free(otr->keys);
  otr->keys = NULL;

  otrng_client_profile_free(otr->their_client_profile);
  otr->their_client_profile = NULL;

  otrng_prekey_profile_free(otr->their_prekey_profile);
  otr->their_prekey_profile = NULL;

  otrng_smp_destroy(otr->smp);
  otrng_secure_free(otr->smp);
  otr->smp = NULL;

  otrng_list_free(otr->pending_fragments, free_fragment_context);
  otr->pending_fragments = NULL;

  otrng_v3_conn_free(otr->v3_conn);
  otr->v3_conn = NULL;

  otrng_free(otr->shared_session_state);
  otr->shared_session_state = NULL;
}

INTERNAL void otrng_conn_free(/*@only@ */ otrng_s *otr) {
  if (!otr) {
    return;
  }

  otrng_destroy(otr);
  otrng_free(otr);
}

INTERNAL otrng_result otrng_build_query_message(string_p *dst,
                                                const string_p msg,
                                                otrng_s *otr) {
  /* size = qm tag + versions + msg length + versions
   * + question mark + whitespace + null byte */
  size_t qm_size = QUERY_MSG_TAG_BYTES + 3 + strlen(msg) + 2 + 1;
  string_p buffer = NULL;
  char allowed[3];
  char *cursor;
  int rem;
  *dst = NULL;

  memset(allowed, 0, 3);

  if (otr->state == OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return OTRNG_ERROR;
  }

  buffer = otrng_xmalloc_z(qm_size);

  allowed_versions(allowed, otr);

  cursor = otrng_stpcpy(buffer, query_header);
  cursor = otrng_stpcpy(cursor, allowed);
  cursor = otrng_stpcpy(cursor, "? ");

  rem = cursor - buffer;

  /* Add '\0' */
  if (*otrng_stpncpy(cursor, msg, qm_size - rem) != '\0') {
    otrng_free(buffer);
    return OTRNG_ERROR; /* could not zero-terminate the string */
  }

  *dst = buffer;

  return OTRNG_SUCCESS;
}

API otrng_result otrng_build_whitespace_tag(string_p *whitespace_tag,
                                            const string_p msg, otrng_s *otr) {
  char *res;
  int allows_v4 = allow_version(otr, OTRNG_ALLOW_V4);
  int allows_v3 = allow_version(otr, OTRNG_ALLOW_V3);
  string_p cursor = NULL;

  size_t msg_len = strlen(msg);
  size_t base_tag_len = WHITESPACE_TAG_BASE_BYTES;
  size_t v3_tag_len = (allows_v3 ? WHITESPACE_TAG_VERSION_BYTES : 0);
  size_t v4_tag_len = (allows_v4 ? WHITESPACE_TAG_VERSION_BYTES : 0);
  char *buffer = NULL;

  if (v3_tag_len == 0 && v4_tag_len == 0) {
    return OTRNG_ERROR;
  }

  buffer =
      otrng_xmalloc_z(msg_len + base_tag_len + v3_tag_len + v4_tag_len + 1);

  cursor = otrng_stpcpy(buffer, tag_base);

  if (allows_v4) {
    cursor = otrng_stpcpy(cursor, tag_version_v4);
  }

  if (allows_v3) {
    cursor = otrng_stpcpy(cursor, tag_version_v3);
  }

  res = otrng_stpcpy(cursor, msg);
  if (!res) {
    otrng_free(buffer);
    return OTRNG_ERROR;
  }

  *whitespace_tag = buffer;

  return OTRNG_SUCCESS;
}

tstatic otrng_result serialize_and_encode_identity_message(
    string_p *dst, const dake_identity_message_s *msg) {
  uint8_t *buffer = NULL;
  size_t len = 0;

  if (!otrng_dake_identity_message_serialize(&buffer, &len, msg)) {
    return OTRNG_ERROR;
  }

  *dst = otrl_base64_otr_encode(buffer, len);

  otrng_free(buffer);
  return OTRNG_SUCCESS;
}

API otrng_result otrng_build_identity_message(string_p *dst, otrng_s *otr) {
  dake_identity_message_s *msg = NULL;
  otrng_result result;

  otr->running_version = OTRNG_PROTOCOL_VERSION_4;

  if (otrng_key_manager_generate_ephemeral_keys(otr->keys) == OTRNG_ERROR) {
    return OTRNG_ERROR;
  }

  maybe_create_keys(otr->client);

  msg = otrng_dake_identity_message_new(get_my_client_profile(otr));
  if (!msg) {
    return OTRNG_ERROR;
  }

  msg->sender_instance_tag = our_instance_tag(otr);
  msg->receiver_instance_tag = otr->their_instance_tag;

  otrng_ec_point_copy(msg->Y, our_ecdh(otr));
  msg->B = otrng_dh_mpi_copy(our_dh(otr));

  result = serialize_and_encode_identity_message(dst, msg);
  otrng_dake_identity_message_free(msg);

  if (result == OTRNG_ERROR) {
    return result;
  }

  otr->state = OTRNG_STATE_WAITING_AUTH_R;

  return OTRNG_SUCCESS;
}

tstatic otrng_bool message_contains_tag(const string_p msg) {
  return strstr(msg, tag_base) != NULL;
}

tstatic void set_to_display(otrng_response_s *response, const string_p msg) {
  size_t msg_len = strlen(msg);
  response->to_display = otrng_xstrndup(msg, msg_len);
}

tstatic otrng_result message_to_display_without_tag(otrng_response_s *response,
                                                    const string_p msg,
                                                    size_t msg_len) {
  size_t tag_len = 0;
  size_t chars = 0;
  char *found_at;
  string_p buffer;
  size_t bytes_before_tag;

  if ((strstr(msg, tag_version_v4) != NULL) &&
      (strstr(msg, tag_version_v3) != NULL)) {
    tag_len = WHITESPACE_TAG_BASE_BYTES + 2 * WHITESPACE_TAG_VERSION_BYTES;
  } else {
    tag_len = WHITESPACE_TAG_BASE_BYTES + WHITESPACE_TAG_VERSION_BYTES;
  }

  chars = msg_len - tag_len;

  if (msg_len < tag_len) {
    return OTRNG_ERROR;
  }

  found_at = strstr(msg, tag_base);
  if (found_at == NULL) {
    return OTRNG_ERROR;
  }

  buffer = otrng_xmalloc_z(chars + 1);

  bytes_before_tag = found_at - msg;
  if (!bytes_before_tag) {
    strncpy(buffer, msg + tag_len, chars);
  } else {
    strncpy(buffer, msg, bytes_before_tag);
    strncpy(buffer, msg + bytes_before_tag, chars - bytes_before_tag);
  }
  buffer[chars] = '\0';

  response->to_display = otrng_xstrndup(buffer, chars);

  otrng_free(buffer);
  return OTRNG_SUCCESS;
}

tstatic void set_running_version_from_tag(otrng_s *otr, const string_p msg) {
  if (allow_version(otr, OTRNG_ALLOW_V4) &&
      (strstr(msg, tag_version_v4) != NULL)) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_4;
    return;
  }

  if (allow_version(otr, OTRNG_ALLOW_V3) &&
      (strstr(msg, tag_version_v3) != NULL)) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_3;
    return;
  }
}

tstatic otrng_bool message_is_query(const string_p msg) {
  if (strstr(msg, query_header) != NULL) {
    return otrng_true;
  }
  return otrng_false;
}

tstatic void set_running_version_from_query_message(otrng_s *otr,
                                                    const string_p msg) {
  if (allow_version(otr, OTRNG_ALLOW_V4) && (strstr(msg, "4") != NULL)) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_4;
  } else if (allow_version(otr, OTRNG_ALLOW_V3) && (strstr(msg, "3") != NULL)) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_3;
  }
}

tstatic otrng_bool message_is_otr_encoded(const string_p msg) {
  if (strstr(msg, otr_header) != NULL) {
    return otrng_true;
  }
  return otrng_false;
}

tstatic otrng_bool message_is_otr_error(const string_p msg) {
  if (strncmp(msg, otr_error_header, strlen(otr_error_header)) == 0) {
    return otrng_true;
  }
  return otrng_false;
}

INTERNAL otrng_response_s *otrng_response_new(void) {
  otrng_response_s *response = otrng_xmalloc_z(sizeof(otrng_response_s));

  return response;
}

INTERNAL void otrng_response_free(otrng_response_s *response) {
  if (!response) {
    return;
  }

  otrng_free(response->to_display);
  otrng_free(response->to_send);

  otrng_tlv_list_free(response->tlvs);

  otrng_free(response);
}

// TODO: @erroing Is not receiving a plaintext a problem?
tstatic void receive_plaintext(otrng_response_s *response, const string_p msg,
                               const otrng_s *otr) {
  set_to_display(response, msg);

  if (otr->state != OTRNG_STATE_START) {
    otrng_client_callbacks_handle_event(otr->client->global_state->callbacks,
                                        OTRNG_MSG_EVENT_RCV_UNENCRYPTED);
  }
}

tstatic otrng_result reply_with_identity_message(otrng_response_s *response,
                                                 otrng_s *otr) {
  dake_identity_message_s *msg = NULL;
  otrng_result result;

  msg = otrng_dake_identity_message_new(get_my_client_profile(otr));
  if (!msg) {
    return OTRNG_ERROR;
  }

  msg->sender_instance_tag = our_instance_tag(otr);
  msg->receiver_instance_tag = otr->their_instance_tag;

  otrng_ec_point_copy(msg->Y, our_ecdh(otr));
  msg->B = otrng_dh_mpi_copy(our_dh(otr));

  result = serialize_and_encode_identity_message(&response->to_send, msg);
  otrng_dake_identity_message_free(msg);

  return result;
}

tstatic otrng_result start_dake(otrng_response_s *response, otrng_s *otr) {
  if (otrng_key_manager_generate_ephemeral_keys(otr->keys) == OTRNG_ERROR) {
    return OTRNG_ERROR;
  }

  maybe_create_keys(otr->client);
  if (reply_with_identity_message(response, otr) == OTRNG_ERROR) {
    return OTRNG_ERROR;
  }

  otr->state = OTRNG_STATE_WAITING_AUTH_R;

  return OTRNG_SUCCESS;
}

tstatic otrng_result receive_tagged_plaintext(otrng_response_s *response,
                                              const string_p msg,
                                              otrng_s *otr) {
  set_running_version_from_tag(otr, msg);

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_4:
    if (otr->policy_type == OTRNG_REQUIRE_AUTHENTICATED) {
      otrng_known_fingerprint_s *fp_peer;
      fp_peer = otrng_fingerprint_get_current_peer(otr);
      if (!fp_peer || fp_peer->trusted == otrng_false) {
        return OTRNG_ERROR;
      }
    }
    if (otr->policy_type & OTRNG_WHITESPACE_START_DAKE) {
      if (message_to_display_without_tag(response, msg, strlen(msg)) ==
          OTRNG_ERROR) {
        return OTRNG_ERROR;
      }
      return start_dake(response, otr);
    }
    return OTRNG_ERROR;
  case OTRNG_PROTOCOL_VERSION_3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, msg, otr->v3_conn);
  default:
    /* ignore */
    return OTRNG_SUCCESS;
  }
}

tstatic otrng_result receive_query_message(otrng_response_s *response,
                                           const string_p msg, otrng_s *otr) {
  set_running_version_from_query_message(otr, msg);

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_4:
    if (otr->policy_type == OTRNG_REQUIRE_AUTHENTICATED) {
      otrng_known_fingerprint_s *fp_peer;
      fp_peer = otrng_fingerprint_get_current_peer(otr);
      if (!fp_peer || fp_peer->trusted == otrng_false) {
        return OTRNG_ERROR;
      }
    }
    return start_dake(response, otr);
  case OTRNG_PROTOCOL_VERSION_3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, msg, otr->v3_conn);
  default:
    /* ignore */
    return OTRNG_SUCCESS;
  }
}

tstatic otrng_result serialize_and_encode_auth_r(string_p *dst,
                                                 const dake_auth_r_s *auth_r) {
  uint8_t *buffer = NULL;
  size_t len = 0;

  if (!otrng_dake_auth_r_serialize(&buffer, &len, auth_r)) {
    return OTRNG_ERROR;
  }

  *dst = otrl_base64_otr_encode(buffer, len);

  otrng_free(buffer);
  return OTRNG_SUCCESS;
}

tstatic /*@null@*/ char *
otrng_generate_session_state_string(const otrng_shared_session_state_s *state) {
  char *sss;
  size_t sss_len;

  if (!state || !state->identifier1 || !state->identifier2) {
    return NULL;
  }

  sss_len = strlen(state->identifier1) + strlen(state->identifier2) + 1;
  if (state->password) {
    sss_len += strlen(state->password);
  }

  sss = otrng_xmalloc_z(sss_len);

  /* The below calls to strncpy and strncat will always be safe with sss_len as
     the argument, since it's calculated based on the strlen of both things */
  if (strcmp(state->identifier1, state->identifier2) < 0) {
    strncpy(sss, state->identifier1, sss_len);
    strncat(sss, state->identifier2, sss_len);
  } else {
    strncpy(sss, state->identifier2, sss_len);
    strncat(sss, state->identifier1, sss_len);
  }

  if (state->password) {
    strncat(sss, state->password, sss_len);
  }

  return sss;
}

/*@null@*/ static const char *get_shared_session_state(otrng_s *otr) {
  otrng_shared_session_state_s state;

  if (otr->shared_session_state) {
    return otr->shared_session_state;
  }

  state = otrng_get_shared_session_state(otr);
  otr->shared_session_state = otrng_generate_session_state_string(&state);

  otrng_free(state.identifier1);
  otrng_free(state.identifier2);
  otrng_free(state.password);

  return otr->shared_session_state;
}

static otrng_result generate_phi_serialized(uint8_t **dst, size_t *dst_len,
                                            const char *phi_prime,
                                            uint16_t instance_tag1,
                                            uint16_t instance_tag2) {
  size_t phi_prime_len, size;

  if (!phi_prime) {
    return OTRNG_ERROR;
  }

  /*
   * phi = smaller instance tag || larger instance tag || phi'
   */
  phi_prime_len = strlen(phi_prime) + 1;
  size = 4 + 4 + (4 + phi_prime_len);
  *dst = otrng_xmalloc_z(size);

  *dst_len = otrng_serialize_phi(*dst, phi_prime, instance_tag1, instance_tag2);

  return OTRNG_SUCCESS;
}

static otrng_result generate_phi_receiving(uint8_t **dst, size_t *dst_len,
                                           otrng_s *otr) {
  return generate_phi_serialized(dst, dst_len, get_shared_session_state(otr),
                                 our_instance_tag(otr),
                                 otr->their_instance_tag);
}

static otrng_result generate_phi_sending(uint8_t **dst, size_t *dst_len,
                                         otrng_s *otr) {
  return generate_phi_serialized(dst, dst_len, get_shared_session_state(otr),
                                 our_instance_tag(otr),
                                 otr->their_instance_tag);
}

static otrng_result generate_sending_rsig_tag(uint8_t **dst, size_t *dst_len,
                                              const char auth_tag_type,
                                              otrng_s *otr) {
  const otrng_dake_participant_data_s initiator = {
      .client_profile = otr->their_client_profile,
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(otr->keys->their_ecdh),
      .dh = their_dh(otr),
  };

  const otrng_dake_participant_data_s responder = {
      .client_profile = (otrng_client_profile_s *)get_my_client_profile(otr),
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(otr->keys->our_ecdh->pub),
      .dh = our_dh(otr),
  };

  uint8_t *phi = NULL;
  size_t phi_len = 0;
  otrng_result ret;
  if (!generate_phi_sending(&phi, &phi_len, otr)) {
    return OTRNG_ERROR;
  }

  ret = build_interactive_rsign_tag(dst, dst_len, auth_tag_type, &initiator,
                                    &responder, phi, phi_len);

  otrng_free(phi);
  return ret;
}

static otrng_result generate_receiving_rsig_tag(
    uint8_t **dst, size_t *dst_len, const char auth_tag_type,
    const otrng_dake_participant_data_s *responder, otrng_s *otr) {
  const otrng_dake_participant_data_s initiator = {
      .client_profile = (otrng_client_profile_s *)get_my_client_profile(otr),
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(otr->keys->our_ecdh->pub),
      .dh = our_dh(otr),
  };

  uint8_t *phi = NULL;
  size_t phi_len = 0;
  otrng_result ret;
  if (!generate_phi_receiving(&phi, &phi_len, otr)) {
    return OTRNG_ERROR;
  }

  ret = build_interactive_rsign_tag(dst, dst_len, auth_tag_type, &initiator,
                                    responder, phi, phi_len);

  otrng_free(phi);
  return ret;
}

tstatic otrng_result reply_with_auth_r_message(string_p *dst, otrng_s *otr) {
  dake_auth_r_s msg;
  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_result result;

  msg.sender_instance_tag = 0;
  msg.receiver_instance_tag = 0;
  msg.profile = NULL;
  msg.sigma = NULL;

  otrng_dake_auth_r_init(&msg);

  msg.sender_instance_tag = our_instance_tag(otr);
  msg.receiver_instance_tag = otr->their_instance_tag;

  if (!otrng_client_profile_copy(msg.profile, get_my_client_profile(otr))) {
    otrng_dake_auth_r_destroy(&msg);
    return OTRNG_ERROR;
  }

  otrng_ec_point_copy(msg.X, our_ecdh(otr));
  msg.A = otrng_dh_mpi_copy(our_dh(otr));

  if (!generate_sending_rsig_tag(&t, &t_len, 'r', otr)) {
    otrng_dake_auth_r_destroy(&msg);
    return OTRNG_ERROR;
  }

  /* sigma = RSig(H_a, sk_ha, {F_b, H_a, Y}, t) */
  if (!otrng_rsig_authenticate(
          msg.sigma, otr->client->keypair->priv,      /* sk_ha */
          otr->client->keypair->pub,                  /* H_a */
          otr->their_client_profile->forging_pub_key, /* F_b */
          otr->client->keypair->pub,                  /* H_a */
          their_ecdh(otr),                            /* Y */
          t, t_len)) {
    otrng_free(t);
    otrng_dake_auth_r_destroy(&msg);
    return OTRNG_ERROR;
  }

  otrng_free(t);

  result = serialize_and_encode_auth_r(dst, &msg);
  otrng_dake_auth_r_destroy(&msg);

  return result;
}

tstatic otrng_result generate_tmp_key(uint8_t *dst, otrng_s *otr,
                                      otrng_bool is_i) {
  k_ecdh ecdh_key;
  k_ecdh tmp_ecdh_k1;
  k_ecdh tmp_ecdh_k2;
  dh_shared_secret dh_key;
  size_t dh_key_len = 0;
  k_brace brace_key;
  ec_scalar priv;
  ec_point pub;

  // TODO: @refactoring this workaround is not the nicest there is
  if (!otrng_ecdh_shared_secret(ecdh_key, ED448_POINT_BYTES,
                                otr->keys->our_ecdh->priv,
                                otr->keys->their_ecdh)) {
    return OTRNG_ERROR;
  }

  if (!otrng_dh_shared_secret(dh_key, &dh_key_len, otr->keys->our_dh->priv,
                              otr->keys->their_dh)) {
    return OTRNG_ERROR;
  }

  hash_hash(brace_key, BRACE_KEY_BYTES, dh_key, dh_key_len);

  otrng_secure_wipe(dh_key, DH3072_MOD_LEN_BYTES);

  if (is_i) {
    *priv = *our_shared_prekey(otr)->priv;
    *pub = *their_ecdh(otr);
  } else {
    *priv = *otr->keys->our_ecdh->priv;
    *pub = *otr->keys->their_shared_prekey;
  }

  if (!otrng_ecdh_shared_secret(tmp_ecdh_k1, ED448_POINT_BYTES, priv, pub)) {
    return OTRNG_ERROR;
  }

  if (is_i) {
    *priv = *otr->client->keypair->priv;
    *pub = *their_ecdh(otr);
  } else {
    *priv = *otr->keys->our_ecdh->priv;
    *pub = *otr->their_client_profile->long_term_pub_key;
  }

  if (!otrng_ecdh_shared_secret(tmp_ecdh_k2, ED448_POINT_BYTES, priv, pub)) {
    return OTRNG_ERROR;
  }

  if (!otrng_key_manager_calculate_tmp_key(dst, ecdh_key, brace_key,
                                           tmp_ecdh_k1, tmp_ecdh_k2)) {
    return OTRNG_ERROR;
  }

  otrng_secure_wipe(brace_key, BRACE_KEY_BYTES);
  otrng_secure_wipe(tmp_ecdh_k1, ED448_POINT_BYTES);
  otrng_secure_wipe(tmp_ecdh_k2, ED448_POINT_BYTES);

  return OTRNG_SUCCESS;
}

tstatic otrng_result generate_tmp_key_r(uint8_t *dst, otrng_s *otr) {
  return generate_tmp_key(dst, otr, otrng_false);
}

tstatic otrng_result serialize_and_encode_non_interactive_auth(
    string_p *dst, const dake_non_interactive_auth_message_s *msg) {
  uint8_t *buffer = NULL;
  size_t len = 0;

  if (!otrng_dake_non_interactive_auth_message_serialize(&buffer, &len, msg)) {
    return OTRNG_ERROR;
  }

  *dst = otrl_base64_otr_encode(buffer, len);

  otrng_free(buffer);
  return OTRNG_SUCCESS;
}

// TODO: move this to the dake file
tstatic otrng_bool non_interactive_auth_message_init(
    dake_non_interactive_auth_message_s *auth, otrng_s *otr) {
  auth->sender_instance_tag = our_instance_tag(otr);
  auth->receiver_instance_tag = otr->their_instance_tag;

  if (!otrng_client_profile_copy(auth->profile, get_my_client_profile(otr))) {
    return otrng_false;
  }

  // TODO: is this set?
  otrng_ec_point_copy(auth->X, our_ecdh(otr));
  auth->A = otrng_dh_mpi_copy(our_dh(otr));

  auth->prekey_message_id = 0;

  return otrng_true;
}

tstatic otrng_result build_non_interactive_auth_message(
    dake_non_interactive_auth_message_s *auth, otrng_s *otr) {
  uint8_t *phi = NULL;
  size_t phi_len = 0;
  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_result ret;

  const otrng_dake_participant_data_s initiator = {
      .client_profile = otr->their_client_profile,
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(otr->keys->their_ecdh),
      .dh = their_dh(otr),
  };

  const otrng_dake_participant_data_s responder = {
      .client_profile = (otrng_client_profile_s *)get_my_client_profile(otr),
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(otr->keys->our_ecdh->pub),
      .dh = our_dh(otr),
  };

  if (!non_interactive_auth_message_init(auth, otr)) {
    return OTRNG_ERROR;
  }

  auth->prekey_message_id = otr->their_prekeys_id;
  otr->their_prekeys_id = 0;

  /* tmp_k = KDF_1(usage_tmp_key || K_ecdh || ECDH(x, their_shared_prekey) ||
     ECDH(x, Pkb) || brace_key)
     @secret this should be deleted when the mixed shared secret is generated
  */
  if (!generate_tmp_key_r(otr->keys->tmp_key, otr)) {
    return OTRNG_ERROR;
  }

  if (!generate_phi_receiving(&phi, &phi_len, otr)) {
    return OTRNG_ERROR;
  }

  /* t = KDF_1(usageNonIntAuthBobClientProfile || Bob_Client_Profile, 64) ||
   * KDF_1(usageNonIntAuthAliceClientProfile || Alice_Client_Profile, 64) || Y
   * || X || B || A || their_shared_prekey || KDF_1(usageNonIntAuthPhi || phi,
   * 64) */
  if (!build_non_interactive_rsign_tag(&t, &t_len, &initiator, &responder,
                                       otr->keys->their_shared_prekey, phi,
                                       phi_len)) {
    otrng_free(phi);
    return OTRNG_ERROR;
  }

  otrng_free(phi);

  /* sigma = RSig(H_a, sk_ha, {F_b, H_a, Y}, t) */
  if (!otrng_rsig_authenticate(
          auth->sigma, otr->client->keypair->priv,    /* sk_ha */
          otr->client->keypair->pub,                  /* H_a */
          otr->their_client_profile->forging_pub_key, /* F_b */
          otr->client->keypair->pub,                  /* H_a */
          their_ecdh(otr),                            /* Y */
          t, t_len)) {
    otrng_free(t);
    return OTRNG_ERROR;
  }

  ret = otrng_dake_non_interactive_auth_message_authenticator(
      auth->auth_mac, auth, t, t_len, otr->keys->tmp_key);

  otrng_free(t);

  return ret;
}

tstatic otrng_result double_ratcheting_init(otrng_s *otr,
                                            const char participant) {
  if (!otrng_key_manager_ratcheting_init(otr->keys, participant)) {
    return OTRNG_ERROR;
  }

  otr->state = OTRNG_STATE_ENCRYPTED_MESSAGES;
  gone_secure_cb_v4(otr);
  otrng_key_manager_wipe_shared_prekeys(otr->keys);

  return OTRNG_SUCCESS;
}

tstatic otrng_result reply_with_non_interactive_auth_message(string_p *dst,
                                                             otrng_s *otr) {
  dake_non_interactive_auth_message_s auth;
  otrng_dake_non_interactive_auth_message_init(&auth);
  maybe_create_keys(otr->client);

  if (otrng_failed(build_non_interactive_auth_message(&auth, otr))) {
    otrng_dake_non_interactive_auth_message_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (otrng_failed(serialize_and_encode_non_interactive_auth(dst, &auth))) {
    otrng_dake_non_interactive_auth_message_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (otrng_failed(
          otrng_key_manager_generate_shared_secret(otr->keys, otrng_false))) {
    otrng_dake_non_interactive_auth_message_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (!double_ratcheting_init(otr, 't')) {
    otrng_dake_non_interactive_auth_message_destroy(&auth);
    return OTRNG_ERROR;
  }

  otrng_dake_non_interactive_auth_message_destroy(&auth);

  return OTRNG_SUCCESS;
}

/* This is only used for tests */
INTERNAL /*@null@*/ prekey_ensemble_s *
otrng_build_prekey_ensemble(otrng_s *otr) {
  ecdh_keypair_s ecdh;
  dh_keypair_s dh;
  otrng_client_s *client;

  prekey_ensemble_s *ensemble = otrng_prekey_ensemble_new();

  if (!otrng_client_profile_copy(ensemble->client_profile,
                                 get_my_client_profile(otr))) {
    otrng_prekey_ensemble_free(ensemble);
    return NULL;
  }

  otrng_prekey_profile_copy(ensemble->prekey_profile,
                            get_my_prekey_profile(otr));

  if (!otrng_generate_ephemeral_keys(&ecdh, &dh)) {
    otrng_prekey_ensemble_free(ensemble);
    return NULL;
  }

  ensemble->message =
      otrng_prekey_message_build(our_instance_tag(otr), &ecdh, &dh);
  if (!ensemble->message) {
    otrng_prekey_ensemble_free(ensemble);
    return NULL;
  }

  client = otr->client;
  otrng_client_store_my_prekey_message(
      otrng_prekey_message_create_copy(ensemble->message), client);
  otrng_ecdh_keypair_destroy(&ecdh);
  otrng_dh_keypair_destroy(&dh);

  return ensemble;
}

tstatic otrng_result
set_their_client_profile(const otrng_client_profile_s *profile, otrng_s *otr) {
  // The protocol is already committed to a specific profile, and receives an
  // ensemble with another profile.
  // How should the protocol behave? I am failling for now.
  if (otr->their_client_profile) {
    return OTRNG_ERROR;
  }

  otr->their_client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));

  if (!otrng_client_profile_copy(otr->their_client_profile, profile)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result
set_their_prekey_profile(const otrng_prekey_profile_s *profile, otrng_s *otr) {
  // The protocol is already committed to a specific profile, and receives an
  // ensemble with another profile.
  // How should the protocol behave? I am failling for now.
  if (otr->their_prekey_profile) {
    return OTRNG_ERROR;
  }

  otr->their_prekey_profile = otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));

  otrng_prekey_profile_copy(otr->their_prekey_profile, profile);

  otrng_ec_point_copy(otr->keys->their_shared_prekey,
                      otr->their_prekey_profile->shared_prekey);

  return OTRNG_SUCCESS;
}

tstatic otrng_result received_sender_instance_tag(uint32_t their_instance_tag,
                                                  otrng_s *otr) {
  if (otrng_instance_tag_valid(their_instance_tag) == otrng_false) {
    return OTRNG_ERROR;
  }

  otr->their_instance_tag = their_instance_tag;

  return OTRNG_SUCCESS;
}

static otrng_bool valid_receiver_instance_tag(uint32_t instance_tag) {
  if (instance_tag == 0) {
    return otrng_false;
  }

  if (otrng_instance_tag_valid(instance_tag) == otrng_false) {
    return otrng_false;
  }

  return otrng_true;
}

tstatic otrng_result prekey_message_received(const prekey_message_s *msg,
                                             otrng_s *otr) {
  if (!otr->their_client_profile) {
    return OTRNG_ERROR;
  }

  if (!otr->their_prekey_profile) {
    return OTRNG_ERROR;
  }

  if (received_sender_instance_tag(msg->sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    otrng_client_callbacks_handle_event(otr->client->global_state->callbacks,
                                        OTRNG_MSG_EVENT_MALFORMED_PREKEY);
    return OTRNG_ERROR;
  }

  if (!otrng_valid_received_values(msg->sender_instance_tag, msg->Y, msg->B,
                                   otr->their_client_profile)) {
    return OTRNG_ERROR;
  }

  otr->their_prekeys_id = msg->id; /* Store for the non-interactive-auth */
  otrng_key_manager_set_their_ecdh(msg->Y, otr->keys);
  otrng_key_manager_set_their_dh(msg->B, otr->keys);

  if (!otrng_key_manager_generate_ephemeral_keys(otr->keys)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result ensure_client_profile_version(char *versions,
                                                   otrng_s *otr) {
  while (*versions != '\0') {
    if (*versions == '4' && (otr->supported_versions == OTRNG_ALLOW_V4 ||
                             otr->supported_versions == OTRNG_ALLOW_V34)) {
      return OTRNG_SUCCESS;
    }

    if (*versions == '3' && (otr->supported_versions == OTRNG_ALLOW_V3 ||
                             otr->supported_versions == OTRNG_ALLOW_V34)) {
      return OTRNG_SUCCESS;
    }
    versions++;
  }

  return OTRNG_ERROR;
}

tstatic otrng_result receive_prekey_ensemble(const prekey_ensemble_s *ensemble,
                                             otrng_s *otr) {
  if (!otrng_prekey_ensemble_validate(ensemble)) {
    return OTRNG_ERROR;
  }

  if (!ensure_client_profile_version(ensemble->client_profile->versions, otr)) {
    return OTRNG_ERROR;
  }

  // TODO: @non_interactive Decide whether to send a message using this Prekey
  // Ensemble if the long-term key within the Client Profile is trusted or not.
  // Maybe use a callback for this.
  if (!set_their_client_profile(ensemble->client_profile, otr)) {
    return OTRNG_ERROR;
  }

  if (!set_their_prekey_profile(ensemble->prekey_profile, otr)) {
    return OTRNG_ERROR;
  }

  /* Set their ephemeral keys, instance tag, and their_prekeys_id */
  if (!prekey_message_received(ensemble->message, otr)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_send_non_interactive_auth(
    char **dst, const prekey_ensemble_s *ensemble, otrng_s *otr) {
  otrng_fingerprint fp;
  *dst = NULL;

  if (!receive_prekey_ensemble(ensemble, otr)) {
    return OTRNG_ERROR; // TODO: should unset the stored things from ensemble
  }

  otr->running_version = OTRNG_PROTOCOL_VERSION_4;

  if (otrng_serialize_fingerprint(fp,
                                  otr->their_client_profile->long_term_pub_key,
                                  otr->their_client_profile->forging_pub_key)) {
    fingerprint_seen_cb_v4(fp, otr);
  }

  return reply_with_non_interactive_auth_message(dst, otr);
}

tstatic otrng_result generate_tmp_key_i(uint8_t *dst, otrng_s *otr) {
  return generate_tmp_key(dst, otr, otrng_true);
}

tstatic otrng_bool verify_non_interactive_auth_message(
    const dake_non_interactive_auth_message_s *auth, otrng_s *otr) {
  uint8_t *phi = NULL;
  size_t phi_len = 0;
  unsigned char *t = NULL;
  size_t t_len = 0;
  uint8_t mac_tag[DATA_MSG_MAC_BYTES];

  const otrng_dake_participant_data_s initiator = {
      .client_profile = (otrng_client_profile_s *)get_my_client_profile(otr),
      .exp_client_profile =
          (otrng_client_profile_s *)get_my_exp_client_profile(otr),
      .prekey_profile = (otrng_prekey_profile_s *)get_my_prekey_profile(otr),
      .exp_prekey_profile =
          (otrng_prekey_profile_s *)get_my_exp_prekey_profile(otr),
      .ecdh = *(otr->keys->our_ecdh->pub),
      .dh = our_dh(otr),
  };

  const otrng_dake_participant_data_s responder = {
      .client_profile = (otrng_client_profile_s *)auth->profile,
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(auth->X),
      .dh = auth->A,
  };

  if (!initiator.prekey_profile) {
    return otrng_false;
  }

  if (!generate_phi_sending(&phi, &phi_len, otr)) {
    return otrng_false;
  }

  /* t = KDF_2(Bobs_User_Profile) || KDF_2(Alices_User_Profile) ||
   * Y || X || B || A || our_shared_prekey.public */
  if (!build_non_interactive_rsign_tag(&t, &t_len, &initiator, &responder,
                                       initiator.prekey_profile->shared_prekey,
                                       phi, phi_len)) {
    otrng_free(phi);
    return otrng_false;
  }

  /* RVrf({F_b, H_a, Y}, sigma, message) */
  if (!otrng_rsig_verify(auth->sigma, *otr->client->forging_key, /* F_b */
                         auth->profile->long_term_pub_key,       /* H_a */
                         our_ecdh(otr),                          /* Y  */
                         t, t_len)) {
    otrng_free(t);
    t = NULL;

    if ((initiator.exp_client_profile != NULL) &&
        (initiator.exp_prekey_profile != NULL)) {
      /* the fallback */
      if (!build_fallback_non_interactive_rsign_tag(
              &t, &t_len, &initiator, &responder,
              initiator.exp_prekey_profile->shared_prekey, phi, phi_len)) {
        otrng_free(phi);
        return otrng_false;
      }

      otrng_free(phi);

      if (!otrng_rsig_verify(auth->sigma, *otr->client->forging_key, /* H_b */
                             auth->profile->long_term_pub_key,       /* H_a */
                             our_ecdh(otr),                          /* Y  */
                             t, t_len)) {
        otrng_free(t);
        return otrng_false;
      }

      return otrng_false;
    }
  }

  otrng_free(phi);

  /* Check mac */
  if (!otrng_dake_non_interactive_auth_message_authenticator(
          mac_tag, auth, t, t_len, otr->keys->tmp_key)) {
    otrng_free(t);
    /* here no warning should be passed */
    return otrng_false;
  }

  otrng_free(t);

  /* here no warning should be passed */
  if (sodium_memcmp(mac_tag, auth->auth_mac, DATA_MSG_MAC_BYTES) != 0) {
    otrng_secure_wipe(mac_tag, DATA_MSG_MAC_BYTES);
    return otrng_false;
  }

  return otrng_true;
}

tstatic otrng_result non_interactive_auth_message_received(
    otrng_response_s *response, const dake_non_interactive_auth_message_s *auth,
    otrng_s *otr) {
  otrng_client_s *client = otr->client;
  const prekey_message_s *stored_prekey = NULL;
  otrng_fingerprint fp;

  if (!client) {
    return OTRNG_ERROR;
  }

  if (received_sender_instance_tag(auth->sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_MALFORMED);
    return OTRNG_ERROR;
  }

  if (valid_receiver_instance_tag(auth->receiver_instance_tag) == otrng_false) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_MALFORMED);
    return OTRNG_ERROR;
  }

  if (!otrng_valid_received_values(auth->sender_instance_tag, auth->X, auth->A,
                                   auth->profile)) {
    return OTRNG_ERROR;
  }

  stored_prekey =
      otrng_client_get_prekey_by_id(auth->prekey_message_id, otr->client);
  if (!stored_prekey) {
    // TODO: this should send an error to the plugin
    return OTRNG_ERROR;
  }

  // Check if the state is consistent. This must be removed and simplified.
  // If the state is not, we may need to update our current  (client and/or
  // prekey) profiles to a profile from the past.

  // Long-term keypair is the same as used to generate my current client
  // profile.
  // Should be always true, though.
  if (!otrng_ec_point_eq(otr->client->keypair->pub,
                         get_my_client_profile(otr)->long_term_pub_key)) {
    return OTRNG_ERROR;
  }

  if (!otrng_ec_point_eq(our_shared_prekey(otr)->pub,
                         get_my_prekey_profile(otr)->shared_prekey)) {
    return OTRNG_ERROR;
  }

  /* Set our current ephemeral keys, based on the received message */
  otrng_ecdh_keypair_destroy(otr->keys->our_ecdh);
  otrng_ec_scalar_copy(otr->keys->our_ecdh->priv, stored_prekey->y->priv);
  otrng_ec_point_copy(otr->keys->our_ecdh->pub, stored_prekey->y->pub);

  otrng_dh_keypair_destroy(otr->keys->our_dh);
  otr->keys->our_dh->priv = otrng_dh_mpi_copy(stored_prekey->b->priv);
  otr->keys->our_dh->pub = otrng_dh_mpi_copy(stored_prekey->b->pub);

  // TODO: this has to happen long before, for this to work
  if (auth->receiver_instance_tag != stored_prekey->sender_instance_tag) {
    return OTRNG_SUCCESS;
  }

  /* Delete the stored prekeys for this ID so they can't be used again. */
  otrng_client_delete_my_prekey_message_by_id(auth->prekey_message_id, client);

  otrng_key_manager_set_their_ecdh(auth->X, otr->keys);
  otrng_key_manager_set_their_dh(auth->A, otr->keys);

  // TODO: @client_profile Extract function to set_their_client_profile
  otr->their_client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));

  if (!otrng_client_profile_copy(otr->their_client_profile, auth->profile)) {
    return OTRNG_ERROR;
  }

  /* tmp_k = KDF_1(usage_tmp_key || K_ecdh ||
   * ECDH(x, our_shared_prekey.secret, their_ecdh) ||
   * ECDH(Ska, X) || brace_key) */
  if (!generate_tmp_key_i(otr->keys->tmp_key, otr)) {
    return OTRNG_ERROR;
  }

  // TODO: this should happen before we change any internal state
  if (!verify_non_interactive_auth_message(auth, otr)) {
    return OTRNG_ERROR;
  }

  if (otrng_serialize_fingerprint(fp,
                                  otr->their_client_profile->long_term_pub_key,
                                  otr->their_client_profile->forging_pub_key)) {
    fingerprint_seen_cb_v4(fp, otr);
  }

  if (!otrng_key_manager_generate_shared_secret(otr->keys, otrng_false)) {
    return OTRNG_ERROR;
  }

  if (!double_ratcheting_init(otr, 'u')) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result receive_non_interactive_auth_message(
    otrng_response_s *response, const uint8_t *src, size_t len, otrng_s *otr) {
  dake_non_interactive_auth_message_s auth;

  otrng_dake_non_interactive_auth_message_init(&auth);
  if (otr->state == OTRNG_STATE_FINISHED) {
    return OTRNG_SUCCESS; /* ignore the message */
  }

  if (!otrng_dake_non_interactive_auth_message_deserialize(&auth, src, len)) {
    return OTRNG_ERROR;
  }

  if (otrng_failed(
          non_interactive_auth_message_received(response, &auth, otr))) {
    otrng_dake_non_interactive_auth_message_destroy(&auth);
    return OTRNG_ERROR;
  }

  otr->state = OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE;

  otrng_dake_non_interactive_auth_message_destroy(&auth);

  return OTRNG_SUCCESS;
}

tstatic otrng_result receive_identity_message_on_state_start(
    string_p *dst, dake_identity_message_s *identity_msg, otrng_s *otr) {
  otr->their_client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));

  otrng_key_manager_set_their_ecdh(identity_msg->Y, otr->keys);
  otrng_key_manager_set_their_dh(identity_msg->B, otr->keys);

  if (!otrng_client_profile_copy(otr->their_client_profile,
                                 identity_msg->profile)) {
    return OTRNG_ERROR;
  }

  /* @secret the priv parts will be deleted once the mixed shared secret is
   * derived */
  if (!otrng_key_manager_generate_ephemeral_keys(otr->keys)) {
    return OTRNG_ERROR;
  }

  if (!reply_with_auth_r_message(dst, otr)) {
    return OTRNG_ERROR;
  }

  /* @secret the shared secret will be deleted once the double ratchet is
   * initialized */
  if (!otrng_key_manager_generate_shared_secret(otr->keys, otrng_true)) {
    return OTRNG_ERROR;
  }

  otr->state = OTRNG_STATE_WAITING_AUTH_I;

  return OTRNG_SUCCESS;
}

tstatic void forget_our_keys(otrng_s *otr) {
  otrng_key_manager_destroy(otr->keys);
  otrng_key_manager_init(otr->keys);
}

tstatic otrng_result receive_identity_message_on_waiting_auth_r(
    string_p *dst, dake_identity_message_s *msg, otrng_s *otr) {
  int cmp = gcry_mpi_cmp(our_dh(otr), msg->B);

  /* If our is higher, ignore. */
  if (cmp > 0) {
    // TODO: @state_machine this should resend the prev identity message
    return OTRNG_SUCCESS;
  }

  // Every time we call 'otrng_key_manager_generate_ephemeral_keys'
  // keys get deleted and replaced
  // forget_our_keys(otr);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

tstatic otrng_result receive_identity_message_on_waiting_auth_i(
    string_p *dst, dake_identity_message_s *msg, otrng_s *otr) {
  // Every time we call 'otrng_key_manager_generate_ephemeral_keys'
  // keys get deleted and replaced
  // forget_our_keys(otr);
  otrng_client_profile_free(otr->their_client_profile);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

tstatic otrng_result receive_identity_message(string_p *dst,
                                              const uint8_t *buffer,
                                              size_t buff_len, otrng_s *otr) {
  otrng_result result = OTRNG_ERROR;
  dake_identity_message_s msg;
  msg.profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));
  msg.sender_instance_tag = 0;
  msg.receiver_instance_tag = 0;
  msg.B = NULL;

  if (!otrng_dake_identity_message_deserialize(&msg, buffer, buff_len)) {
    otrng_free(msg.profile);
    return result;
  }

  if (received_sender_instance_tag(msg.sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    otrng_dake_identity_message_destroy(&msg);
    return result;
  }

  if (!otrng_valid_received_values(msg.sender_instance_tag, msg.Y, msg.B,
                                   msg.profile)) {
    otrng_dake_identity_message_destroy(&msg);
    return result;
  }

  switch (otr->state) {
  case OTRNG_STATE_START:
    result = receive_identity_message_on_state_start(dst, &msg, otr);
    break;
  case OTRNG_STATE_WAITING_AUTH_R:
    result = receive_identity_message_on_waiting_auth_r(dst, &msg, otr);
    break;
  case OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE:
  case OTRNG_STATE_WAITING_AUTH_I:
    result = receive_identity_message_on_waiting_auth_i(dst, &msg, otr);
    break;
  case OTRNG_STATE_NONE:
  case OTRNG_STATE_ENCRYPTED_MESSAGES:
  case OTRNG_STATE_FINISHED:
    result = receive_identity_message_on_state_start(dst, &msg, otr);
    break;
  default:
    break;
  }

  otrng_dake_identity_message_destroy(&msg);
  return result;
}

tstatic otrng_result serialize_and_encode_auth_i(string_p *dst,
                                                 const dake_auth_i_s *msg) {
  uint8_t *buffer = NULL;
  size_t len = 0;

  if (!otrng_dake_auth_i_serialize(&buffer, &len, msg)) {
    return OTRNG_ERROR;
  }

  *dst = otrl_base64_otr_encode(buffer, len);

  otrng_free(buffer);
  return OTRNG_SUCCESS;
}

tstatic otrng_result reply_with_auth_i_message(
    string_p *dst, const otrng_client_profile_s *their_client_profile,
    otrng_s *otr) {
  dake_auth_i_s msg;

  const otrng_dake_participant_data_s responder = {
      .client_profile = (otrng_client_profile_s *)their_client_profile,
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(otr->keys->their_ecdh),
      .dh = their_dh(otr),
  };

  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_result result;

  msg.sigma = NULL;

  otrng_dake_auth_i_init(&msg);
  msg.sender_instance_tag = our_instance_tag(otr);
  msg.receiver_instance_tag = otr->their_instance_tag;

  if (!generate_receiving_rsig_tag(&t, &t_len, 'i', &responder, otr)) {
    return OTRNG_ERROR;
  }

  /* sigma = RSig(H_b, sk_hb, {H_b, F_a, X}, t) */
  if (!otrng_rsig_authenticate(msg.sigma,
                               otr->client->keypair->priv, /* sk_hb */
                               otr->client->keypair->pub,  /* H_b */
                               otr->client->keypair->pub,  /* H_b */
                               their_client_profile->forging_pub_key, /* F_a */
                               their_ecdh(otr),                       /* X */
                               t, t_len)) {
    otrng_free(t);
    return OTRNG_ERROR;
  }

  otrng_free(t);

  result = serialize_and_encode_auth_i(dst, &msg);
  otrng_dake_auth_i_destroy(&msg);

  return result;
}

tstatic otrng_bool valid_auth_r_message(const dake_auth_r_s *auth,
                                        otrng_s *otr) {
  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_bool err;

  const otrng_dake_participant_data_s responder = {
      .client_profile = (otrng_client_profile_s *)auth->profile,
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(auth->X),
      .dh = auth->A,
  };

  if (!otrng_valid_received_values(auth->sender_instance_tag, auth->X, auth->A,
                                   auth->profile)) {
    return otrng_false;
  }

  if (!generate_receiving_rsig_tag(&t, &t_len, 'r', &responder, otr)) {
    return otrng_false;
  }

  /* RVrf({F_b, H_a, Y}, sigma, message) */
  err = otrng_rsig_verify(auth->sigma, *otr->client->forging_key, /* F_b */
                          auth->profile->long_term_pub_key,       /* H_a */
                          our_ecdh(otr),                          /* Y */
                          t, t_len);

  otrng_free(t);
  return err;
}

tstatic otrng_result receive_auth_r(string_p *dst, const uint8_t *buffer,
                                    size_t buff_len, otrng_s *otr) {
  dake_auth_r_s auth;
  otrng_fingerprint fp;
  otrng_result ret;

  auth.receiver_instance_tag = 0;
  auth.sender_instance_tag = 0;
  auth.A = NULL;
  auth.profile = NULL;

  otrng_dake_auth_r_init(&auth);

  if (otr->state != OTRNG_STATE_WAITING_AUTH_R) {
    otrng_dake_auth_r_destroy(&auth);
    return OTRNG_SUCCESS; /* ignore the message */
  }

  if (!otrng_dake_auth_r_deserialize(&auth, buffer, buff_len)) {
    otrng_dake_auth_r_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (auth.receiver_instance_tag != our_instance_tag(otr)) {
    otrng_dake_auth_r_destroy(&auth);
    return OTRNG_SUCCESS;
  }

  if (received_sender_instance_tag(auth.sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    otrng_dake_auth_r_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (valid_receiver_instance_tag(auth.receiver_instance_tag) == otrng_false) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    otrng_dake_auth_r_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (!valid_auth_r_message(&auth, otr)) {
    otrng_dake_auth_r_destroy(&auth);
    return OTRNG_ERROR;
  }

  otr->their_client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));

  otrng_key_manager_set_their_ecdh(auth.X, otr->keys);
  otrng_key_manager_set_their_dh(auth.A, otr->keys);

  if (!otrng_client_profile_copy(otr->their_client_profile, auth.profile)) {
    otrng_dake_auth_r_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (!reply_with_auth_i_message(dst, otr->their_client_profile, otr)) {
    otrng_dake_auth_r_destroy(&auth);
    return OTRNG_ERROR;
  }

  otrng_dake_auth_r_destroy(&auth);

  if (otrng_serialize_fingerprint(fp,
                                  otr->their_client_profile->long_term_pub_key,
                                  otr->their_client_profile->forging_pub_key)) {
    fingerprint_seen_cb_v4(fp, otr);
  }

  /* @secret the shared secret will be deleted once the double ratchet is
   * initialized */
  if (!otrng_key_manager_generate_shared_secret(otr->keys, otrng_true)) {
    return OTRNG_ERROR;
  }

  // TODO: Refactor
  ret = double_ratcheting_init(otr, 'u');
  otr->state = OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE;

  return ret;
}

tstatic otrng_bool valid_auth_i_message(const dake_auth_i_s *auth,
                                        otrng_s *otr) {
  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_bool err;

  if (!generate_sending_rsig_tag(&t, &t_len, 'i', otr)) {
    return otrng_false;
  }

  /* RVrf({H_b, F_a, X}, sigma, message) */
  err = otrng_rsig_verify(
      auth->sigma, otr->their_client_profile->long_term_pub_key, /* H_b */
      *otr->client->forging_key,                                 /* F_a */
      our_ecdh(otr),                                             /* X */
      t, t_len);

  otrng_free(t);

  return err;
}

tstatic otrng_result receive_auth_i(char **dst, const uint8_t *buffer,
                                    size_t buff_len, otrng_s *otr) {
  dake_auth_i_s auth;
  otrng_fingerprint fp;

  auth.receiver_instance_tag = 0;
  auth.sender_instance_tag = 0;

  otrng_dake_auth_i_init(&auth);
  if (otr->state != OTRNG_STATE_WAITING_AUTH_I) {
    otrng_dake_auth_i_destroy(&auth);
    return OTRNG_SUCCESS; /* Ignore the message */
  }

  if (!otrng_dake_auth_i_deserialize(&auth, buffer, buff_len)) {
    otrng_dake_auth_i_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (auth.receiver_instance_tag != our_instance_tag(otr)) {
    otrng_dake_auth_i_destroy(&auth);
    return OTRNG_SUCCESS;
  }

  if (received_sender_instance_tag(auth.sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    otrng_dake_auth_i_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (valid_receiver_instance_tag(auth.receiver_instance_tag) == otrng_false) {
    otrng_dake_auth_i_destroy(&auth);
    return OTRNG_ERROR;
  }

  if (!valid_auth_i_message(&auth, otr)) {
    otrng_dake_auth_i_destroy(&auth);
    return OTRNG_ERROR;
  }

  otrng_dake_auth_i_destroy(&auth);

  if (otrng_serialize_fingerprint(fp,
                                  otr->their_client_profile->long_term_pub_key,
                                  otr->their_client_profile->forging_pub_key)) {
    fingerprint_seen_cb_v4(fp, otr);
  }

  if (!double_ratcheting_init(otr, 't')) {
    return OTRNG_ERROR;
  }

  // Reply with initial data message
  return otrng_send_message(dst, "", NULL, MSG_FLAGS_IGNORE_UNREADABLE, otr);
}

/*@null@*/ tstatic tlv_list_s *deserialize_received_tlvs(const uint8_t *src,
                                                         size_t len) {
  uint8_t *tlvs_start = NULL;
  size_t tlvs_len;

  tlvs_start = memchr(src, 0, len);
  if (!tlvs_start) {
    return NULL;
  }

  tlvs_len = len - (tlvs_start + 1 - src);
  return otrng_parse_tlvs(tlvs_start + 1, tlvs_len);
}

tstatic otrng_result decrypt_data_message(otrng_response_s *response,
                                          const k_msg_enc enc_key,
                                          const data_message_s *msg) {
  string_p *dst = &response->to_display;
  uint8_t *plain;
  uint8_t actual_enc_key[ENC_ACTUAL_KEY_BYTES];
  int err;

#ifdef DEBUG
  debug_print("\n");
  debug_print("DECRYPTING\n");
  debug_print("enc_key = ");
  otrng_memdump(enc_key, ENC_KEY_BYTES);
  debug_print("nonce = ");
  otrng_memdump(msg->nonce, DATA_MSG_NONCE_BYTES);
#endif

  // TODO: @initialization What if message->enc_msg_len == 0?
  plain = otrng_secure_alloc(msg->enc_msg_len);

  memcpy(actual_enc_key, enc_key, ENC_ACTUAL_KEY_BYTES);
  err = crypto_stream_xor(plain, msg->enc_msg, msg->enc_msg_len, msg->nonce,
                          actual_enc_key);
  otrng_secure_wipe(actual_enc_key, ENC_ACTUAL_KEY_BYTES);

  if (err) {
    otrng_secure_free(plain);
    return OTRNG_ERROR;
  }

  /* If plain != "" and msg->enc_msg_len != 0 */
  if (otrng_strnlen((string_p)plain, msg->enc_msg_len)) {
    *dst = otrng_xstrndup((char *)plain, msg->enc_msg_len);
  }

  response->tlvs = deserialize_received_tlvs(plain, msg->enc_msg_len);
  otrng_secure_free(plain);
  return OTRNG_SUCCESS;
}

tstatic unsigned int extract_word(const unsigned char *bufp) {
  unsigned int use =
      (bufp[0] << 24) | (bufp[1] << 16) | (bufp[2] << 8) | bufp[3];
  return use;
}

/*@null@*/ tstatic tlv_s *process_tlv(const tlv_s *tlv, otrng_s *otr) {
  if (tlv->type == OTRNG_TLV_NONE || tlv->type == OTRNG_TLV_PADDING) {
    return NULL;
  }

  if (tlv->type == OTRNG_TLV_DISCONNECTED) {
    forget_our_keys(otr);
    otr->state = OTRNG_STATE_FINISHED;
    gone_insecure_cb_v4(otr);
    return NULL;
  }

  if (tlv->type == OTRNG_TLV_SYM_KEY && tlv->len >= 4) {
    uint32_t use = extract_word(tlv->data);
    received_extra_sym_key(otr, use, tlv->data + 4, tlv->len - 4,
                           otr->keys->extra_symmetric_key);
    otrng_secure_wipe(otr->keys->extra_symmetric_key,
                      EXTRA_SYMMETRIC_KEY_BYTES);
    return NULL;
  }

  otrng_secure_wipe(otr->keys->extra_symmetric_key, EXTRA_SYMMETRIC_KEY_BYTES);

  return otrng_process_smp_tlv(tlv, otr);
}

/*@null@*/ tstatic otrng_result process_received_tlvs(
    tlv_list_s **to_send, otrng_response_s *response, otrng_s *otr) {
  const tlv_list_s *current = response->tlvs;
  while (current) {
    tlv_s *tlv = process_tlv(current->data, otr);
    current = current->next;

    if (!tlv) {
      continue;
    }

    *to_send = otrng_append_tlv(*to_send, tlv);
    if (!*to_send) {
      return OTRNG_ERROR;
    }
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result receive_tlvs(otrng_response_s *response, otrng_s *otr) {
  tlv_list_s *reply_tlvs = NULL;
  otrng_result ret = process_received_tlvs(&reply_tlvs, response, otr);
  if (!reply_tlvs) {
    return ret;
  }

  if (!ret) {
    return ret;
  }

  // Serialize response message to send
  ret = otrng_send_message(&response->to_send, "", reply_tlvs,
                           MSG_FLAGS_IGNORE_UNREADABLE, otr);
  otrng_tlv_list_free(reply_tlvs);
  return ret;
}

tstatic otrng_result otrng_receive_data_message_after_dake(
    otrng_response_s *response, const uint8_t *buffer, size_t buff_len,
    otrng_s *otr) {
  data_message_s *msg = otrng_data_message_new();
  k_msg_enc enc_key;
  k_msg_mac mac_key;
  size_t read = 0;
  receiving_ratchet_s *tmp_receiving_ratchet;

  memset(enc_key, 0, ENC_KEY_BYTES);
  memset(mac_key, 0, MAC_KEY_BYTES);

  response->to_display = NULL;

  if (otrng_failed(
          otrng_data_message_deserialize(msg, buffer, buff_len, &read))) {
    otrng_data_message_free(msg);
    return OTRNG_ERROR;
  }

  // TODO: @freeing Do we care if the buffer had more than the data message?
  // if (read < buffer)
  //  return OTRNG_ERROR;

  if (msg->receiver_instance_tag != our_instance_tag(otr)) {
    otrng_data_message_free(msg);
    return OTRNG_SUCCESS;
  }

  if (otrng_failed(
          received_sender_instance_tag(msg->sender_instance_tag, otr))) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_MALFORMED);
    otrng_data_message_free(msg);
    return OTRNG_ERROR;
  }

  if (valid_receiver_instance_tag(msg->receiver_instance_tag) == otrng_false) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_MALFORMED);
    return OTRNG_ERROR;
  }

  // TODO: we still need to persist our_dh->priv
  tmp_receiving_ratchet = otrng_receiving_ratchet_new(otr->keys);

  otrng_key_manager_set_their_tmp_keys(msg->ecdh, msg->dh,
                                       tmp_receiving_ratchet);

  do {
    /* Try to decrypt the message with a stored skipped message key */
    if (otrng_failed(otrng_key_get_skipped_keys(enc_key, mac_key, msg->ecdh,
                                                msg->message_id, otr->keys,
                                                tmp_receiving_ratchet))) {
      /* if a new ratchet */
      if (otrng_failed(otrng_key_manager_derive_dh_ratchet_keys(
              otr->keys, otr->client->max_stored_msg_keys,
              tmp_receiving_ratchet, msg->ecdh, msg->previous_chain_n, 'r',
              otr->client->global_state->callbacks))) {
        otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);

        return OTRNG_ERROR;
      }

      if (otrng_failed(otrng_key_manager_derive_chain_keys(
              enc_key, mac_key, otr->keys, tmp_receiving_ratchet,
              otr->client->max_stored_msg_keys, msg->message_id, 'r',
              otr->client->global_state->callbacks))) {
        return OTRNG_ERROR;
      }

      tmp_receiving_ratchet->k = tmp_receiving_ratchet->k + 1;
    }
    if (!otrng_valid_data_message(mac_key, msg)) {
      otrng_secure_wipe(enc_key, ENC_KEY_BYTES);
      otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
      otrng_data_message_free(msg);

      if (tmp_receiving_ratchet->skipped_keys) {
        otrng_list_free(tmp_receiving_ratchet->skipped_keys, otrng_secure_free);
      }
      otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);

      otrng_client_callbacks_handle_event(otr->client->global_state->callbacks,
                                          OTRNG_MSG_EVENT_INVALID_MSG);

      return OTRNG_ERROR;
    }

    if (otrng_failed(decrypt_data_message(response, enc_key, msg))) {

      if (msg->flags != MSG_FLAGS_IGNORE_UNREADABLE) {
        otrng_error_message(&response->to_send, OTRNG_ERR_MSG_UNREADABLE);
        otrng_secure_wipe(enc_key, ENC_KEY_BYTES);
        otrng_secure_wipe(mac_key, MAC_KEY_BYTES);

        if (tmp_receiving_ratchet->skipped_keys) {
          otrng_list_free(tmp_receiving_ratchet->skipped_keys,
                          otrng_secure_free);
        }
        otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);

        otrng_data_message_free(msg);

        return OTRNG_ERROR;
      }
      if (msg->flags == MSG_FLAGS_IGNORE_UNREADABLE) {
        otrng_secure_wipe(enc_key, ENC_KEY_BYTES);
        otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
        if (tmp_receiving_ratchet->skipped_keys) {
          otrng_list_free(tmp_receiving_ratchet->skipped_keys,
                          otrng_secure_free);
        }
        otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);
        otrng_data_message_free(msg);

        return OTRNG_ERROR;
      }
    }

    otrng_secure_wipe(enc_key, ENC_KEY_BYTES);

    otrng_receiving_ratchet_copy(otr->keys, tmp_receiving_ratchet);
    otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);

    if (otrng_failed(receive_tlvs(response, otr))) {
      continue;
    }

    if (otrng_failed(otrng_store_old_mac_keys(otr->keys, mac_key))) {
      continue;
    }

    if (!response->to_display) {
      otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
      otrng_data_message_free(msg);
      return OTRNG_SUCCESS;
    }

    if (otr->client->should_heartbeat(otr->last_sent)) {
      otrng_debug_enter("trying to send a heartbeat message");
      if (!otrng_send_message(&response->to_send, "", NULL,
                              MSG_FLAGS_IGNORE_UNREADABLE, otr)) {
        otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
        otrng_data_message_free(msg);
        return OTRNG_ERROR;
      }
      otrng_client_callbacks_handle_event(otr->client->global_state->callbacks,
                                          OTRNG_MSG_EVENT_HEARTBEAT_SENT);
      otrng_debug_exit("heartbeat message sent");
      otr->last_sent = time(NULL);
    }

    otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
    otrng_data_message_free(msg);

    return OTRNG_SUCCESS;
  } while (0);

  otrng_secure_wipe(mac_key, MAC_KEY_BYTES);
  otrng_data_message_free(msg);

  return OTRNG_ERROR;
}

tstatic otrng_result otrng_receive_data_message(otrng_response_s *response,
                                                const uint8_t *buffer,
                                                size_t buff_len, otrng_s *otr) {
  if (otr->state == OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE) {
    if (otrng_receive_data_message_after_dake(response, buffer, buff_len,
                                              otr)) {
      otr->state = OTRNG_STATE_ENCRYPTED_MESSAGES;
      return OTRNG_SUCCESS;
    }

    return OTRNG_ERROR;
  }

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_NOT_PRIVATE);
    return OTRNG_ERROR;
  }

  return otrng_receive_data_message_after_dake(response, buffer, buff_len, otr);
}

static otrng_result extract_header(otrng_header_s *dst, const uint8_t *buffer,
                                   const size_t buff_len) {
  size_t read = 0;

  if (buff_len < 3) {
    return OTRNG_ERROR;
  }

  if (!dst) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint16(&dst->version, buffer, buff_len, &read)) {
    return OTRNG_ERROR;
  }

  buffer += read;

  if (!otrng_deserialize_uint8(&dst->type, buffer, buff_len - read, &read)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result receive_decoded_message(otrng_response_s *response,
                                             const uint8_t *decoded,
                                             size_t dec_len, otrng_s *otr) {
  otrng_header_s header;
  int v3_allowed, v4_allowed;

  header.version = 0;

  if (otrng_failed(extract_header(&header, decoded, dec_len))) {
    return OTRNG_ERROR;
  }

  v3_allowed = header.version == OTRNG_PROTOCOL_VERSION_3 &&
               allow_version(otr, OTRNG_ALLOW_V3);
  v4_allowed = header.version == OTRNG_PROTOCOL_VERSION_4 &&
               allow_version(otr, OTRNG_ALLOW_V4);
  if (!v3_allowed && !v4_allowed) {
    return OTRNG_ERROR;
  }

  maybe_create_keys(otr->client);

  response->to_send = NULL;

  switch (header.type) {
  case IDENTITY_MSG_TYPE:
    otr->running_version = OTRNG_PROTOCOL_VERSION_4;
    return receive_identity_message(&response->to_send, decoded, dec_len, otr);
  case AUTH_R_MSG_TYPE:
    return receive_auth_r(&response->to_send, decoded, dec_len, otr);
  case AUTH_I_MSG_TYPE:
    return receive_auth_i(&response->to_send, decoded, dec_len, otr);
  case NON_INT_AUTH_MSG_TYPE:
    otr->running_version = OTRNG_PROTOCOL_VERSION_4;
    return receive_non_interactive_auth_message(response, decoded, dec_len,
                                                otr);
  case DATA_MSG_TYPE:
    return otrng_receive_data_message(response, decoded, dec_len, otr);
  default:
    /* error. bad message type */
    return OTRNG_ERROR;
  }
}

tstatic otrng_result receive_encoded_message(otrng_response_s *response,
                                             const string_p msg, otrng_s *otr) {
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  otrng_result result;

  if (otrl_base64_otr_decode(msg, &decoded, &dec_len)) {
    return OTRNG_ERROR;
  }

  result = receive_decoded_message(response, decoded, dec_len, otr);
  otrng_free(decoded);

  return result;
}

tstatic otrng_result receive_error_message(otrng_response_s *response,
                                           const string_p msg, otrng_s *otr) {
  otrng_error_event error_event = OTRNG_ERROR_NONE;

  if (strncmp(msg, "ERROR_1:", 8) == 0) {
    error_event = OTRNG_ERROR_UNREADABLE_EVENT;
    display_error_message_cb(error_event, &response->to_display, otr);

    if (otr->policy_type & OTRNG_ERROR_START_DAKE) {
      return otrng_build_query_message(&response->to_send, "", otr);
    }

    return OTRNG_SUCCESS;
  } else if (strncmp(msg, "ERROR_2:", 8) == 0) {
    error_event = OTRNG_ERROR_NOT_IN_PRIVATE_EVENT;
    display_error_message_cb(error_event, &response->to_display, otr);

    if (otr->policy_type & OTRNG_ERROR_START_DAKE) {
      forget_our_keys(otr);
      otr->state = OTRNG_STATE_START;
      gone_insecure_cb_v4(otr);

      return otrng_build_query_message(&response->to_send, "", otr);
    }

    return OTRNG_SUCCESS;
  } else if (strncmp(msg, "ERROR_3:", 8) == 0) {
    error_event = OTRNG_ERROR_MALFORMED_EVENT;
    display_error_message_cb(error_event, &response->to_display, otr);

    if (otr->policy_type & OTRNG_ERROR_START_DAKE) {
      return otrng_build_query_message(&response->to_send, "", otr);
    }

    return OTRNG_SUCCESS;
  }

  return OTRNG_ERROR;
}

static int get_message_type(const string_p msg) {
  if (message_contains_tag(msg)) {
    return MSG_TAGGED_PLAINTEXT;
  }
  if (message_is_query(msg)) {
    return MSG_QUERY_STRING;
  } else if (message_is_otr_error(msg)) {
    return MSG_OTR_ERROR;
  } else if (message_is_otr_encoded(msg)) {
    return MSG_OTR_ENCODED;
  }

  // TODO: this defaults everything to plaintext.. what if this is a corrupted
  // message?
  return MSG_PLAINTEXT;
}

tstatic otrng_result receive_message_v4_only(otrng_response_s *response,
                                             const string_p msg, otrng_s *otr) {
  switch (get_message_type(msg)) {
  case MSG_PLAINTEXT:
    receive_plaintext(response, msg, otr);
    return OTRNG_SUCCESS;

  case MSG_TAGGED_PLAINTEXT:
    return receive_tagged_plaintext(response, msg, otr);

  case MSG_QUERY_STRING:
    return receive_query_message(response, msg, otr);

  case MSG_OTR_ENCODED:
    return receive_encoded_message(response, msg, otr);

  case MSG_OTR_ERROR:
    return receive_error_message(response, msg + strlen(ERROR_PREFIX), otr);
  default:
    break;
  }

  return OTRNG_SUCCESS;
}

static otrng_result receive_defragmented_message(otrng_response_s *response,
                                                 const string_p msg,
                                                 otrng_s *otr) {
  if (!msg || !response) {
    return OTRNG_ERROR;
  }

  response->to_display = NULL;

  /* A DH-Commit sets our running version to 3 */
  if ((allow_version(otr, OTRNG_ALLOW_V3) ||
       allow_version(otr, OTRNG_ALLOW_V34)) &&
      (strstr(msg, "?OTR:AAMC") != NULL)) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_3;
  }

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, msg, otr->v3_conn);
  case OTRNG_PROTOCOL_VERSION_4:
  default:
    // V4 handles every message BUT v3 messages
    return receive_message_v4_only(response, msg, otr);
  }
}

/* Receive a possibly OTR message. */
INTERNAL otrng_result otrng_receive_message(otrng_response_s *response,
                                            const string_p msg, otrng_s *otr) {
  char *defrag = NULL;
  otrng_result ret;

  response->to_display = NULL;

  if (otrng_failed(otrng_unfragment_message(&defrag, &otr->pending_fragments,
                                            msg, our_instance_tag(otr)))) {
    return OTRNG_ERROR;
  }

  ret = receive_defragmented_message(response, defrag, otr);
  otrng_free(defrag);
  return ret;
}

INTERNAL otrng_result otrng_send_message(string_p *to_send, const string_p msg,
                                         const tlv_list_s *tlvs, uint8_t flags,
                                         otrng_s *otr) {
  if (!otr) {
    return OTRNG_ERROR;
  }

  if (otr->running_version == OTRNG_PROTOCOL_VERSION_NONE) {
    if (otr->state == OTRNG_STATE_START) {
      if (otr->policy_type & OTRNG_REQUIRE_ENCRYPTION) {
        otrng_client_callbacks_handle_event(
            otr->client->global_state->callbacks,
            OTRNG_MSG_EVENT_ENCRYPTION_REQUIRED);
        return otrng_build_query_message(to_send, "", otr);
      } else if (otr->policy_type & OTRNG_SEND_WHITESPACE_TAG) {
        return otrng_build_whitespace_tag(to_send, msg, otr);
      }
    }
  }

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_3:
    return otrng_v3_send_message(to_send, msg, tlvs, otr->v3_conn);
  case OTRNG_PROTOCOL_VERSION_4:
    return otrng_prepare_to_send_data_message(to_send, msg, tlvs, otr, flags);
  default:
    return OTRNG_ERROR;
  }
}

tstatic otrng_result otrng_close_v4(string_p *to_send, otrng_s *otr) {
  size_t ser_len;
  uint8_t *ser_mac_keys;
  tlv_list_s *disconnected;
  otrng_result result;

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return OTRNG_SUCCESS;
  }

  ser_len = otrng_list_len(otr->keys->skipped_keys) * MAC_KEY_BYTES;
  ser_mac_keys = otrng_reveal_mac_keys_on_tlv(otr->keys);
  otr->keys->skipped_keys = NULL;

  disconnected = otrng_tlv_list_one(
      otrng_tlv_new(OTRNG_TLV_DISCONNECTED, ser_len, ser_mac_keys));
  otrng_secure_free(ser_mac_keys);

  if (!disconnected) {
    return OTRNG_ERROR;
  }

  result = otrng_send_message(to_send, "", disconnected,
                              MSG_FLAGS_IGNORE_UNREADABLE, otr);

  otrng_tlv_list_free(disconnected);
  forget_our_keys(otr);
  otr->state = OTRNG_STATE_START;
  gone_insecure_cb_v4(otr);

  return result;
}

INTERNAL otrng_result otrng_close(string_p *to_send, otrng_s *otr) {
  if (!otr) {
    return OTRNG_ERROR;
  }

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_3:
    if (!otrng_v3_close(to_send, otr->v3_conn)) {
      return OTRNG_ERROR;
    }
    gone_insecure_cb_v4(otr); // TODO: @client Only if success
    return OTRNG_SUCCESS;
  case OTRNG_PROTOCOL_VERSION_4:
    return otrng_close_v4(to_send, otr);
  default:
    return OTRNG_ERROR;
  }
}

tstatic otrng_result otrng_send_symkey_message_v4(
    string_p *to_send, unsigned int use, const unsigned char *use_data,
    size_t use_data_len, otrng_s *otr, unsigned char *extra_key) {
  unsigned char *tlv_data;
  tlv_list_s *tlvs;
  otrng_result ret;

  if (use_data_len > 0 && !use_data) {
    return OTRNG_ERROR;
  }

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return OTRNG_ERROR;
  }

  tlv_data = otrng_xmalloc_z(use_data_len + 4);

  tlv_data[0] = (use >> 24) & 0xff;
  tlv_data[1] = (use >> 16) & 0xff;
  tlv_data[2] = (use >> 8) & 0xff;
  tlv_data[3] = (use)&0xff;

  if (use_data_len > 0) {
    memmove(tlv_data + 4, use_data, use_data_len);
  }

  memmove(extra_key, otr->keys->extra_symmetric_key, EXTRA_SYMMETRIC_KEY_BYTES);

  tlvs = otrng_tlv_list_one(
      otrng_tlv_new(OTRNG_TLV_SYM_KEY, use_data_len + 4, tlv_data));
  otrng_free(tlv_data);

  // TODO: @freeing Should not extra_key be zeroed if any error happens from
  // here on?
  if (!tlvs) {
    return OTRNG_ERROR;
  }

  // TODO: @refactoring in v3 the extra_key is passed as a param to this
  // do the same?
  ret = otrng_send_message(to_send, "", tlvs, MSG_FLAGS_IGNORE_UNREADABLE, otr);
  otrng_tlv_list_free(tlvs);

  return ret;
}

API otrng_result otrng_send_symkey_message(string_p *to_send, unsigned int use,
                                           const unsigned char *use_data,
                                           size_t use_data_len,
                                           uint8_t *extra_key, otrng_s *otr) {
  if (!otr) {
    return OTRNG_ERROR;
  }

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_3:
    return otrng_v3_send_symkey_message(to_send, otr->v3_conn, use, use_data,
                                        use_data_len, extra_key);
  case OTRNG_PROTOCOL_VERSION_4:
    return otrng_send_symkey_message_v4(to_send, use, use_data, use_data_len,
                                        otr, extra_key);
  default:
    return OTRNG_ERROR;
  }
}

#define GCRYPT_WANTED_VERSION_16 "1.6.0"
#define GCRYPT_WANTED_VERSION_17 "1.7.6"
#define GCRYPT_WANTED_VERSION_18 "1.8.0"

static int otrl_initialized = 0;

static otrng_result otrng_v3_init(otrng_bool die) {
  if (otrl_initialized) {
    return OTRNG_SUCCESS;
  }

  if (otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB)) {
    fprintf(stderr, "otrv3 initialization failed\n");
    if (die) {
      exit(EXIT_FAILURE);
    }
    return OTRNG_ERROR;
  }

  otrl_initialized = 1;

  return OTRNG_SUCCESS;
}

API otrng_result otrng_init(otrng_bool die) {
  const char *real;
  otrng_result r;

  if (gcry_check_version(GCRYPT_WANTED_VERSION_18) == NULL) {
    if (gcry_check_version(GCRYPT_WANTED_VERSION_17) == NULL) {
      if (gcry_check_version(GCRYPT_WANTED_VERSION_16) == NULL) {
        real = gcry_check_version(NULL);

        fprintf(stderr,
                "gcrypt initialization failed - we need versions larger than "
                "%s, %s or %s - but your version is %s\n",
                GCRYPT_WANTED_VERSION_18, GCRYPT_WANTED_VERSION_17,
                GCRYPT_WANTED_VERSION_16, real);
        if (die) {
          exit(EXIT_FAILURE);
        }
        return OTRNG_ERROR;
      }
    }
  }

  if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
  }

  if (sodium_init() == -1) {
    if (die) {
      exit(EXIT_FAILURE);
    }
    return OTRNG_ERROR;
  }

  r = otrng_v3_init(die);

  if (otrng_failed(r)) {
    return r;
  }

  otrng_debug_init();

  return otrng_dh_init(die);
}
