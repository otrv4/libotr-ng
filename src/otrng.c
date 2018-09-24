/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
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
#include <libotr/b64.h>
#include <libotr/mem.h>
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

static inline dh_public_key_p their_dh(const otrng_s *otr) {
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
  if (!conv || !conv->client) {
    return;
  }

  otrng_client_callbacks_gone_secure(conv->client->global_state->callbacks,
                                     conv);
}

tstatic void gone_insecure_cb_v4(const otrng_s *conv) {
  if (!conv || !conv->client || !conv->client->global_state->callbacks ||
      !conv->client->global_state->callbacks->gone_insecure) {
    return;
  }

  conv->client->global_state->callbacks->gone_insecure(conv);
}

tstatic void fingerprint_seen_cb_v4(const otrng_fingerprint_p fp,
                                    const otrng_s *conv) {
  if (!conv || !conv->client || !conv->client->global_state->callbacks ||
      !conv->client->global_state->callbacks->fingerprint_seen) {
    return;
  }

  conv->client->global_state->callbacks->fingerprint_seen(fp, conv);
}

tstatic void received_extra_sym_key(const otrng_s *conv, unsigned int use,
                                    const unsigned char *use_data,
                                    size_t use_data_len,
                                    const unsigned char *extra_sym_key) {

  if (!conv || !conv->client || !conv->client->global_state->callbacks ||
      !conv->client->global_state->callbacks->received_extra_symm_key) {
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
  // TODO: this callback is required, so it will segfault if not provided
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

  *dst = 0;
}

tstatic const otrng_shared_prekey_pair_s *
our_shared_prekey(const otrng_s *otr) {
  return otr->client->shared_prekey_pair;
}

INTERNAL otrng_s *otrng_new(otrng_client_s *client, otrng_policy_s policy) {
  otrng_s *otr = otrng_xmalloc(sizeof(otrng_s));

  otr->client = client;
  otr->peer = NULL;
  otr->state = OTRNG_STATE_START;
  otr->running_version = 0;
  otr->supported_versions = policy.allows;

  otr->their_instance_tag = 0;

  otr->their_prekeys_id = 0;
  otr->their_client_profile = NULL;
  otr->their_prekey_profile = NULL;

  otr->keys = otrng_key_manager_new();
  otrng_smp_protocol_init(otr->smp);

  otr->pending_fragments = NULL;

  // TODO: Why is not this automatically generated?
  // Probably because it expects to receive a peer name.
  otr->v3_conn = NULL;

  otr->shared_session_state = NULL;
  otr->sending_init_msg = NULL;
  otr->receiving_init_msg = NULL;

  return otr;
}

static void free_fragment_context(void *p) { otrng_fragment_context_free(p); }

INTERNAL void otrng_destroy(/*@only@ */ otrng_s *otr) {
  free(otr->peer);

  otrng_key_manager_free(otr->keys);
  otr->keys = NULL;

  otrng_client_profile_free(otr->their_client_profile);
  otr->their_client_profile = NULL;

  otrng_prekey_profile_free(otr->their_prekey_profile);
  otr->their_prekey_profile = NULL;

  otrng_smp_destroy(otr->smp);

  otrng_list_free(otr->pending_fragments, free_fragment_context);
  otr->pending_fragments = NULL;

  otrng_v3_conn_free(otr->v3_conn);
  otr->v3_conn = NULL;

  free(otr->shared_session_state);
  otr->shared_session_state = NULL;

  // TODO: @freeing should we free this after being used by phi?
  free(otr->sending_init_msg);
  otr->sending_init_msg = NULL;

  // TODO: @freeing should we free this after being used by phi?;
  free(otr->receiving_init_msg);
  otr->receiving_init_msg = NULL;
}

INTERNAL void otrng_free(/*@only@ */ otrng_s *otr) {
  if (!otr) {
    return;
  }

  otrng_destroy(otr);
  free(otr);
}

INTERNAL otrng_result otrng_build_query_message(string_p *dst,
                                                const string_p message,
                                                otrng_s *otr) {
  /* size = qm tag + versions + msg length + versions
   * + question mark + whitespace + null byte */
  size_t qm_size = QUERY_MESSAGE_TAG_BYTES + 3 + strlen(message) + 2 + 1;
  string_p buff = NULL;
  char allowed[3] = {0};
  char *cursor;
  int rem;
  *dst = NULL;

  if (otr->state == OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return OTRNG_ERROR;
  }

  buff = otrng_xmalloc(qm_size);

  allowed_versions(allowed, otr);

  cursor = otrng_stpcpy(buff, query_header);
  cursor = otrng_stpcpy(cursor, allowed);
  cursor = otrng_stpcpy(cursor, "? ");

  rem = cursor - buff;

  /* Add '\0' */
  if (*otrng_stpncpy(cursor, message, qm_size - rem)) {
    free(buff);
    return OTRNG_ERROR; /* could not zero-terminate the string */
  }

  if (otr->sending_init_msg) {
    free(otr->sending_init_msg);
  }

  otr->sending_init_msg = otrng_xstrdup(buff);

  *dst = buff;

  return OTRNG_SUCCESS;
}

API otrng_result otrng_build_whitespace_tag(string_p *whitespace_tag,
                                            const string_p message,
                                            otrng_s *otr) {
  int allows_v4 = allow_version(otr, OTRNG_ALLOW_V4);
  int allows_v3 = allow_version(otr, OTRNG_ALLOW_V3);
  string_p cursor = NULL;

#define WHITESPACE_TAG_MAX_BYTES                                               \
  (WHITESPACE_TAG_BASE_BYTES + 2 * WHITESPACE_TAG_VERSION_BYTES)
  char *buff = otrng_xmalloc(WHITESPACE_TAG_MAX_BYTES + strlen(message) + 1);

  cursor = otrng_stpcpy(buff, tag_base);

  if (allows_v4) {
    cursor = otrng_stpcpy(cursor, tag_version_v4);
  }

  if (allows_v3) {
    cursor = otrng_stpcpy(cursor, tag_version_v3);
  }

  otrng_stpcpy(cursor, message);

  if (otr->sending_init_msg) {
    free(otr->sending_init_msg);
  }

  otr->sending_init_msg = otrng_xstrdup(buff);

  *whitespace_tag = buff;

  return OTRNG_SUCCESS;
}

tstatic otrng_bool message_contains_tag(const string_p message) {
  return strstr(message, tag_base) != NULL;
}

tstatic void set_to_display(otrng_response_s *response,
                            const string_p message) {
  size_t msg_len = strlen(message);
  response->to_display = otrng_xstrndup(message, msg_len);
}

tstatic otrng_result message_to_display_without_tag(otrng_response_s *response,
                                                    const string_p message,
                                                    size_t msg_len) {
  // TODO: What if there is more than one VERSION TAG?
  size_t tag_length = WHITESPACE_TAG_BASE_BYTES + WHITESPACE_TAG_VERSION_BYTES;
  size_t chars = msg_len - tag_length;
  char *found_at;
  string_p buff;
  size_t bytes_before_tag;

  if (msg_len < tag_length) {
    return OTRNG_ERROR;
  }

  found_at = strstr(message, tag_base);
  if (!found_at) {
    return OTRNG_ERROR;
  }

  buff = otrng_xmalloc(chars + 1);

  bytes_before_tag = found_at - message;
  if (!bytes_before_tag) {
    strncpy(buff, message + tag_length, chars);
  } else {
    strncpy(buff, message, bytes_before_tag);
    strncpy(buff, message + bytes_before_tag, chars - bytes_before_tag);
  }
  buff[chars] = '\0';

  response->to_display = otrng_xstrndup(buff, chars);

  free(buff);
  return OTRNG_SUCCESS;
}

tstatic void set_running_version_from_tag(otrng_s *otr,
                                          const string_p message) {
  if (allow_version(otr, OTRNG_ALLOW_V4) && strstr(message, tag_version_v4)) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_4;
    return;
  }

  if (allow_version(otr, OTRNG_ALLOW_V3) && strstr(message, tag_version_v3)) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_3;
    return;
  }
}

tstatic otrng_bool message_is_query(const string_p message) {
  if (strstr(message, query_header) != NULL) {
    return otrng_true;
  }
  return otrng_false;
}

tstatic void set_running_version_from_query_msg(otrng_s *otr,
                                                const string_p message) {
  if (allow_version(otr, OTRNG_ALLOW_V4) && strstr(message, "4")) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_4;
  } else if (allow_version(otr, OTRNG_ALLOW_V3) && strstr(message, "3")) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_3;
  }
}

tstatic otrng_bool message_is_otr_encoded(const string_p message) {
  if (strstr(message, otr_header) != NULL) {
    return otrng_true;
  }
  return otrng_false;
}

tstatic otrng_bool message_is_otr_error(const string_p message) {
  if (strncmp(message, otr_error_header, strlen(otr_error_header)) == 0) {
    return otrng_true;
  }
  return otrng_false;
}

INTERNAL otrng_response_s *otrng_response_new(void) {
  otrng_response_s *response = otrng_xmalloc(sizeof(otrng_response_s));

  response->to_display = NULL;
  response->to_send = NULL;
  response->warning = OTRNG_WARN_NONE;
  response->tlvs = NULL;

  return response;
}

INTERNAL void otrng_response_free(otrng_response_s *response) {
  if (!response) {
    return;
  }

  if (response->to_display) {
    free(response->to_display);
  }

  if (response->to_send) {
    free(response->to_send);
  }

  otrng_tlv_list_free(response->tlvs);

  free(response);
}

// TODO: @erroing Is not receiving a plaintext a problem?
tstatic void receive_plaintext(otrng_response_s *response,
                               const string_p message, const otrng_s *otr) {
  set_to_display(response, message);

  if (otr->state != OTRNG_STATE_START) {
    response->warning = OTRNG_WARN_RECEIVED_UNENCRYPTED;
  }
}

tstatic otrng_result serialize_and_encode_identity_message(
    string_p *dst, const dake_identity_message_s *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (!otrng_dake_identity_message_asprintf(&buff, &len, m)) {
    return OTRNG_ERROR;
  }

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  return OTRNG_SUCCESS;
}

tstatic otrng_result reply_with_identity_msg(otrng_response_s *response,
                                             otrng_s *otr) {
  dake_identity_message_s *m = NULL;
  otrng_result result;

  m = otrng_dake_identity_message_new(get_my_client_profile(otr));
  if (!m) {
    return OTRNG_ERROR;
  }

  m->sender_instance_tag = our_instance_tag(otr);
  m->receiver_instance_tag = otr->their_instance_tag;

  otrng_ec_point_copy(m->Y, our_ecdh(otr));
  m->B = otrng_dh_mpi_copy(our_dh(otr));

  result = serialize_and_encode_identity_message(&response->to_send, m);
  otrng_dake_identity_message_free(m);

  return result;
}

tstatic otrng_result start_dake(otrng_response_s *response, otrng_s *otr) {
  if (otrng_key_manager_generate_ephemeral_keys(otr->keys) == OTRNG_ERROR) {
    return OTRNG_ERROR;
  }

  maybe_create_keys(otr->client);
  if (reply_with_identity_msg(response, otr) == OTRNG_ERROR) {
    return OTRNG_ERROR;
  }

  otr->state = OTRNG_STATE_WAITING_AUTH_R;

  return OTRNG_SUCCESS;
}

tstatic otrng_result receive_tagged_plaintext(otrng_response_s *response,
                                              const string_p message,
                                              otrng_s *otr) {
  set_running_version_from_tag(otr, message);

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_4:
    if (message_to_display_without_tag(response, message, strlen(message)) ==
        OTRNG_ERROR) {
      return OTRNG_ERROR;
    }

    return start_dake(response, otr);
  case OTRNG_PROTOCOL_VERSION_3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, message, otr->v3_conn);
  default:
    /* ignore */
    return OTRNG_SUCCESS;
  }
}

tstatic otrng_result receive_query_message(otrng_response_s *response,
                                           const string_p message,
                                           otrng_s *otr) {
  set_running_version_from_query_msg(otr, message);

  // TODO: @refactoring still unsure about this
  if (!otr->receiving_init_msg) {
    otr->receiving_init_msg = otrng_xstrdup(message);
  }

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_4:
    return start_dake(response, otr);
  case OTRNG_PROTOCOL_VERSION_3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, message, otr->v3_conn);
  default:
    /* ignore */
    return OTRNG_SUCCESS;
  }
}

tstatic otrng_result serialize_and_encode_auth_r(string_p *dst,
                                                 const dake_auth_r_s *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (!otrng_dake_auth_r_asprintf(&buff, &len, m)) {
    return OTRNG_ERROR;
  }

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  return OTRNG_SUCCESS;
}

static const char *get_shared_session_state(otrng_s *otr) {
  otrng_shared_session_state_s state;

  if (otr->shared_session_state) {
    return otr->shared_session_state;
  }

  state = otrng_get_shared_session_state(otr);
  otr->shared_session_state = otrng_generate_session_state_string(&state);

  free(state.identifier1);
  free(state.identifier2);
  free(state.password);

  return otr->shared_session_state;
}

static otrng_result generate_phi_serialized(uint8_t **dst, size_t *dst_len,
                                            const char *phi_prime,
                                            const char *init_msg,
                                            uint16_t instance_tag1,
                                            uint16_t instance_tag2) {
  size_t init_msg_len, phi_prime_len, size;

  if (!phi_prime) {
    return OTRNG_ERROR;
  }

  /*
   * phi = smaller instance tag || larger instance tag || DATA(query message)
   *       || phi'
   */
  init_msg_len = init_msg ? strlen(init_msg) + 1 : 0;
  phi_prime_len = strlen(phi_prime) + 1;
  size = 4 + 4 + (4 + init_msg_len) + (4 + phi_prime_len);
  *dst = otrng_xmalloc(size);

  *dst_len = otrng_serialize_phi(*dst, phi_prime, init_msg, instance_tag1,
                                 instance_tag2);

  return OTRNG_SUCCESS;
}

static otrng_result generate_phi_receiving(uint8_t **dst, size_t *dst_len,
                                           otrng_s *otr) {
  return generate_phi_serialized(dst, dst_len, get_shared_session_state(otr),
                                 otr->receiving_init_msg, our_instance_tag(otr),
                                 otr->their_instance_tag);
}

static otrng_result generate_phi_sending(uint8_t **dst, size_t *dst_len,
                                         otrng_s *otr) {
  return generate_phi_serialized(dst, dst_len, get_shared_session_state(otr),
                                 otr->sending_init_msg, our_instance_tag(otr),
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
      .client_profile = (client_profile_s *)get_my_client_profile(otr),
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

  free(phi);
  return ret;
}

static otrng_result generate_receiving_rsig_tag(
    uint8_t **dst, size_t *dst_len, const char auth_tag_type,
    const otrng_dake_participant_data_s *responder, otrng_s *otr) {
  const otrng_dake_participant_data_s initiator = {
      .client_profile = (client_profile_s *)get_my_client_profile(otr),
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

  free(phi);
  return ret;
}

tstatic otrng_result reply_with_auth_r_msg(string_p *dst, otrng_s *otr) {
  dake_auth_r_p msg;
  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_result result;

  msg->sender_instance_tag = our_instance_tag(otr);
  msg->receiver_instance_tag = otr->their_instance_tag;

  otrng_client_profile_copy(msg->profile, get_my_client_profile(otr));

  otrng_ec_point_copy(msg->X, our_ecdh(otr));
  msg->A = otrng_dh_mpi_copy(our_dh(otr));

  if (!generate_sending_rsig_tag(&t, &t_len, 'r', otr)) {
    return OTRNG_ERROR;
  }

  /* sigma = RSig(H_a, sk_ha, {F_b, H_a, Y}, t) */
  if (!otrng_rsig_authenticate(
          msg->sigma, otr->client->keypair->priv,     /* sk_ha */
          otr->client->keypair->pub,                  /* H_a */
          otr->their_client_profile->forging_pub_key, /* F_b */
          otr->client->keypair->pub,                  /* H_a */
          their_ecdh(otr),                            /* Y */
          t, t_len)) {
    free(t);
    return OTRNG_ERROR;
  }

  free(t);

  result = serialize_and_encode_auth_r(dst, msg);
  otrng_dake_auth_r_destroy(msg);

  return result;
}

tstatic otrng_result generate_tmp_key_r(uint8_t *dst, otrng_s *otr) {
  k_ecdh_p tmp_ecdh_k1;
  k_ecdh_p tmp_ecdh_k2;
  k_ecdh_p k_ecdh;
  dh_shared_secret_p k_dh;
  size_t k_dh_len = 0;
  brace_key_p brace_key;

  // TODO: @refactoring this will be calculated again later
  if (!otrng_ecdh_shared_secret(k_ecdh, sizeof(k_ecdh),
                                otr->keys->our_ecdh->priv,
                                otr->keys->their_ecdh)) {
    return OTRNG_ERROR;
  }

  // TODO: @refactoring this will be calculated again later
  if (!otrng_dh_shared_secret(k_dh, &k_dh_len, otr->keys->our_dh->priv,
                              otr->keys->their_dh)) {
    return OTRNG_ERROR;
  }

  hash_hash(brace_key, sizeof(brace_key_p), k_dh, k_dh_len);

  sodium_memzero(k_dh, sizeof(k_dh));

#ifdef DEBUG
  debug_print("\n");
  debug_print("GENERATING TEMP KEY R\n");
  debug_print("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_p));
  debug_print("brace_key = ");
  otrng_memdump(brace_key, sizeof(brace_key_p));
#endif

  if (!otrng_ecdh_shared_secret(tmp_ecdh_k1, sizeof(tmp_ecdh_k1),
                                otr->keys->our_ecdh->priv,
                                otr->keys->their_shared_prekey)) {
    return OTRNG_ERROR;
  }

  if (!otrng_ecdh_shared_secret(tmp_ecdh_k2, sizeof(tmp_ecdh_k2),
                                otr->keys->our_ecdh->priv,
                                otr->their_client_profile->long_term_pub_key)) {
    return OTRNG_ERROR;
  }

  otrng_key_manager_calculate_tmp_key(dst, k_ecdh, brace_key, tmp_ecdh_k1,
                                      tmp_ecdh_k2);

#ifdef DEBUG
  debug_print("\n");
  debug_print("GENERATING TEMP KEY R\n");
  debug_print("tmp_key_r = ");
  otrng_memdump(dst, HASH_BYTES);
#endif

  sodium_memzero(tmp_ecdh_k1, ED448_POINT_BYTES);
  sodium_memzero(tmp_ecdh_k2, ED448_POINT_BYTES);

  return OTRNG_SUCCESS;
}

tstatic otrng_result serialize_and_encode_non_interactive_auth(
    string_p *dst, const dake_non_interactive_auth_message_s *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (!otrng_dake_non_interactive_auth_message_asprintf(&buff, &len, m)) {
    return OTRNG_ERROR;
  }

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  return OTRNG_SUCCESS;
}

tstatic void
non_interactive_auth_message_init(dake_non_interactive_auth_message_p auth,
                                  otrng_s *otr) {
  auth->sender_instance_tag = our_instance_tag(otr);
  auth->receiver_instance_tag = otr->their_instance_tag;
  otrng_client_profile_copy(auth->profile, get_my_client_profile(otr));

  // TODO: is this set?
  otrng_ec_point_copy(auth->X, our_ecdh(otr));
  auth->A = otrng_dh_mpi_copy(our_dh(otr));

  auth->prekey_message_id = 0;
}

tstatic otrng_result build_non_interactive_auth_message(
    dake_non_interactive_auth_message_p auth, otrng_s *otr) {
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
      .client_profile = (client_profile_s *)get_my_client_profile(otr),
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(otr->keys->our_ecdh->pub),
      .dh = our_dh(otr),
  };

  non_interactive_auth_message_init(auth, otr);
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

  /* t = KDF_1(0x0D || Bob_Client_Profile, 64) || KDF_1(0x0E ||
   * Alice_Client_Profile, 64) || Y || X || B || A || their_shared_prekey ||
   * KDF_1(0x0F || phi, 64) */
  if (!build_non_interactive_rsign_tag(&t, &t_len, &initiator, &responder,
                                       otr->keys->their_shared_prekey, phi,
                                       phi_len)) {
    free(phi);
    return OTRNG_ERROR;
  }

  free(phi);

  /* sigma = RSig(H_a, sk_ha, {F_b, H_a, Y}, t) */
  if (!otrng_rsig_authenticate(
          auth->sigma, otr->client->keypair->priv,    /* sk_ha */
          otr->client->keypair->pub,                  /* H_a */
          otr->their_client_profile->forging_pub_key, /* F_b */
          otr->client->keypair->pub,                  /* H_a */
          their_ecdh(otr),                            /* Y */
          t, t_len)) {
    free(t);
    return OTRNG_ERROR;
  }

  ret = otrng_dake_non_interactive_auth_message_authenticator(
      auth->auth_mac, auth, t, t_len, otr->keys->tmp_key);

  free(t);

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

tstatic otrng_result reply_with_non_interactive_auth_msg(string_p *dst,
                                                         otrng_s *otr) {
  dake_non_interactive_auth_message_p auth;
  otrng_result ret;

  maybe_create_keys(otr->client);

  ret = build_non_interactive_auth_message(auth, otr);

  if (ret == OTRNG_SUCCESS) {
    ret = serialize_and_encode_non_interactive_auth(dst, auth);
  }

  if (!otrng_key_manager_generate_shared_secret(otr->keys, otrng_false)) {
    return OTRNG_ERROR;
  }

  if (!double_ratcheting_init(otr, 't')) {
    return OTRNG_ERROR;
  }

  otrng_dake_non_interactive_auth_message_destroy(auth);
  return ret;
}

// TODO: @non_interactive Should maybe return a serialized ensemble, ready to
// publish to the server
INTERNAL prekey_ensemble_s *otrng_build_prekey_ensemble(otrng_s *otr) {
  ecdh_keypair_p ecdh;
  dh_keypair_p dh;
  otrng_client_s *client;

  prekey_ensemble_s *ensemble = otrng_xmalloc(sizeof(prekey_ensemble_s));

  otrng_client_profile_copy(ensemble->client_profile,
                            get_my_client_profile(otr));
  otrng_prekey_profile_copy(ensemble->prekey_profile,
                            get_my_prekey_profile(otr));

  if (!otrng_generate_ephemeral_keys(ecdh, dh)) {
    otrng_prekey_ensemble_free(ensemble);
    return NULL;
  }

  ensemble->message = otrng_dake_prekey_message_build(our_instance_tag(otr),
                                                      ecdh->pub, dh->pub);
  if (!ensemble->message) {
    otrng_prekey_ensemble_free(ensemble);
    return NULL;
  }

  client = otr->client;
  otrng_client_store_my_prekey_message(ensemble->message->id,
                                       our_instance_tag(otr), ecdh, dh, client);
  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dh_keypair_destroy(dh);

  return ensemble;
}

tstatic otrng_result set_their_client_profile(const client_profile_s *profile,
                                              otrng_s *otr) {
  // The protocol is already committed to a specific profile, and receives an
  // ensemble with another profile.
  // How should the protocol behave? I am failling for now.
  if (otr->their_client_profile) {
    return OTRNG_ERROR;
  }

  otr->their_client_profile = otrng_xmalloc(sizeof(client_profile_s));

  otrng_client_profile_copy(otr->their_client_profile, profile);

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

  otr->their_prekey_profile = otrng_xmalloc(sizeof(otrng_prekey_profile_s));

  otrng_prekey_profile_copy(otr->their_prekey_profile, profile);

  otrng_ec_point_copy(otr->keys->their_shared_prekey,
                      otr->their_prekey_profile->shared_prekey);

  return OTRNG_SUCCESS;
}

tstatic otrng_result received_sender_instance_tag(uint32_t their_instance_tag,
                                                  otrng_s *otr) {
  if (!otrng_instance_tag_valid(their_instance_tag)) {
    return OTRNG_ERROR;
  }

  otr->their_instance_tag = their_instance_tag;

  return OTRNG_SUCCESS;
}

static otrng_bool valid_receiver_instance_tag(uint32_t instance_tag) {
  return (instance_tag == 0 || otrng_instance_tag_valid(instance_tag));
}

tstatic otrng_result prekey_message_received(const dake_prekey_message_s *m,
                                             otrng_warning *warn,
                                             otrng_s *otr) {
  if (!otr->their_client_profile) {
    return OTRNG_ERROR;
  }

  if (!otr->their_prekey_profile) {
    return OTRNG_ERROR;
  }

  if (received_sender_instance_tag(m->sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    if (warn) {
      *warn = OTRNG_WARN_MALFORMED;
    }
    return OTRNG_ERROR;
  }

  if (!otrng_valid_received_values(m->sender_instance_tag, m->Y, m->B,
                                   otr->their_client_profile)) {
    return OTRNG_ERROR;
  }

  otr->their_prekeys_id = m->id; /* Store for the non-interactive-auth */
  otrng_key_manager_set_their_ecdh(m->Y, otr->keys);
  otrng_key_manager_set_their_dh(m->B, otr->keys);

  if (!otrng_key_manager_generate_ephemeral_keys(otr->keys)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result receive_prekey_ensemble(string_p *dst,
                                             const prekey_ensemble_s *ensemble,
                                             otrng_s *otr) {
  otrng_warning warn;

  if (!otrng_prekey_ensemble_validate(ensemble)) {
    return OTRNG_ERROR;
  }

  // TODO: @client_profile As part of validating the prekey ensemble, we should
  // also:
  // 1. If the Transitional Signature is present, verify its validity using the
  // OTRv3 DSA key.
  //    (the OTRv3 key needed to validate the signature should be somewhere in
  //    client maybe).
  // 1. Check if the Client Profile's version is supported by the receiver.

  // TODO: @non_interactive Decide whether to send a message using this Prekey
  // Ensemble if the long-term key within the Client Profile is trusted or not.
  // Maybe use a callback for this.
  if (!set_their_client_profile(ensemble->client_profile, otr)) {
    return OTRNG_ERROR;
  }

  if (!set_their_prekey_profile(ensemble->prekey_profile, otr)) {
    return OTRNG_ERROR;
  }

  warn = OTRNG_WARN_NONE;
  /* Set their ephemeral keys, instance tag, and their_prekeys_id */
  if (!prekey_message_received(ensemble->message, &warn, otr)) {
    if (warn == OTRNG_WARN_MALFORMED) {
      otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    }
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

// TODO: Will this exist?
API otrng_result otrng_send_offline_message(char **dst,
                                            const prekey_ensemble_s *ensemble,
                                            const char *plaintext,
                                            otrng_s *otr) {
  (void)dst;
  (void)ensemble;
  (void)plaintext;
  (void)otr;
  // This was supposed to send the non interactive auth AND the encrypted data
  // message on the same network message.
  return OTRNG_ERROR;
}

API otrng_result otrng_send_non_interactive_auth(
    char **dst, const prekey_ensemble_s *ensemble, otrng_s *otr) {
  otrng_fingerprint_p fp;
  *dst = NULL;

  if (!receive_prekey_ensemble(dst, ensemble, otr)) {
    return OTRNG_ERROR; // TODO: should unset the stored things from ensemble
  }

  otr->running_version = OTRNG_PROTOCOL_VERSION_4;

  if (otrng_serialize_fingerprint(
          fp, otr->their_client_profile->long_term_pub_key)) {
    fingerprint_seen_cb_v4(fp, otr);
  }

  return reply_with_non_interactive_auth_msg(dst, otr);
}

tstatic otrng_result generate_tmp_key_i(uint8_t *dst, otrng_s *otr) {
  k_ecdh_p k_ecdh;
  k_ecdh_p tmp_ecdh_k1;
  k_ecdh_p tmp_ecdh_k2;
  dh_shared_secret_p k_dh;
  size_t k_dh_len = 0;
  brace_key_p brace_key;

  // TODO: @refactoring this workaround is not the nicest there is
  if (!otrng_ecdh_shared_secret(k_ecdh, sizeof(k_ecdh),
                                otr->keys->our_ecdh->priv,
                                otr->keys->their_ecdh)) {
    return OTRNG_ERROR;
  }

  if (!otrng_dh_shared_secret(k_dh, &k_dh_len, otr->keys->our_dh->priv,
                              otr->keys->their_dh)) {
    return OTRNG_ERROR;
  }

  hash_hash(brace_key, sizeof(brace_key_p), k_dh, k_dh_len);

  sodium_memzero(k_dh, sizeof(k_dh));

#ifdef DEBUG
  debug_print("\n");
  debug_print("GENERATING TEMP KEY I\n");
  debug_print("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_p));
  debug_print("brace_key = ");
  otrng_memdump(brace_key, sizeof(brace_key_p));
#endif

  if (!otrng_ecdh_shared_secret(tmp_ecdh_k1, sizeof(tmp_ecdh_k1),
                                our_shared_prekey(otr)->priv,
                                their_ecdh(otr))) {
    return OTRNG_ERROR;
  }

  if (!otrng_ecdh_shared_secret(tmp_ecdh_k2, sizeof(tmp_ecdh_k1),
                                otr->client->keypair->priv, their_ecdh(otr))) {
    return OTRNG_ERROR;
  }

  otrng_key_manager_calculate_tmp_key(dst, k_ecdh, brace_key, tmp_ecdh_k1,
                                      tmp_ecdh_k2);

#ifdef DEBUG
  debug_print("\n");
  debug_print("GENERATING TEMP KEY I\n");
  debug_print("tmp_key_i = ");
  otrng_memdump(dst, HASH_BYTES);
#endif

  sodium_memzero(tmp_ecdh_k1, ED448_POINT_BYTES);
  sodium_memzero(tmp_ecdh_k2, ED448_POINT_BYTES);

  return OTRNG_SUCCESS;
}

tstatic otrng_bool verify_non_interactive_auth_message(
    otrng_response_s *response, const dake_non_interactive_auth_message_s *auth,
    otrng_s *otr) {
  const otrng_prekey_profile_s *prekey_profile;
  uint8_t *phi = NULL;
  size_t phi_len = 0;
  unsigned char *t = NULL;
  size_t t_len = 0;
  uint8_t mac_tag[DATA_MSG_MAC_BYTES];

  const otrng_dake_participant_data_s initiator = {
      .client_profile = (client_profile_s *)get_my_client_profile(otr),
      .exp_client_profile = (client_profile_s *)get_my_exp_client_profile(otr),
      .prekey_profile =
          (otrng_prekey_profile_s *)get_my_exp_prekey_profile(otr),
      .exp_prekey_profile =
          (otrng_prekey_profile_s *)get_my_exp_prekey_profile(otr),
      .ecdh = *(otr->keys->our_ecdh->pub),
      .dh = our_dh(otr),
  };

  const otrng_dake_participant_data_s responder = {
      .client_profile = (client_profile_s *)auth->profile,
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(auth->X),
      .dh = auth->A,
  };

  (void)response;

  if (!initiator.prekey_profile) {
    return otrng_false;
  }

  if (!generate_phi_sending(&phi, &phi_len, otr)) {
    return otrng_false;
  }

  /* t = KDF_2(Bobs_User_Profile) || KDF_2(Alices_User_Profile) ||
   * Y || X || B || A || our_shared_prekey.public */
  if (!build_non_interactive_rsign_tag(&t, &t_len, &initiator, &responder,
                                       prekey_profile->shared_prekey, phi,
                                       phi_len)) {
    free(phi);
    return otrng_false;
  }

  /* RVrf({F_b, H_a, Y}, sigma, msg) */
  if (!otrng_rsig_verify(auth->sigma, *otr->client->forging_key, /* H_b */
                         auth->profile->long_term_pub_key,       /* H_a */
                         our_ecdh(otr),                          /* Y  */
                         t, t_len)) {
    free(t);
    t = NULL;

    if (initiator.exp_client_profile && initiator.exp_prekey_profile) {
      /* the fallback */
      if (!build_fallback_non_interactive_rsign_tag(
              &t, &t_len, &initiator, &responder,
              initiator.exp_prekey_profile->shared_prekey, phi, phi_len)) {
        free(phi);
        return otrng_false;
      }

      if (!otrng_rsig_verify(auth->sigma, *otr->client->forging_key, /* H_b */
                             auth->profile->long_term_pub_key,       /* H_a */
                             our_ecdh(otr),                          /* Y  */
                             t, t_len)) {
        free(phi);
        free(t);
        return otrng_false;
      }

      free(phi);
      return otrng_false;
    }
  }

  free(phi);

  /* Check mac */
  if (!otrng_dake_non_interactive_auth_message_authenticator(
          mac_tag, auth, t, t_len, otr->keys->tmp_key)) {
    free(t);
    /* here no warning should be passed */
    return otrng_false;
  }

  free(t);

  /* here no warning should be passed */
  if (0 != otrl_mem_differ(mac_tag, auth->auth_mac, DATA_MSG_MAC_BYTES)) {
    sodium_memzero(mac_tag, DATA_MSG_MAC_BYTES);
    return otrng_false;
  }

  return otrng_true;
}

tstatic otrng_result non_interactive_auth_message_received(
    otrng_response_s *response, const dake_non_interactive_auth_message_p auth,
    otrng_s *otr) {
  otrng_client_s *client = otr->client;
  const otrng_stored_prekeys_s *stored_prekey = NULL;
  otrng_fingerprint_p fp;

  if (!client) {
    return OTRNG_ERROR;
  }

  if (received_sender_instance_tag(auth->sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_MALFORMED);
    return OTRNG_ERROR;
  }

  if (!valid_receiver_instance_tag(auth->receiver_instance_tag)) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_MALFORMED);
    return OTRNG_ERROR;
  }

  if (!otrng_valid_received_values(auth->sender_instance_tag, auth->X, auth->A,
                                   auth->profile)) {
    return OTRNG_ERROR;
  }

  stored_prekey =
      otrng_client_get_my_prekeys_by_id(auth->prekey_message_id, otr->client);
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

  // Shared prekey is the same as used to generate my current prekey profile.
  // Should be always true, though.
  // TODO: it seems people ignore the error message returned from this
  // function...
  if (!otrng_ec_point_eq(our_shared_prekey(otr)->pub,
                         get_my_prekey_profile(otr)->shared_prekey)) {
    return OTRNG_ERROR;
  }

  /* Set our current ephemeral keys, based on the received message */
  otrng_ecdh_keypair_destroy(otr->keys->our_ecdh);
  otrng_ec_scalar_copy(otr->keys->our_ecdh->priv,
                       stored_prekey->our_ecdh->priv);
  otrng_ec_point_copy(otr->keys->our_ecdh->pub, stored_prekey->our_ecdh->pub);

  otrng_dh_keypair_destroy(otr->keys->our_dh);
  otr->keys->our_dh->priv = otrng_dh_mpi_copy(stored_prekey->our_dh->priv);
  otr->keys->our_dh->pub = otrng_dh_mpi_copy(stored_prekey->our_dh->pub);

  // TODO: this has to happen long before, for this to work
  if (auth->receiver_instance_tag != stored_prekey->sender_instance_tag) {
    return OTRNG_SUCCESS;
  }

  /* Delete the stored prekeys for this ID so they can't be used again. */
  otrng_client_delete_my_prekey_message_by_id(auth->prekey_message_id, client);

  otrng_key_manager_set_their_ecdh(auth->X, otr->keys);
  otrng_key_manager_set_their_dh(auth->A, otr->keys);

  // TODO: @client_profile Extract function to set_their_client_profile
  otr->their_client_profile = otrng_xmalloc(sizeof(client_profile_s));

  otrng_client_profile_copy(otr->their_client_profile, auth->profile);

  /* tmp_k = KDF_1(usage_tmp_key || K_ecdh ||
   * ECDH(x, our_shared_prekey.secret, their_ecdh) ||
   * ECDH(Ska, X) || brace_key) */
  if (!generate_tmp_key_i(otr->keys->tmp_key, otr)) {
    return OTRNG_ERROR;
  }

  // TODO: this should happen before we change any internal state
  if (!verify_non_interactive_auth_message(response, auth, otr)) {
    return OTRNG_ERROR;
  }

  if (otrng_serialize_fingerprint(
          fp, otr->their_client_profile->long_term_pub_key)) {
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
  dake_non_interactive_auth_message_p auth;
  otrng_result ret;

  if (otr->state == OTRNG_STATE_FINISHED) {
    return OTRNG_SUCCESS; /* ignore the message */
  }

  if (!otrng_dake_non_interactive_auth_message_deserialize(auth, src, len)) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_MALFORMED);
    return OTRNG_ERROR;
  }

  // TODO: we should actually care about the result here before setting the
  // state
  ret = non_interactive_auth_message_received(response, auth, otr);
  otrng_dake_non_interactive_auth_message_destroy(auth);

  otr->state = OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE;

  return ret;
}

tstatic otrng_result receive_identity_message_on_state_start(
    string_p *dst, dake_identity_message_s *identity_message, otrng_s *otr) {
  otr->their_client_profile = otrng_xmalloc(sizeof(client_profile_s));

  otrng_key_manager_set_their_ecdh(identity_message->Y, otr->keys);
  otrng_key_manager_set_their_dh(identity_message->B, otr->keys);
  otrng_client_profile_copy(otr->their_client_profile,
                            identity_message->profile);

  /* @secret the priv parts will be deleted once the mixed shared secret is
   * derived */
  if (!otrng_key_manager_generate_ephemeral_keys(otr->keys)) {
    return OTRNG_ERROR;
  }

  if (!reply_with_auth_r_msg(dst, otr)) {
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
                                              const uint8_t *buff,
                                              size_t buflen, otrng_s *otr) {
  otrng_result result = OTRNG_ERROR;
  dake_identity_message_p m;

  if (!otrng_dake_identity_message_deserialize(m, buff, buflen)) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    return result;
  }

  if (received_sender_instance_tag(m->sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    otrng_dake_identity_message_destroy(m);
    return result;
  }

  if (!otrng_valid_received_values(m->sender_instance_tag, m->Y, m->B,
                                   m->profile)) {
    otrng_dake_identity_message_destroy(m);
    return result;
  }

  switch (otr->state) {
  case OTRNG_STATE_START:
    result = receive_identity_message_on_state_start(dst, m, otr);
    break;
  case OTRNG_STATE_WAITING_AUTH_R:
    result = receive_identity_message_on_waiting_auth_r(dst, m, otr);
    break;
  case OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE:
  case OTRNG_STATE_WAITING_AUTH_I:
    result = receive_identity_message_on_waiting_auth_i(dst, m, otr);
    break;
  case OTRNG_STATE_NONE:
  case OTRNG_STATE_ENCRYPTED_MESSAGES:
  case OTRNG_STATE_FINISHED:
    result = receive_identity_message_on_state_start(dst, m, otr);
    break;
  }

  otrng_dake_identity_message_destroy(m);
  return result;
}

tstatic otrng_result serialize_and_encode_auth_i(string_p *dst,
                                                 const dake_auth_i_s *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (!otrng_dake_auth_i_asprintf(&buff, &len, m)) {
    return OTRNG_ERROR;
  }

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  return OTRNG_SUCCESS;
}

tstatic otrng_result reply_with_auth_i_msg(
    string_p *dst, const client_profile_s *their_client_profile, otrng_s *otr) {
  dake_auth_i_p msg;

  const otrng_dake_participant_data_s responder = {
      .client_profile = (client_profile_s *)their_client_profile,
      .exp_client_profile = NULL,
      .prekey_profile = NULL,
      .exp_prekey_profile = NULL,
      .ecdh = *(otr->keys->their_ecdh),
      .dh = their_dh(otr),
  };

  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_result result;

  msg->sender_instance_tag = our_instance_tag(otr);
  msg->receiver_instance_tag = otr->their_instance_tag;

  if (!generate_receiving_rsig_tag(&t, &t_len, 'i', &responder, otr)) {
    return OTRNG_ERROR;
  }

  /* sigma = RSig(H_b, sk_hb, {H_b, F_a, X}, t) */
  if (!otrng_rsig_authenticate(msg->sigma,
                               otr->client->keypair->priv, /* sk_hb */
                               otr->client->keypair->pub,  /* H_b */
                               otr->client->keypair->pub,  /* H_b */
                               their_client_profile->forging_pub_key, /* F_a */
                               their_ecdh(otr),                       /* X */
                               t, t_len)) {
    free(t);
    return OTRNG_ERROR;
  }

  free(t);

  result = serialize_and_encode_auth_i(dst, msg);
  otrng_dake_auth_i_destroy(msg);

  return result;
}

tstatic otrng_bool valid_auth_r_message(const dake_auth_r_s *auth,
                                        otrng_s *otr) {
  unsigned char *t = NULL;
  size_t t_len = 0;
  otrng_bool err;

  const otrng_dake_participant_data_s responder = {
      .client_profile = (client_profile_s *)auth->profile,
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

  /* RVrf({F_b, H_a, Y}, sigma, msg) */
  err = otrng_rsig_verify(auth->sigma, *otr->client->forging_key, /* F_b */
                          auth->profile->long_term_pub_key,       /* H_a */
                          our_ecdh(otr),                          /* Y */
                          t, t_len);

  free(t);
  return err;
}

tstatic otrng_result receive_auth_r(string_p *dst, const uint8_t *buff,
                                    size_t buff_len, otrng_s *otr) {
  dake_auth_r_p auth;
  otrng_fingerprint_p fp;
  otrng_result ret;

  if (otr->state != OTRNG_STATE_WAITING_AUTH_R) {
    return OTRNG_SUCCESS; /* ignore the message */
  }

  if (!otrng_dake_auth_r_deserialize(auth, buff, buff_len)) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    return OTRNG_ERROR;
  }

  if (auth->receiver_instance_tag != our_instance_tag(otr)) {
    otrng_dake_auth_r_destroy(auth);
    return OTRNG_SUCCESS;
  }

  if (received_sender_instance_tag(auth->sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    otrng_dake_auth_r_destroy(auth);
    return OTRNG_ERROR;
  }

  if (!valid_receiver_instance_tag(auth->receiver_instance_tag)) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    otrng_dake_auth_r_destroy(auth);
    return OTRNG_ERROR;
  }

  if (!valid_auth_r_message(auth, otr)) {
    otrng_dake_auth_r_destroy(auth);
    return OTRNG_ERROR;
  }

  otr->their_client_profile = otrng_xmalloc(sizeof(client_profile_s));

  otrng_key_manager_set_their_ecdh(auth->X, otr->keys);
  otrng_key_manager_set_their_dh(auth->A, otr->keys);
  otrng_client_profile_copy(otr->their_client_profile, auth->profile);

  if (!reply_with_auth_i_msg(dst, otr->their_client_profile, otr)) {
    otrng_dake_auth_r_destroy(auth);
    return OTRNG_ERROR;
  }

  otrng_dake_auth_r_destroy(auth);

  if (otrng_serialize_fingerprint(
          fp, otr->their_client_profile->long_term_pub_key)) {
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

  /* RVrf({H_b, F_a, X}, sigma, msg) */
  err = otrng_rsig_verify(
      auth->sigma, otr->their_client_profile->long_term_pub_key, /* H_b */
      *otr->client->forging_key,                                 /* F_a */
      our_ecdh(otr),                                             /* X */
      t, t_len);

  free(t);

  return err;
}

tstatic otrng_result receive_auth_i(char **dst, const uint8_t *buff,
                                    size_t buff_len, otrng_s *otr) {
  dake_auth_i_p auth;
  otrng_fingerprint_p fp;

  if (otr->state != OTRNG_STATE_WAITING_AUTH_I) {
    return OTRNG_SUCCESS; /* Ignore the message */
  }

  if (!otrng_dake_auth_i_deserialize(auth, buff, buff_len)) {
    otrng_error_message(dst, OTRNG_ERR_MSG_MALFORMED);
    return OTRNG_ERROR;
  }

  if (auth->receiver_instance_tag != our_instance_tag(otr)) {
    otrng_dake_auth_i_destroy(auth);
    return OTRNG_SUCCESS;
  }

  if (received_sender_instance_tag(auth->sender_instance_tag, otr) !=
      OTRNG_SUCCESS) {
    otrng_dake_auth_i_destroy(auth);
    return OTRNG_ERROR;
  }

  if (!valid_receiver_instance_tag(auth->receiver_instance_tag)) {
    otrng_dake_auth_i_destroy(auth);
    return OTRNG_ERROR;
  }

  if (!valid_auth_i_message(auth, otr)) {
    otrng_dake_auth_i_destroy(auth);
    return OTRNG_ERROR;
  }

  otrng_dake_auth_i_destroy(auth);

  if (otrng_serialize_fingerprint(
          fp, otr->their_client_profile->long_term_pub_key)) {
    fingerprint_seen_cb_v4(fp, otr);
  }

  if (!double_ratcheting_init(otr, 't')) {
    return OTRNG_ERROR;
  }

  // Reply with initial data message
  // TODO: this ignores the warning received. that might
  // be valid, but should be investigated.
  return otrng_send_message(dst, "", NULL, NULL, MSGFLAGS_IGNORE_UNREADABLE,
                            otr);
}

// TODO: @refactoring this is the same as otrng_close
INTERNAL otrng_result otrng_expire_session(string_p *to_send, otrng_s *otr) {
  size_t serlen = otrng_list_len(otr->keys->skipped_keys) * MAC_KEY_BYTES;
  uint8_t *ser_mac_keys = otrng_reveal_mac_keys_on_tlv(otr->keys);
  tlv_list_s *disconnected;
  otrng_warning warn;
  otrng_result result;

  otr->keys->skipped_keys = NULL;

  disconnected = otrng_tlv_list_one(
      otrng_tlv_new(OTRNG_TLV_DISCONNECTED, serlen, ser_mac_keys));
  free(ser_mac_keys);

  if (!disconnected) {
    return OTRNG_ERROR;
  }

  warn = OTRNG_WARN_NONE;
  // TODO: we are ignoring the warning/notification happening here
  result = otrng_send_message(to_send, "", &warn, disconnected,
                              MSGFLAGS_IGNORE_UNREADABLE, otr);

  forget_our_keys(otr);
  otr->state = OTRNG_STATE_START;
  gone_insecure_cb_v4(otr);

  return result;
}

tstatic tlv_list_s *deserialize_received_tlvs(const uint8_t *src, size_t len) {
  uint8_t *tlvs_start = NULL;
  size_t tlvs_len;

  tlvs_start = memchr(src, 0, len);
  if (!tlvs_start) {
    return NULL;
  }

  tlvs_len = len - (tlvs_start + 1 - src);
  return otrng_parse_tlvs(tlvs_start + 1, tlvs_len);
}

tstatic otrng_result decrypt_data_msg(otrng_response_s *response,
                                      const msg_enc_key_p enc_key,
                                      const data_message_s *msg) {
  string_p *dst = &response->to_display;
  uint8_t *plain;
  int err;

#ifdef DEBUG
  debug_print("\n");
  debug_print("DECRYPTING\n");
  debug_print("enc_key = ");
  otrng_memdump(enc_key, sizeof(msg_enc_key_p));
  debug_print("nonce = ");
  otrng_memdump(msg->nonce, DATA_MSG_NONCE_BYTES);
#endif

  // TODO: @initialization What if msg->enc_msg_len == 0?
  plain = otrng_xmalloc(msg->enc_msg_len);

  err = crypto_stream_xor(plain, msg->enc_msg, msg->enc_msg_len, msg->nonce,
                          enc_key);

  if (err) {
    free(plain);
    return OTRNG_ERROR;
  }

  /* If plain != "" and msg->enc_msg_len != 0 */
  if (otrng_strnlen((string_p)plain, msg->enc_msg_len)) {
    *dst = otrng_xstrndup((char *)plain, msg->enc_msg_len);
  }

  response->tlvs = deserialize_received_tlvs(plain, msg->enc_msg_len);
  free(plain);
  return OTRNG_SUCCESS;
}

tstatic unsigned int extract_word(const unsigned char *bufp) {
  unsigned int use =
      (bufp[0] << 24) | (bufp[1] << 16) | (bufp[2] << 8) | bufp[3];
  return use;
}

tstatic tlv_s *process_tlv(const tlv_s *tlv, otrng_s *otr) {
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
    sodium_memzero(otr->keys->extra_symmetric_key,
                   sizeof(otr->keys->extra_symmetric_key));
    return NULL;
  }

  sodium_memzero(otr->keys->extra_symmetric_key, sizeof(extra_symmetric_key_p));

  return otrng_process_smp_tlv(tlv, otr);
}

tstatic otrng_result process_received_tlvs(tlv_list_s **to_send,
                                           otrng_response_s *response,
                                           otrng_s *otr) {
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
  // TODO: this ignores the warning received. that might
  // be valid, but should be investigated.
  ret = otrng_send_message(&response->to_send, "", NULL, reply_tlvs,
                           MSGFLAGS_IGNORE_UNREADABLE, otr);
  otrng_tlv_list_free(reply_tlvs);
  return ret;
}

tstatic otrng_result otrng_receive_data_message_after_dake(
    otrng_response_s *response, otrng_warning *warn, const uint8_t *buff,
    size_t buflen, otrng_s *otr) {
  data_message_s *msg = otrng_data_message_new();
  msg_enc_key_p enc_key;
  msg_mac_key_p mac_key;
  size_t read = 0;
  receiving_ratchet_s *tmp_receiving_ratchet;

  memset(enc_key, 0, sizeof(msg_enc_key_p));
  memset(mac_key, 0, sizeof(msg_mac_key_p));

  response->to_display = NULL;

  if (otrng_failed(otrng_data_message_deserialize(msg, buff, buflen, &read))) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_MALFORMED);
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
    return OTRNG_ERROR;
  }

  if (!valid_receiver_instance_tag(msg->receiver_instance_tag)) {
    otrng_error_message(&response->to_send, OTRNG_ERR_MSG_MALFORMED);
    return OTRNG_ERROR;
  }

  // TODO: we still need to persist our_dh->priv
  tmp_receiving_ratchet = otrng_receiving_ratchet_new(otr->keys);

  otrng_key_manager_set_their_tmp_keys(msg->ecdh, msg->dh,
                                       tmp_receiving_ratchet);

  do {
    /* Try to decrypt the message with a stored skipped message key */
    if (otrng_failed(otrng_key_get_skipped_keys(
            enc_key, mac_key, msg->ratchet_id, msg->message_id, otr->keys,
            tmp_receiving_ratchet))) {
      /* if a new ratchet */
      if (otrng_failed(otrng_key_manager_derive_dh_ratchet_keys(
              otr->keys, otr->client->max_stored_msg_keys,
              tmp_receiving_ratchet, msg->message_id, msg->previous_chain_n,
              'r', warn))) {
        otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);

        return OTRNG_ERROR;
      }

      if (otrng_failed(otrng_key_manager_derive_chain_keys(
              enc_key, mac_key, otr->keys, tmp_receiving_ratchet,
              otr->client->max_stored_msg_keys, msg->message_id, 'r', warn))) {
        return OTRNG_ERROR;
      }

      tmp_receiving_ratchet->k = tmp_receiving_ratchet->k + 1;
    }
    if (!otrng_valid_data_message(mac_key, msg)) {
      sodium_memzero(enc_key, sizeof(enc_key));
      sodium_memzero(mac_key, sizeof(mac_key));
      otrng_data_message_free(msg);

      if (tmp_receiving_ratchet->skipped_keys) {
        otrng_list_free_full(tmp_receiving_ratchet->skipped_keys);
      }
      otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);

      response->warning = OTRNG_WARN_RECEIVED_NOT_VALID;
      if (warn) {
        *warn = OTRNG_WARN_RECEIVED_NOT_VALID;
      }

      return OTRNG_ERROR;
    }

    if (otrng_failed(decrypt_data_msg(response, enc_key, msg))) {

      if (msg->flags != MSGFLAGS_IGNORE_UNREADABLE) {
        otrng_error_message(&response->to_send, OTRNG_ERR_MSG_UNREADABLE);
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(mac_key, sizeof(mac_key));

        if (tmp_receiving_ratchet->skipped_keys) {
          otrng_list_free_full(tmp_receiving_ratchet->skipped_keys);
        }
        otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);

        otrng_data_message_free(msg);

        return OTRNG_ERROR;
      }
      if (msg->flags == MSGFLAGS_IGNORE_UNREADABLE) {
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        if (tmp_receiving_ratchet->skipped_keys) {
          otrng_list_free_full(tmp_receiving_ratchet->skipped_keys);
        }
        otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);
        otrng_data_message_free(msg);

        return OTRNG_ERROR;
      }
    }

    sodium_memzero(enc_key, sizeof(enc_key));

    otrng_receiving_ratchet_copy(otr->keys, tmp_receiving_ratchet);
    otrng_receiving_ratchet_destroy(tmp_receiving_ratchet);

    if (otrng_failed(receive_tlvs(response, otr))) {
      continue;
    }

    if (otrng_failed(otrng_store_old_mac_keys(otr->keys, mac_key))) {
      continue;
    }

    // TODO: @client this displays an event on otrv3..
    if (!response->to_display) {
      sodium_memzero(mac_key, sizeof(msg_mac_key_p));
      otrng_data_message_free(msg);
      return OTRNG_SUCCESS;
    }

    if (otr->client->should_heartbeat(otr->last_sent)) {
      if (!otrng_send_message(&response->to_send, "", warn, NULL,
                              MSGFLAGS_IGNORE_UNREADABLE, otr)) {
        sodium_memzero(mac_key, sizeof(msg_mac_key_p));
        otrng_data_message_free(msg);
        return OTRNG_ERROR;
      }
      otr->last_sent = time(NULL);
    }

    sodium_memzero(mac_key, sizeof(msg_mac_key_p));
    otrng_data_message_free(msg);

    return OTRNG_SUCCESS;
  } while (0);

  sodium_memzero(mac_key, sizeof(msg_mac_key_p));
  otrng_data_message_free(msg);

  return OTRNG_ERROR;
}

tstatic otrng_result otrng_receive_data_message(otrng_response_s *response,
                                                otrng_warning *warn,
                                                const uint8_t *buff,
                                                size_t buflen, otrng_s *otr) {
  if (otr->state == OTRNG_STATE_WAITING_DAKE_DATA_MESSAGE) {
    if (otrng_receive_data_message_after_dake(response, warn, buff, buflen,
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

  return otrng_receive_data_message_after_dake(response, warn, buff, buflen,
                                               otr);
}

API otrng_result otrng_extract_header(otrng_header_s *dst,
                                      const uint8_t *buffer,
                                      const size_t bufflen) {
  size_t read = 0;

  if (bufflen < 3) {
    return OTRNG_ERROR;
  }

  if (!dst) {
    return OTRNG_ERROR;
  }

  if (!otrng_deserialize_uint16(&dst->version, buffer, bufflen, &read)) {
    return OTRNG_ERROR;
  }

  buffer += read;

  if (!otrng_deserialize_uint8(&dst->type, buffer, bufflen - read, &read)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result receive_decoded_message(otrng_response_s *response,
                                             otrng_warning *warn,
                                             const uint8_t *decoded,
                                             size_t dec_len, otrng_s *otr) {
  otrng_header_s header;
  int v3_allowed, v4_allowed;

  if (otrng_failed(otrng_extract_header(&header, decoded, dec_len))) {
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
    return otrng_receive_data_message(response, warn, decoded, dec_len, otr);
  default:
    /* error. bad message type */
    return OTRNG_ERROR;
  }
}

tstatic otrng_result receive_encoded_message(otrng_response_s *response,
                                             otrng_warning *warn,
                                             const string_p message,
                                             otrng_s *otr) {
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  otrng_result result;

  if (otrl_base64_otr_decode(message, &decoded, &dec_len)) {
    return OTRNG_ERROR;
  }

  result = receive_decoded_message(response, warn, decoded, dec_len, otr);
  free(decoded);

  return result;
}

tstatic otrng_result receive_error_message(otrng_response_s *response,
                                           const string_p message) {
  // TODO: We should not assume English as the language. This should be
  // generated via callback: the plugin knows in which language this should be
  // displayed to the user.
  const char *unreadable_msg_error = "Unreadable message";
  const char *not_in_private_error = "Not in private state message";
  const char *encryption_error = "Encryption error";
  const char *malformed_error = "Malformed message";

  if (strncmp(message, "ERROR_1:", 8) == 0) {
    response->to_display =
        otrng_xstrndup(unreadable_msg_error, strlen(unreadable_msg_error));
    return OTRNG_SUCCESS;
  } else if (strncmp(message, "ERROR_2:", 8) == 0) {
    response->to_display =
        otrng_xstrndup(not_in_private_error, strlen(not_in_private_error));
    return OTRNG_SUCCESS;
  } else if (strncmp(message, "ERROR_3:", 8) == 0) {
    response->to_display =
        otrng_xstrndup(encryption_error, strlen(encryption_error));
    return OTRNG_SUCCESS;
  } else if (strncmp(message, "ERROR_4:", 8) == 0) {
    response->to_display =
        otrng_xstrndup(malformed_error, strlen(malformed_error));
    return OTRNG_SUCCESS;
  }

  return OTRNG_ERROR;
}

API int otrng_get_message_type(const string_p message) {
  if (message_contains_tag(message)) {
    return MSG_TAGGED_PLAINTEXT;
  }
  if (message_is_query(message)) {
    return MSG_QUERY_STRING;
  } else if (message_is_otr_error(message)) {
    return MSG_OTR_ERROR;
  } else if (message_is_otr_encoded(message)) {
    return MSG_OTR_ENCODED;
  }

  return MSG_PLAINTEXT;
}

tstatic otrng_result receive_message_v4_only(otrng_response_s *response,
                                             otrng_warning *warn,
                                             const string_p message,
                                             otrng_s *otr) {
  switch (otrng_get_message_type(message)) {
  case MSG_PLAINTEXT:
    receive_plaintext(response, message, otr);
    return OTRNG_SUCCESS;

  case MSG_TAGGED_PLAINTEXT:
    return receive_tagged_plaintext(response, message, otr);

  case MSG_QUERY_STRING:
    return receive_query_message(response, message, otr);

  case MSG_OTR_ENCODED:
    return receive_encoded_message(response, warn, message, otr);

  case MSG_OTR_ERROR:
    return receive_error_message(response, message + strlen(ERROR_PREFIX));
  }

  return OTRNG_SUCCESS;
}

/* Receive a possibly OTR message. */
INTERNAL otrng_result otrng_receive_message(otrng_response_s *response,
                                            otrng_warning *warn,
                                            const string_p message,
                                            otrng_s *otr) {
  char *defrag = NULL;
  otrng_result ret;

  response->warning = OTRNG_WARN_NONE;
  response->to_display = NULL;

  if (otrng_failed(otrng_unfragment_message(&defrag, &otr->pending_fragments,
                                            message, our_instance_tag(otr)))) {
    return OTRNG_ERROR;
  }

  ret = otrng_receive_defragmented_message(response, warn, defrag, otr);
  free(defrag);
  return ret;
}

INTERNAL otrng_result otrng_receive_defragmented_message(
    otrng_response_s *response, otrng_warning *warn, const string_p message,
    otrng_s *otr) {

  if (!message || !response) {
    return OTRNG_ERROR;
  }

  response->to_display = NULL;

  /* A DH-Commit sets our running version to 3 */
  if (allow_version(otr, OTRNG_ALLOW_V3) && strstr(message, "?OTR:AAMC")) {
    otr->running_version = OTRNG_PROTOCOL_VERSION_3;
  }

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, message, otr->v3_conn);
  case OTRNG_PROTOCOL_VERSION_4:
  default:
    // V4 handles every message BUT v3 messages
    return receive_message_v4_only(response, warn, message, otr);
  }
}

INTERNAL otrng_result otrng_send_message(string_p *to_send,
                                         const string_p message,
                                         otrng_warning *warn,
                                         const tlv_list_s *tlvs, uint8_t flags,
                                         otrng_s *otr) {
  if (!otr) {
    return OTRNG_ERROR;
  }

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_3:
    return otrng_v3_send_message(to_send, message, tlvs, otr->v3_conn);
  case OTRNG_PROTOCOL_VERSION_4:
    return otrng_prepare_to_send_data_message(to_send, warn, message, tlvs, otr,
                                              flags);
  default:
    return OTRNG_ERROR;
  }
}

tstatic otrng_result otrng_close_v4(string_p *to_send, otrng_s *otr) {
  size_t serlen;
  uint8_t *ser_mac_keys;
  tlv_list_s *disconnected;
  otrng_warning warn;
  otrng_result result;

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return OTRNG_SUCCESS;
  }

  serlen = otrng_list_len(otr->keys->skipped_keys) * MAC_KEY_BYTES;
  ser_mac_keys = otrng_reveal_mac_keys_on_tlv(otr->keys);
  otr->keys->skipped_keys = NULL;

  disconnected = otrng_tlv_list_one(
      otrng_tlv_new(OTRNG_TLV_DISCONNECTED, serlen, ser_mac_keys));
  free(ser_mac_keys);

  if (!disconnected) {
    return OTRNG_ERROR;
  }

  warn = OTRNG_WARN_NONE;
  // TODO: we are ignoring the warning here. Send in NULL if we don't care.
  // Otherwise we should act on it.
  result = otrng_send_message(to_send, "", &warn, disconnected,
                              MSGFLAGS_IGNORE_UNREADABLE, otr);

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
    otrng_v3_close(to_send,
                   otr->v3_conn); // TODO: @client This should return an error
                                  // but errors are reported on a
                                  // callback
    gone_insecure_cb_v4(otr);     // TODO: @client Only if success
    return OTRNG_SUCCESS;
  case OTRNG_PROTOCOL_VERSION_4:
    return otrng_close_v4(to_send, otr);
  default:
    return OTRNG_ERROR;
  }
}

tstatic otrng_result otrng_send_symkey_message_v4(
    string_p *to_send, unsigned int use, const unsigned char *usedata,
    size_t usedatalen, otrng_s *otr, unsigned char *extra_key) {
  unsigned char *tlv_data;
  tlv_list_s *tlvs;
  otrng_warning warn;
  otrng_result ret;

  if (usedatalen > 0 && !usedata) {
    return OTRNG_ERROR;
  }

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return OTRNG_ERROR;
  }

  tlv_data = otrng_xmalloc(usedatalen + 4);

  tlv_data[0] = (use >> 24) & 0xff;
  tlv_data[1] = (use >> 16) & 0xff;
  tlv_data[2] = (use >> 8) & 0xff;
  tlv_data[3] = (use)&0xff;

  if (usedatalen > 0) {
    memmove(tlv_data + 4, usedata, usedatalen);
  }

  memmove(extra_key, otr->keys->extra_symmetric_key,
          sizeof(extra_symmetric_key_p));

  tlvs = otrng_tlv_list_one(
      otrng_tlv_new(OTRNG_TLV_SYM_KEY, usedatalen + 4, tlv_data));
  free(tlv_data);

  // TODO: @freeing Should not extra_key be zeroed if any error happens from
  // here on?
  if (!tlvs) {
    return OTRNG_ERROR;
  }

  warn = OTRNG_WARN_NONE;
  // TODO: @refactoring in v3 the extra_key is passed as a param to this
  // do the same?
  // TODO: if we don't care about the warning, send in NULL. Otherwise
  // act on it
  ret = otrng_send_message(to_send, "", &warn, tlvs, MSGFLAGS_IGNORE_UNREADABLE,
                           otr);
  otrng_tlv_list_free(tlvs);

  return ret;
}

API otrng_result otrng_send_symkey_message(string_p *to_send, unsigned int use,
                                           const unsigned char *usedata,
                                           size_t usedatalen,
                                           uint8_t *extra_key, otrng_s *otr) {
  if (!otr) {
    return OTRNG_ERROR;
  }

  switch (otr->running_version) {
  case OTRNG_PROTOCOL_VERSION_3:
    otrng_v3_send_symkey_message(to_send, otr->v3_conn, use, usedata,
                                 usedatalen,
                                 extra_key); // TODO: @client This should return
                                             // an error but errors are reported
                                             // on a callback
    return OTRNG_SUCCESS;
  case OTRNG_PROTOCOL_VERSION_4:
    return otrng_send_symkey_message_v4(to_send, use, usedata, usedatalen, otr,
                                        extra_key);
  default:
    return OTRNG_ERROR;
  }
}

#define GCRYPT_WANTED_VERSION_16 "1.6.4"
#define GCRYPT_WANTED_VERSION_17 "1.7.6"
#define GCRYPT_WANTED_VERSION_18 "1.8.0"

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

  r = otrng_v3_init(die);

  if (otrng_failed(r)) {
    return r;
  }
  return otrng_dh_init(die);
}

static int otrl_initialized = 0;
API otrng_result otrng_v3_init(otrng_bool die) {
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

char *
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

  sss = otrng_xmalloc(sss_len);

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
