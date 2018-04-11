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

#include <libotr/b64.h>
#include <libotr/mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OTRNG_OTRNG_PRIVATE

#include "constants.h"
#include "dake.h"
#include "data_message.h"
#include "deserialize.h"
#include "gcrypt.h"
#include "otrng.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"
#include "tlv.h"

#include "debug.h"

#define OUR_ECDH(s) s->keys->our_ecdh->pub
#define OUR_DH(s) s->keys->our_dh->pub
#define THEIR_ECDH(s) s->keys->their_ecdh
#define THEIR_DH(s) s->keys->their_dh

#define HEARTBEAT(s) s->conversation->client->heartbeat

#define QUERY_MESSAGE_TAG_BYTES 5
#define WHITESPACE_TAG_BASE_BYTES 16
#define WHITESPACE_TAG_VERSION_BYTES 8

static const char tag_base[] = {'\x20', '\x09', '\x20', '\x20', '\x09', '\x09',
                                '\x09', '\x09', '\x20', '\x09', '\x20', '\x09',
                                '\x20', '\x09', '\x20', '\x20', '\0'};

static const char tag_version_v4[] = {'\x20', '\x20', '\x09', '\x09', '\x20',
                                      '\x09', '\x20', '\x20', '\0'};

static const char tag_version_v3[] = {'\x20', '\x20', '\x09', '\x09', '\x20',
                                      '\x20', '\x09', '\x09', '\0'};

static const string_t query_header = "?OTRv";
static const string_t otr_error_header = "?OTR Error:";
static const string_t otr_header = "?OTR:";

tstatic void create_privkey_cb_v4(const otrng_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  // TODO: Change to receive conv->client
  conv->client->callbacks->create_privkey(conv->client->client_id);
}

tstatic void gone_secure_cb_v4(const otrng_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  conv->client->callbacks->gone_secure(conv);
}

tstatic void gone_insecure_cb_v4(const otrng_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  conv->client->callbacks->gone_insecure(conv);
}

tstatic void fingerprint_seen_cb_v4(const otrng_fingerprint_t fp,
                                    const otrng_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  conv->client->callbacks->fingerprint_seen(fp, conv);
}

tstatic void handle_smp_event_cb_v4(const otrng_smp_event_t event,
                                    const uint8_t progress_percent,
                                    const uint8_t *question, const size_t q_len,
                                    const otrng_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  switch (event) {
  case OTRNG_SMPEVENT_ASK_FOR_SECRET:
    conv->client->callbacks->smp_ask_for_secret(conv);
    break;
  case OTRNG_SMPEVENT_ASK_FOR_ANSWER:
    conv->client->callbacks->smp_ask_for_answer(question, q_len, conv);
    break;
  case OTRNG_SMPEVENT_CHEATED:
  case OTRNG_SMPEVENT_IN_PROGRESS:
  case OTRNG_SMPEVENT_SUCCESS:
  case OTRNG_SMPEVENT_FAILURE:
  case OTRNG_SMPEVENT_ABORT:
  case OTRNG_SMPEVENT_ERROR:
    conv->client->callbacks->smp_update(event, progress_percent, conv);
    break;
  default:
    // OTRNG_SMPEVENT_NONE. Should not be used.
    break;
  }
}

tstatic void received_symkey_cb_v4(const otrng_conversation_state_t *conv,
                                   unsigned int use,
                                   const unsigned char *usedata,
                                   size_t usedatalen,
                                   const unsigned char *extra_key) {
  UNUSED_ARG(conv);
  UNUSED_ARG(use);
  UNUSED_ARG(usedata);
  UNUSED_ARG(usedatalen);
  UNUSED_ARG(extra_key);

#ifdef DEBUG
  printf("Received symkey use: %08x\n", use);
  printf("Usedata lenght: %zu\n", usedatalen);
  printf("Usedata: ");
  for (unsigned int i = 0; i < usedatalen; i++) {
    printf("%02x", usedata[i]);
  }
  printf("\n");
  printf("Symkey: ");
  for (int i = 0; i < HASH_BYTES; i++) {
    printf("0x%02x, ", extra_key[i]);
  }
  printf("\n");
#endif
}

tstatic void maybe_create_keys(const otrng_conversation_state_t *conv) {
  if (!conv->client->keypair)
    create_privkey_cb_v4(conv);
}

tstatic int allow_version(const otrng_t *otr, otrng_supported_version version) {
  return (otr->supported_versions & version);
}

/* dst must be at least 3 bytes long. */
tstatic void allowed_versions(string_t dst, const otrng_t *otr) {
  if (allow_version(otr, OTRNG_ALLOW_V4))
    *dst++ = '4';

  if (allow_version(otr, OTRNG_ALLOW_V3))
    *dst++ = '3';

  *dst = 0;
}

tstatic const user_profile_t *get_my_user_profile(otrng_t *otr) {
  if (otr->profile)
    return otr->profile;

  char versions[3] = {0};
  allowed_versions(versions, otr);
  maybe_create_keys(otr->conversation);

  // This is a temporary measure for the pidgin plugin to work
  // This will be removed later
  uint8_t sym_key[ED448_PRIVATE_BYTES] = {0x01};
  otrng_client_state_add_shared_prekey_v4(otr->conversation->client, sym_key);

  otr->profile =
      otrng_user_profile_build(versions, otr->conversation->client->keypair,
                               otr->conversation->client->shared_prekey_pair);
  return otr->profile;
}

INTERNAL otrng_t *otrng_new(otrng_client_state_t *state,
                            otrng_policy_t policy) {
  otrng_t *otr = malloc(sizeof(otrng_t));
  if (!otr)
    return NULL;

  // TODO: Move to constructor
  otr->conversation = malloc(sizeof(otrng_conversation_state_t));
  otr->conversation->client = state;
  otr->conversation->peer = NULL;

  otr->state = OTRNG_STATE_START;
  otr->running_version = OTRNG_VERSION_NONE;
  otr->supported_versions = policy.allows;

  otr->their_instance_tag = 0;
  otr->our_instance_tag = otrng_client_state_get_instance_tag(state);
  otr->profile = NULL;
  otr->their_profile = NULL;

  otr->keys = malloc(sizeof(key_manager_t));
  if (!otr->keys) {
    free(otr);
    otr = NULL;
    return NULL;
  }

  otrng_key_manager_init(otr->keys);
  otrng_smp_context_init(otr->smp);

  otr->frag_ctx = otrng_fragment_context_new();
  otr->v3_conn = NULL;

  return otr;
}

tstatic void otrng_destroy(/*@only@ */ otrng_t *otr) {
  if (otr->conversation) {
    free(otr->conversation->peer);
    otr->conversation->peer = NULL;
    free(otr->conversation);
    otr->conversation = NULL;
  }

  otrng_key_manager_destroy(otr->keys);
  free(otr->keys);
  otr->keys = NULL;

  otrng_user_profile_free(otr->profile);
  otr->profile = NULL;

  otrng_user_profile_free(otr->their_profile);
  otr->their_profile = NULL;

  otrng_smp_destroy(otr->smp);

  otrng_fragment_context_free(otr->frag_ctx);

  otrng_v3_conn_free(otr->v3_conn);
  otr->v3_conn = NULL;
}

INTERNAL void otrng_free(/*@only@ */ otrng_t *otr) {
  if (otr == NULL) {
    return;
  }

  otrng_destroy(otr);
  free(otr);
  otr = NULL;
}

INTERNAL otrng_err_t otrng_build_query_message(string_t *dst,
                                               const string_t message,
                                               const otrng_t *otr) {
  /* size = qm tag + versions + msg length + versions
   * + question mark + whitespace + null byte */
  size_t qm_size = QUERY_MESSAGE_TAG_BYTES + 3 + strlen(message) + 2 + 1;
  string_t buff = NULL;
  char allowed[3] = {0};

  *dst = NULL;
  allowed_versions(allowed, otr);

  buff = malloc(qm_size);
  if (!buff)
    return ERROR;

  char *cursor = stpcpy(buff, query_header);
  cursor = stpcpy(cursor, allowed);
  cursor = stpcpy(cursor, "? ");

  int rem = cursor - buff;

  /* Add '\0' */
  if (*stpncpy(cursor, message, qm_size - rem)) {
    free(buff);
    buff = NULL;
    return ERROR; /* could not zero-terminate the string */
  }

  *dst = buff;
  return SUCCESS;
}

API otrng_err_t otrng_build_whitespace_tag(string_t *whitespace_tag,
                                           const string_t message,
                                           const otrng_t *otr) {
  size_t m_size = WHITESPACE_TAG_BASE_BYTES + strlen(message) + 1;
  int allows_v4 = allow_version(otr, OTRNG_ALLOW_V4);
  int allows_v3 = allow_version(otr, OTRNG_ALLOW_V3);
  string_t buff = NULL;
  string_t cursor = NULL;

  if (allows_v4)
    m_size += WHITESPACE_TAG_VERSION_BYTES;

  if (allows_v3)
    m_size += WHITESPACE_TAG_VERSION_BYTES;

  buff = malloc(m_size);
  if (!buff)
    return ERROR;

  cursor = stpcpy(buff, tag_base);

  if (allows_v4)
    cursor = stpcpy(cursor, tag_version_v4);

  if (allows_v3)
    cursor = stpcpy(cursor, tag_version_v3);

  if (*stpncpy(cursor, message, m_size - strlen(buff))) {
    free(buff);
    buff = NULL;
    return ERROR;
  }

  *whitespace_tag = buff;
  return SUCCESS;
}

tstatic otrng_bool_t message_contains_tag(const string_t message) {
  return strstr(message, tag_base) != NULL;
}

tstatic void set_to_display(otrng_response_t *response,
                            const string_t message) {
  size_t msg_len = strlen(message);
  response->to_display = otrng_strndup(message, msg_len);
}

tstatic otrng_err_t message_to_display_without_tag(otrng_response_t *response,
                                                   const string_t message,
                                                   size_t msg_len) {
  size_t tag_length = WHITESPACE_TAG_BASE_BYTES + WHITESPACE_TAG_VERSION_BYTES;
  size_t chars = msg_len - tag_length;

  if (msg_len < tag_length)
    return ERROR;

  string_t buff = malloc(chars + 1);
  if (buff == NULL)
    return ERROR;

  char *found_at = strstr(message, tag_base);
  if (!found_at)
    return ERROR;

  size_t bytes_before_tag = found_at - message;
  if (!bytes_before_tag) {
    strncpy(buff, message + tag_length, chars);
  } else {
    strncpy(buff, message, bytes_before_tag);
    strncpy(buff, message + bytes_before_tag, chars - bytes_before_tag);
  }
  buff[chars] = '\0';

  response->to_display = otrng_strndup(buff, chars);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic void set_running_version_from_tag(otrng_t *otr,
                                          const string_t message) {
  if (allow_version(otr, OTRNG_ALLOW_V4) && strstr(message, tag_version_v4)) {
    otr->running_version = OTRNG_VERSION_4;
    return;
  }

  if (allow_version(otr, OTRNG_ALLOW_V3) && strstr(message, tag_version_v3)) {
    otr->running_version = OTRNG_VERSION_3;
    return;
  }
}

tstatic bool message_is_query(const string_t message) {
  return strstr(message, query_header) != NULL;
}

tstatic void set_running_version_from_query_msg(otrng_t *otr,
                                                const string_t message) {
  if (allow_version(otr, OTRNG_ALLOW_V4) && strstr(message, "4")) {
    otr->running_version = OTRNG_VERSION_4;
    return;
  }

  if (allow_version(otr, OTRNG_ALLOW_V3) && strstr(message, "3")) {
    otr->running_version = OTRNG_VERSION_3;
    return;
  }
}

tstatic bool message_is_otr_encoded(const string_t message) {
  return strstr(message, otr_header) != NULL;
}

tstatic bool message_is_otr_error(const string_t message) {
  return strstr(message, otr_error_header) != NULL;
}

INTERNAL otrng_response_t *otrng_response_new(void) {
  otrng_response_t *response = malloc(sizeof(otrng_response_t));
  if (!response)
    return NULL;

  response->to_display = NULL;
  response->to_send = NULL;
  response->warning = OTRNG_WARN_NONE;
  response->tlvs = NULL;

  return response;
}

INTERNAL void otrng_response_free(otrng_response_t *response) {
  if (!response)
    return;

  if (response->to_display) {
    free(response->to_display);
    response->to_display = NULL;
  }

  if (response->to_send) {
    free(response->to_send);
    response->to_send = NULL;
  }

  response->warning = OTRNG_WARN_NONE;

  otrng_tlv_list_free(response->tlvs);
  response->tlvs = NULL;

  free(response);
  response = NULL;
}

// TODO: Is not receiving a plaintext a problem?
tstatic void receive_plaintext(otrng_response_t *response,
                               const string_t message, const otrng_t *otr) {
  set_to_display(response, message);

  if (otr->state != OTRNG_STATE_START)
    response->warning = OTRNG_WARN_RECEIVED_UNENCRYPTED;
}

tstatic otrng_err_t serialize_and_encode_prekey_message(
    string_t *dst, const dake_prekey_message_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrng_dake_prekey_message_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic otrng_err_t otrng_build_prekey_message(otrng_server_t *server,
                                               otrng_t *otr) {
  dake_prekey_message_t *m = NULL;
  otrng_err_t err = ERROR;

  m = otrng_dake_prekey_message_new(get_my_user_profile(otr));
  if (!m)
    return err;

  m->sender_instance_tag = otr->our_instance_tag;
  m->receiver_instance_tag = otr->their_instance_tag;

  otrng_ec_point_copy(m->Y, OUR_ECDH(otr));
  m->B = otrng_dh_mpi_copy(OUR_DH(otr));

  if (serialize_and_encode_prekey_message(&server->prekey_message, m)) {
    otrng_dake_prekey_message_free(m);
    return err;
  }

  otrng_dake_prekey_message_free(m);

  return SUCCESS;
}

tstatic otrng_err_t reply_with_prekey_msg_to_server(otrng_server_t *server,
                                                    otrng_t *otr) {
  return otrng_build_prekey_message(server, otr);
}

API void otrng_reply_with_prekey_msg_from_server(otrng_server_t *server,
                                                 otrng_response_t *response) {
  response->to_send = server->prekey_message;
}

tstatic otrng_err_t serialize_and_encode_identity_message(
    string_t *dst, const dake_identity_message_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrng_dake_identity_message_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic otrng_err_t reply_with_identity_msg(otrng_response_t *response,
                                            otrng_t *otr) {
  dake_identity_message_t *m = NULL;
  otrng_err_t err = ERROR;

  m = otrng_dake_identity_message_new(get_my_user_profile(otr));
  if (!m)
    return err;

  m->sender_instance_tag = otr->our_instance_tag;
  m->receiver_instance_tag = otr->their_instance_tag;

  otrng_ec_point_copy(m->Y, OUR_ECDH(otr));
  m->B = otrng_dh_mpi_copy(OUR_DH(otr));

  if (serialize_and_encode_identity_message(&response->to_send, m)) {
    otrng_dake_identity_message_free(m);
    return err;
  }

  otrng_dake_identity_message_free(m);

  return SUCCESS;
}

tstatic otrng_err_t start_dake(otrng_response_t *response, otrng_t *otr) {
  if (otrng_key_manager_generate_ephemeral_keys(otr->keys) == ERROR)
    return ERROR;

  otr->state = OTRNG_STATE_WAITING_AUTH_R;
  maybe_create_keys(otr->conversation);
  return reply_with_identity_msg(response, otr);
}

API otrng_err_t otrng_start_non_interactive_dake(otrng_server_t *server,
                                                 otrng_t *otr) {
  if (otrng_key_manager_generate_ephemeral_keys(otr->keys) == ERROR)
    return ERROR;

  otr->state = OTRNG_STATE_START; // needed?
  maybe_create_keys(otr->conversation);

  return reply_with_prekey_msg_to_server(server, otr);
}

tstatic otrng_err_t receive_tagged_plaintext(otrng_response_t *response,
                                             const string_t message,
                                             otrng_t *otr) {
  set_running_version_from_tag(otr, message);

  switch (otr->running_version) {
  case OTRNG_VERSION_4:
    if (message_to_display_without_tag(response, message, strlen(message))) {
      return ERROR;
    }
    otrng_dh_priv_key_destroy(otr->keys->our_dh);
    otrng_ec_scalar_destroy(otr->keys->our_ecdh->priv);
    return start_dake(response, otr);
    break;
  case OTRNG_VERSION_3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, message, otr->v3_conn);
    break;
  case OTRNG_VERSION_NONE:
    /* ignore */
    return SUCCESS;
  }

  return ERROR;
}

tstatic otrng_err_t receive_query_message(otrng_response_t *response,
                                          const string_t message,
                                          otrng_t *otr) {
  set_running_version_from_query_msg(otr, message);

  switch (otr->running_version) {
  case OTRNG_VERSION_4:
    otrng_dh_priv_key_destroy(otr->keys->our_dh);
    otrng_ec_scalar_destroy(otr->keys->our_ecdh->priv);
    return start_dake(response, otr);
    break;
  case OTRNG_VERSION_3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, message, otr->v3_conn);
    break;
  case OTRNG_VERSION_NONE:
    /* ignore */
    return SUCCESS;
  }

  return ERROR;
}

tstatic otrng_err_t build_auth_message(
    uint8_t **msg, size_t *msg_len, const uint8_t type,
    const user_profile_t *i_profile, const user_profile_t *r_profile,
    const ec_point_t i_ecdh, const ec_point_t r_ecdh, const dh_mpi_t i_dh,
    const dh_mpi_t r_dh, char *phi) {
  uint8_t *ser_i_profile = NULL, *ser_r_profile = NULL;
  size_t ser_i_profile_len, ser_r_profile_len = 0;
  uint8_t ser_i_ecdh[ED448_POINT_BYTES], ser_r_ecdh[ED448_POINT_BYTES];
  uint8_t ser_i_dh[DH3072_MOD_LEN_BYTES], ser_r_dh[DH3072_MOD_LEN_BYTES];
  size_t ser_i_dh_len = 0, ser_r_dh_len = 0;
  uint8_t hash_ser_i_profile[HASH_BYTES];
  uint8_t hash_ser_r_profile[HASH_BYTES];
  uint8_t hash_phi[HASH_BYTES];

  otrng_serialize_ec_point(ser_i_ecdh, i_ecdh);
  otrng_serialize_ec_point(ser_r_ecdh, r_ecdh);

  if (otrng_serialize_dh_public_key(ser_i_dh, &ser_i_dh_len, i_dh))
    return ERROR;

  if (otrng_serialize_dh_public_key(ser_r_dh, &ser_r_dh_len, r_dh))
    return ERROR;

  do {
    if (otrng_user_profile_asprintf(&ser_i_profile, &ser_i_profile_len,
                                    i_profile))
      continue;

    if (otrng_user_profile_asprintf(&ser_r_profile, &ser_r_profile_len,
                                    r_profile))
      continue;

    char *phi_val = NULL;
    if (!phi) {
      phi = "";
    }
    phi_val = otrng_strdup(phi);
    if (!phi_val)
      return ERROR;

    shake_256_hash(hash_ser_i_profile, sizeof(hash_ser_i_profile),
                   ser_i_profile, ser_i_profile_len);
    shake_256_hash(hash_ser_r_profile, sizeof(hash_ser_r_profile),
                   ser_r_profile, ser_r_profile_len);
    shake_256_hash(hash_phi, sizeof(hash_phi), (uint8_t *)phi_val,
                   strlen(phi_val) + 1);

    free(phi_val);
    phi_val = NULL;

    size_t len = 1 + 2 * ED448_POINT_BYTES + 2 * HASH_BYTES + ser_i_dh_len +
                 ser_r_dh_len + HASH_BYTES;

    uint8_t *buff = malloc(len);
    if (!buff)
      continue;

    uint8_t *cursor = buff;
    *cursor = type;
    cursor++;

    memcpy(cursor, hash_ser_i_profile, HASH_BYTES);
    cursor += HASH_BYTES;

    memcpy(cursor, hash_ser_r_profile, HASH_BYTES);
    cursor += HASH_BYTES;

    memcpy(cursor, ser_i_ecdh, ED448_POINT_BYTES);
    cursor += ED448_POINT_BYTES;

    memcpy(cursor, ser_r_ecdh, ED448_POINT_BYTES);
    cursor += ED448_POINT_BYTES;

    memcpy(cursor, ser_i_dh, ser_i_dh_len);
    cursor += ser_i_dh_len;

    memcpy(cursor, ser_r_dh, ser_r_dh_len);
    cursor += ser_r_dh_len;

    memcpy(cursor, hash_phi, HASH_BYTES);
    cursor += HASH_BYTES;

    *msg = buff;
    *msg_len = len;
  } while (0);

  free(ser_i_profile);
  ser_i_profile = NULL;
  free(ser_r_profile);
  ser_r_profile = NULL;

  sodium_memzero(ser_i_ecdh, ED448_POINT_BYTES);
  sodium_memzero(ser_r_ecdh, ED448_POINT_BYTES);
  sodium_memzero(ser_i_dh, DH3072_MOD_LEN_BYTES);
  sodium_memzero(ser_r_dh, DH3072_MOD_LEN_BYTES);

  return SUCCESS;
}

tstatic otrng_err_t serialize_and_encode_auth_r(string_t *dst,
                                                const dake_auth_r_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrng_dake_auth_r_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic otrng_err_t reply_with_auth_r_msg(string_t *dst, otrng_t *otr) {
  dake_auth_r_t msg[1];

  msg->sender_instance_tag = otr->our_instance_tag;
  msg->receiver_instance_tag = otr->their_instance_tag;

  otrng_user_profile_copy(msg->profile, get_my_user_profile(otr));

  otrng_ec_point_copy(msg->X, OUR_ECDH(otr));
  msg->A = otrng_dh_mpi_copy(OUR_DH(otr));

  unsigned char *t = NULL;
  size_t t_len = 0;

  if (build_auth_message(&t, &t_len, 0, otr->their_profile,
                         get_my_user_profile(otr), THEIR_ECDH(otr),
                         OUR_ECDH(otr), THEIR_DH(otr), OUR_DH(otr),
                         otr->conversation->client->phi))
    return ERROR;

  /* sigma = Auth(g^R, R, {g^I, g^R, g^i}, msg) */
  otrng_snizkpk_authenticate(msg->sigma,
                             otr->conversation->client->keypair, /* g^R and R */
                             otr->their_profile->pub_key,        /* g^I */
                             THEIR_ECDH(otr),                    /* g^i -- Y */
                             t, t_len);

  free(t);
  t = NULL;

  otrng_err_t err = serialize_and_encode_auth_r(dst, msg);
  otrng_dake_auth_r_destroy(msg);

  return err;
}

tstatic otrng_err_t generate_tmp_key_r(uint8_t *dst, otrng_t *otr) {
  k_ecdh_t tmp_ecdh_k1;
  k_ecdh_t tmp_ecdh_k2;
  k_ecdh_t k_ecdh;
  k_dh_t k_dh;

  // TODO: this will be calculated again later
  otrng_ecdh_shared_secret(k_ecdh, otr->keys->our_ecdh, otr->keys->their_ecdh);
  // TODO: this will be calculated again later
  if (otrng_dh_shared_secret(k_dh, sizeof(k_dh_t), otr->keys->our_dh->priv,
                             otr->keys->their_dh))
    return ERROR;

  brace_key_t brace_key;
  hash_hash(brace_key, sizeof(brace_key_t), k_dh, sizeof(k_dh_t));

#ifdef DEBUG
  printf("GENERATING TEMP KEY R\n");
  printf("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_t));
  printf("brace_key = ");
  otrng_memdump(brace_key, sizeof(brace_key_t));
#endif

  otrng_ecdh_shared_secret(tmp_ecdh_k1, otr->keys->our_ecdh,
                           otr->keys->their_shared_prekey);
  otrng_ecdh_shared_secret(tmp_ecdh_k2, otr->keys->our_ecdh,
                           otr->their_profile->pub_key);

  goldilocks_shake256_ctx_t hd;
  hash_init_with_dom(hd);
  hash_update(hd, k_ecdh, ED448_POINT_BYTES);
  hash_update(hd, tmp_ecdh_k1, ED448_POINT_BYTES);
  hash_update(hd, tmp_ecdh_k2, ED448_POINT_BYTES);
  hash_update(hd, brace_key, sizeof(brace_key_t));

  hash_final(hd, dst, HASH_BYTES);
  hash_destroy(hd);

#ifdef DEBUG
  printf("GENERATING TEMP KEY R\n");
  printf("tmp_key_i = ");
  otrng_memdump(dst, HASH_BYTES);
#endif

  sodium_memzero(tmp_ecdh_k1, ED448_POINT_BYTES);
  sodium_memzero(tmp_ecdh_k2, ED448_POINT_BYTES);

  return SUCCESS;
}

tstatic otrng_err_t build_non_interactive_auth_message(
    uint8_t **msg, size_t *msg_len, const user_profile_t *i_profile,
    const user_profile_t *r_profile, const ec_point_t i_ecdh,
    const ec_point_t r_ecdh, const dh_mpi_t i_dh, const dh_mpi_t r_dh,
    const otrng_shared_prekey_pub_t r_shared_prekey, char *phi) {
  uint8_t *ser_i_profile = NULL, *ser_r_profile = NULL;
  size_t ser_i_profile_len, ser_r_profile_len = 0;
  uint8_t ser_i_ecdh[ED448_POINT_BYTES], ser_r_ecdh[ED448_POINT_BYTES];
  uint8_t ser_i_dh[DH3072_MOD_LEN_BYTES], ser_r_dh[DH3072_MOD_LEN_BYTES];
  size_t ser_i_dh_len = 0, ser_r_dh_len = 0;
  uint8_t ser_r_shared_prekey[ED448_SHARED_PREKEY_BYTES];
  uint8_t hash_ser_i_profile[HASH_BYTES];
  uint8_t hash_ser_r_profile[HASH_BYTES];
  uint8_t hash_phi[HASH_BYTES];

  otrng_serialize_ec_point(ser_i_ecdh, i_ecdh);
  otrng_serialize_ec_point(ser_r_ecdh, r_ecdh);

  if (otrng_serialize_dh_public_key(ser_i_dh, &ser_i_dh_len, i_dh))
    return ERROR;

  if (otrng_serialize_dh_public_key(ser_r_dh, &ser_r_dh_len, r_dh))
    return ERROR;

  otrng_serialize_otrng_shared_prekey(ser_r_shared_prekey, r_shared_prekey);

  otrng_err_t err = ERROR;

  do {
    if (otrng_user_profile_asprintf(&ser_i_profile, &ser_i_profile_len,
                                    i_profile))
      continue;

    if (otrng_user_profile_asprintf(&ser_r_profile, &ser_r_profile_len,
                                    r_profile))
      continue;

    uint8_t *phi_val = NULL;
    size_t phi_len = strlen(phi) + 1;
    phi_val = malloc(phi_len);
    if (!phi_val)
      return ERROR;

    stpcpy((char *)phi_val, phi);

    shake_256_hash(hash_ser_i_profile, sizeof(hash_ser_i_profile),
                   ser_i_profile, ser_i_profile_len);

    shake_256_hash(hash_ser_r_profile, sizeof(hash_ser_r_profile),
                   ser_r_profile, ser_r_profile_len);

    shake_256_hash(hash_phi, sizeof(hash_phi), phi_val, phi_len);
    free(phi_val);
    phi_val = NULL;

    size_t len = 2 * ED448_POINT_BYTES + 2 * HASH_BYTES + ser_i_dh_len +
                 ser_r_dh_len + ED448_SHARED_PREKEY_BYTES + HASH_BYTES;

    uint8_t *buff = malloc(len);
    if (!buff)
      continue;

    uint8_t *cursor = buff;

    memcpy(cursor, hash_ser_i_profile, HASH_BYTES);
    cursor += HASH_BYTES;

    memcpy(cursor, hash_ser_r_profile, HASH_BYTES);
    cursor += HASH_BYTES;

    memcpy(cursor, ser_i_ecdh, ED448_POINT_BYTES);
    cursor += ED448_POINT_BYTES;

    memcpy(cursor, ser_r_ecdh, ED448_POINT_BYTES);
    cursor += ED448_POINT_BYTES;

    memcpy(cursor, ser_i_dh, ser_i_dh_len);
    cursor += ser_i_dh_len;

    memcpy(cursor, ser_r_dh, ser_r_dh_len);
    cursor += ser_r_dh_len;

    memcpy(cursor, ser_r_shared_prekey, ED448_SHARED_PREKEY_BYTES);
    cursor += ED448_SHARED_PREKEY_BYTES;

    memcpy(cursor, hash_phi, HASH_BYTES);
    cursor += HASH_BYTES;

    *msg = buff;
    *msg_len = len;
    err = SUCCESS;
  } while (0);

  free(ser_i_profile);
  ser_i_profile = NULL;
  free(ser_r_profile);
  ser_r_profile = NULL;

  sodium_memzero(ser_i_ecdh, ED448_POINT_BYTES);
  sodium_memzero(ser_r_ecdh, ED448_POINT_BYTES);
  sodium_memzero(ser_i_dh, DH3072_MOD_LEN_BYTES);
  sodium_memzero(ser_r_dh, DH3072_MOD_LEN_BYTES);
  sodium_memzero(ser_r_shared_prekey, ED448_SHARED_PREKEY_BYTES);

  return err;
}

tstatic otrng_err_t serialize_and_encode_non_interactive_auth(
    string_t *dst, const dake_non_interactive_auth_message_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrng_dake_non_interactive_auth_message_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic data_message_t *generate_data_msg(const otrng_t *otr) {
  data_message_t *data_msg = otrng_data_message_new();
  if (!data_msg)
    return NULL;

  data_msg->sender_instance_tag = otr->our_instance_tag;
  data_msg->receiver_instance_tag = otr->their_instance_tag;
  data_msg->message_id = otr->keys->j;
  otrng_ec_point_copy(data_msg->ecdh, OUR_ECDH(otr));
  data_msg->dh = otrng_dh_mpi_copy(OUR_DH(otr));

  return data_msg;
}

tstatic otrng_err_t encrypt_data_message(data_message_t *data_msg,
                                         const uint8_t *message,
                                         size_t message_len,
                                         const m_enc_key_t enc_key) {
  int err = 0;
  uint8_t *c = NULL;

  random_bytes(data_msg->nonce, sizeof(data_msg->nonce));

  c = malloc(message_len);
  if (!c)
    return ERROR;

  // TODO: message is an UTF-8 string. Is there any problem to cast
  // it to (unsigned char *)
  err = crypto_stream_xor(c, message, message_len, data_msg->nonce, enc_key);
  if (err) {
    free(c);
    c = NULL;
    return ERROR;
  }

  data_msg->enc_msg_len = message_len;
  data_msg->enc_msg = c;

#ifdef DEBUG
  printf("nonce = ");
  otrng_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
  printf("msg = ");
  otrng_memdump(message, message_len);
  printf("cipher = ");
  otrng_memdump(c, message_len);
#endif

  return SUCCESS;
}

tstatic otrng_err_t encrypt_msg_on_non_interactive_auth(
    dake_non_interactive_auth_message_t *auth, uint8_t *message,
    size_t message_len, uint8_t nonce[DATA_MSG_NONCE_BYTES], otrng_t *otr) {
  auth->message_id = otr->keys->j;

  m_enc_key_t enc_key;
  m_mac_key_t mac_key;
  memset(enc_key, 0, sizeof enc_key);
  memset(mac_key, 0, sizeof mac_key);

  if (otrng_key_manager_retrieve_sending_message_keys(enc_key, mac_key,
                                                      otr->keys)) {
    free(message);
    message = NULL;
    return ERROR;
  }

  /* discard this mac key as it is not used */
  sodium_memzero(mac_key, sizeof(m_mac_key_t));
  memcpy(auth->nonce, nonce, DATA_MSG_NONCE_BYTES);

  int err = 0;
  uint8_t *c = NULL;
  c = malloc(message_len);
  if (!c) {
    free(message);
    message = NULL;
    return ERROR;
  }

  // TODO: message is an UTF-8 string. Is there any problem to cast
  // it to (unsigned char *)?
  err = crypto_stream_xor(c, message, message_len, nonce, enc_key);
  if (err) {
    free(c);
    c = NULL;
    return ERROR;
  }

  auth->enc_msg_len = message_len;
  auth->enc_msg = c;

#ifdef DEBUG
  printf("nonce = ");
  otrng_memdump(nonce, DATA_MSG_NONCE_BYTES);
  printf("msg = ");
  otrng_memdump(message, message_len);
  printf("cipher = ");
  otrng_memdump(c, message_len);
#endif

  sodium_memzero(enc_key, sizeof(m_enc_key_t));

  return SUCCESS;
}

tstatic otrng_err_t data_message_body_on_non_interactive_asprintf(
    uint8_t **body, size_t *bodylen,
    const dake_non_interactive_auth_message_t *auth) {
  size_t s = 4 + DATA_MSG_NONCE_BYTES + auth->enc_msg_len + 4;

  uint8_t *dst = malloc(s);
  if (!dst)
    return ERROR;

  uint8_t *cursor = dst;
  cursor += otrng_serialize_uint32(cursor, auth->message_id);
  cursor +=
      otrng_serialize_bytes_array(cursor, auth->nonce, DATA_MSG_NONCE_BYTES);
  cursor += otrng_serialize_data(cursor, auth->enc_msg, auth->enc_msg_len);

  if (body)
    *body = dst;

  if (bodylen)
    *bodylen = cursor - dst;

  return SUCCESS;
}

tstatic otrng_err_t reply_with_non_interactive_auth_msg(string_t *dst,
                                                        uint8_t *message,
                                                        size_t msglen,
                                                        otrng_t *otr) {
  dake_non_interactive_auth_message_t auth[1];
  auth->enc_msg = NULL;
  auth->enc_msg_len = 0;

  auth->sender_instance_tag = otr->our_instance_tag;
  auth->receiver_instance_tag = otr->their_instance_tag;

  otrng_user_profile_copy(auth->profile, get_my_user_profile(otr));

  otrng_ec_point_copy(auth->X, OUR_ECDH(otr));
  auth->A = otrng_dh_mpi_copy(OUR_DH(otr));

  /* auth_mac_k = KDF_2(0x01 || tmp_k) */
  uint8_t magic[1] = {0x01};
  uint8_t auth_mac_k[HASH_BYTES];
  shake_256_kdf(auth_mac_k, sizeof(auth_mac_k), magic, otr->keys->tmp_key,
                HASH_BYTES);

  unsigned char *t = NULL;
  size_t t_len = 0;

  /* t = KDF_2(Bobs_User_Profile) || KDF_2(Alices_User_Profile) ||
   * Y || X || B || A || our_shared_prekey.public */
  if (build_non_interactive_auth_message(
          &t, &t_len, otr->their_profile, get_my_user_profile(otr),
          THEIR_ECDH(otr), OUR_ECDH(otr), THEIR_DH(otr), OUR_DH(otr),
          otr->their_profile->shared_prekey, otr->conversation->client->phi)) {
    if (message) {
      free(message);
      message = NULL;
    }
    otrng_dake_non_interactive_auth_message_destroy(auth);

    return ERROR;
  }

  /* sigma = Auth(g^R, R, {g^I, g^R, g^i}, msg) */
  otrng_snizkpk_authenticate(auth->sigma,
                             otr->conversation->client->keypair, /* g^R and R */
                             otr->their_profile->pub_key,        /* g^I */
                             THEIR_ECDH(otr),                    /* g^i -- Y */
                             t, t_len);

  sodium_memzero(auth->nonce, DATA_MSG_NONCE_BYTES);

  if (message) {
    uint8_t nonce[DATA_MSG_NONCE_BYTES];
    uint8_t *ser_data_msg = NULL;

    memcpy(nonce, t, DATA_MSG_NONCE_BYTES);

    if (encrypt_msg_on_non_interactive_auth(auth, message, msglen, nonce,
                                            otr)) {
      otrng_dake_non_interactive_auth_message_destroy(auth);
      free(t);
      t = NULL;
      return ERROR;
    }

    free(message);
    message = NULL;

    size_t bodylen = 0;
    if (data_message_body_on_non_interactive_asprintf(&ser_data_msg, &bodylen,
                                                      auth)) {
      free(auth->enc_msg);
      auth->enc_msg = NULL;
      otrng_dake_non_interactive_auth_message_destroy(auth);
      free(t);
      t = NULL;
      return ERROR;
    }

    /* Auth MAC = KDF_2(auth_mac_k || t || (message_id || nonce || enc_msg)) */
    goldilocks_shake256_ctx_t hd;
    hash_init_with_dom(hd);
    hash_update(hd, auth_mac_k, sizeof(auth_mac_k));
    hash_update(hd, t, t_len);
    hash_update(hd, ser_data_msg, bodylen);
    hash_final(hd, auth->auth_mac, sizeof(auth->auth_mac));
    hash_destroy(hd);

    free(ser_data_msg);
    ser_data_msg = NULL;
  } else {
    /* Auth MAC = KDF_2(auth_mac_k || t) */
    shake_256_mac(auth->auth_mac, sizeof(auth->auth_mac), auth_mac_k,
                  sizeof(auth_mac_k), t, t_len);
  }

  free(t);
  t = NULL;

  otrng_err_t err = serialize_and_encode_non_interactive_auth(dst, auth);

  if (auth->enc_msg) {
    free(auth->enc_msg);
    auth->enc_msg = NULL;
  }
  otrng_dake_non_interactive_auth_message_destroy(auth);

  return err;
}

tstatic otrng_err_t generate_tmp_key_i(uint8_t *dst, otrng_t *otr) {
  k_ecdh_t k_ecdh;
  k_dh_t k_dh;
  k_ecdh_t tmp_ecdh_k1;
  k_ecdh_t tmp_ecdh_k2;

  // TODO: this will be calculated again later
  otrng_ecdh_shared_secret(k_ecdh, otr->keys->our_ecdh, otr->keys->their_ecdh);
  // TODO: this will be calculated again later
  if (otrng_dh_shared_secret(k_dh, sizeof(k_dh_t), otr->keys->our_dh->priv,
                             otr->keys->their_dh))
    return ERROR;

  brace_key_t brace_key;
  hash_hash(brace_key, sizeof(brace_key_t), k_dh, sizeof(k_dh_t));

#ifdef DEBUG
  printf("GENERATING TEMP KEY I\n");
  printf("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_t));
  printf("brace_key = ");
  otrng_memdump(brace_key, sizeof(brace_key_t));
#endif

  otrng_ecdh_shared_secret_from_prekey(
      tmp_ecdh_k1, otr->conversation->client->shared_prekey_pair,
      THEIR_ECDH(otr));
  otrng_ecdh_shared_secret_from_keypair(
      tmp_ecdh_k2, otr->conversation->client->keypair, THEIR_ECDH(otr));

  goldilocks_shake256_ctx_t hd;
  hash_init_with_dom(hd);
  hash_update(hd, k_ecdh, ED448_POINT_BYTES);
  hash_update(hd, tmp_ecdh_k1, ED448_POINT_BYTES);
  hash_update(hd, tmp_ecdh_k2, ED448_POINT_BYTES);
  hash_update(hd, brace_key, sizeof(brace_key_t));

  hash_final(hd, dst, HASH_BYTES);
  hash_destroy(hd);

#ifdef DEBUG
  printf("GENERATING TEMP KEY I\n");
  printf("tmp_key_i = ");
  otrng_memdump(dst, HASH_BYTES);
#endif

  sodium_memzero(tmp_ecdh_k1, ED448_POINT_BYTES);
  sodium_memzero(tmp_ecdh_k2, ED448_POINT_BYTES);

  return SUCCESS;
}

tstatic void otrng_error_message(string_t *to_send, otrng_err_code_t err_code) {
  char *msg = NULL;
  char *err_msg = NULL;

  switch (err_code) {
  case ERR_NONE:
    break;
  case ERR_MSG_UNDECRYPTABLE:
    msg = strdup("OTRNG_ERR_MSG_READABLE");
    err_msg =
        malloc(strlen(ERROR_PREFIX) + strlen(ERROR_CODE_1) + strlen(msg) + 1);
    if (!err_msg)
      return;

    if (err_msg) {
      strcpy(err_msg, ERROR_PREFIX);
      strcpy(err_msg + strlen(ERROR_PREFIX), ERROR_CODE_1);
      strcat(err_msg, msg);
    }
    free((char *)msg);
    msg = NULL;

    *to_send = otrng_strdup(err_msg);
    free(err_msg);
    err_msg = NULL;
    break;
  case ERR_MSG_NOT_PRIVATE:
    msg = strdup("OTRNG_ERR_MSG_NOT_PRIVATE_STATE");
    err_msg =
        malloc(strlen(ERROR_PREFIX) + strlen(ERROR_CODE_2) + strlen(msg) + 1);
    if (!err_msg)
      return;

    if (err_msg) {
      strcpy(err_msg, ERROR_PREFIX);
      strcpy(err_msg + strlen(ERROR_PREFIX), ERROR_CODE_2);
      strcat(err_msg, msg);
    }
    free((char *)msg);
    msg = NULL;

    *to_send = otrng_strdup(err_msg);
    free(err_msg);
    err_msg = NULL;
    break;
  }
}

tstatic otrng_err_t double_ratcheting_init(int j, bool interactive,
                                           otrng_t *otr) {
  if (otrng_key_manager_ratcheting_init(j, interactive, otr->keys))
    return ERROR;

  otr->state = OTRNG_STATE_ENCRYPTED_MESSAGES;
  gone_secure_cb_v4(otr->conversation);

  return SUCCESS;
}

tstatic void received_instance_tag(uint32_t their_instance_tag, otrng_t *otr) {
  // TODO: should we do any additional check?
  otr->their_instance_tag = their_instance_tag;
}

tstatic otrng_err_t receive_prekey_message(string_t *dst, const uint8_t *buff,
                                           size_t buflen, otrng_t *otr) {
  if (otr->state == OTRNG_STATE_FINISHED)
    return SUCCESS; /* ignore the message */

  otrng_err_t err = ERROR;
  dake_prekey_message_t m[1];

  if (otrng_dake_prekey_message_deserialize(m, buff, buflen))
    return err;

  if (m->receiver_instance_tag != 0) {
    otrng_dake_prekey_message_destroy(m);
    return SUCCESS;
  }

  received_instance_tag(m->sender_instance_tag, otr);

  if (otrng_valid_received_values(m->Y, m->B, m->profile)) {
    otrng_dake_prekey_message_destroy(m);
    return err;
  }

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile) {
    otrng_dake_prekey_message_destroy(m);
    return err;
  }

  otrng_key_manager_set_their_ecdh(m->Y, otr->keys);
  otrng_key_manager_set_their_dh(m->B, otr->keys);
  otrng_user_profile_copy(otr->their_profile, m->profile);

  otrng_dake_prekey_message_destroy(m);

  if (otrng_key_manager_generate_ephemeral_keys(otr->keys))
    return err;

  memcpy(otr->keys->their_shared_prekey, otr->their_profile->shared_prekey,
         sizeof(otrng_shared_prekey_pub_t));

  /* tmp_k = KDF_2(K_ecdh || ECDH(x, their_shared_prekey) ||
   * ECDH(x, Pkb) || k_dh) */
  if (generate_tmp_key_r(otr->keys->tmp_key, otr))
    return err;

  if (double_ratcheting_init(0, false, otr))
    return err;

  return SUCCESS;
}

API otrng_err_t otrng_send_non_interactive_auth_msg(string_t *dst, otrng_t *otr,
                                                    const string_t message) {
  uint8_t *c = NULL;
  size_t clen = strlen(message) + 1;

  if ((strcmp(message, "") != 0)) {
    c = malloc(clen);
    if (!c) {
      return ERROR;
    }

    stpcpy((char *)c, message);
  }

  *dst = NULL;

  return reply_with_non_interactive_auth_msg(dst, c, clen, otr);
}

tstatic otrng_bool_t valid_data_message_on_non_interactive_auth(
    unsigned char *t, size_t t_len, m_mac_key_t mac_key,
    const dake_non_interactive_auth_message_t *auth) {
  uint8_t *enc_msg = NULL;
  size_t enc_msg_len = 0;

  if (data_message_body_on_non_interactive_asprintf(&enc_msg, &enc_msg_len,
                                                    auth))
    return otrng_false;

  uint8_t mac_tag[DATA_MSG_MAC_BYTES];
  memset(mac_tag, 0, sizeof mac_tag);

  /* Auth MAC = KDF_2(auth_mac_k || t || enc_msg) */
  goldilocks_shake256_ctx_t hd;

  hash_init_with_dom(hd);
  hash_update(hd, mac_key, DATA_MSG_MAC_BYTES);
  hash_update(hd, t, t_len);
  hash_update(hd, enc_msg, enc_msg_len);

  hash_final(hd, mac_tag, DATA_MSG_MAC_BYTES);
  hash_destroy(hd);

  free(enc_msg);
  enc_msg = NULL;

  if (0 != otrl_mem_differ(mac_tag, auth->auth_mac, sizeof mac_tag)) {
    sodium_memzero(mac_tag, sizeof mac_tag);
    return otrng_false;
  }

  return otrng_true;
}

tstatic otrng_bool_t verify_non_interactive_auth_message(
    otrng_response_t *response, const dake_non_interactive_auth_message_t *auth,
    otrng_t *otr) {
  unsigned char *t = NULL;
  size_t t_len = 0;

  /* t = KDF_2(Bobs_User_Profile) || KDF_2(Alices_User_Profile) ||
   * Y || X || B || A || our_shared_prekey.public */
  if (build_non_interactive_auth_message(
          &t, &t_len, get_my_user_profile(otr), auth->profile, OUR_ECDH(otr),
          auth->X, OUR_DH(otr), auth->A, otr->profile->shared_prekey,
          otr->conversation->client->phi)) {
    return otrng_false;
  }

  /* Verif({g^I, g^R, g^i}, sigma, msg) */
  otrng_bool_t err =
      otrng_snizkpk_verify(auth->sigma, auth->profile->pub_key,     /* g^R */
                           otr->conversation->client->keypair->pub, /* g^I */
                           OUR_ECDH(otr),                           /* g^  */
                           t, t_len);

  if (auth->enc_msg) {
    m_enc_key_t enc_key;
    m_mac_key_t mac_key;

    memset(enc_key, 0, sizeof enc_key);
    memset(mac_key, 0, sizeof mac_key);

    /* auth_mac_k = KDF_2(0x01 || tmp_k) */
    uint8_t magic[1] = {0x01};
    uint8_t auth_mac_k[HASH_BYTES];
    shake_256_kdf(auth_mac_k, sizeof(auth_mac_k), magic, otr->keys->tmp_key,
                  HASH_BYTES);

    if (otrng_key_manager_retrieve_receiving_message_keys(
            enc_key, mac_key, auth->message_id, otr->keys)) {
      free(t);
      t = NULL;
      sodium_memzero(enc_key, sizeof(m_enc_key_t));
      sodium_memzero(mac_key, sizeof(m_mac_key_t));
      return otrng_false;
    }

    /* discard this mac key as it is not needed */
    sodium_memzero(mac_key, sizeof(m_mac_key_t));

    if (valid_data_message_on_non_interactive_auth(t, t_len, auth_mac_k,
                                                   auth)) {
      free(t);
      t = NULL;
      sodium_memzero(enc_key, sizeof(m_enc_key_t));
      /* here no warning should be passed */
      return otrng_false;
    }

    free(t);
    t = NULL;

    string_t *dst = &response->to_display;
    uint8_t *plain = malloc(auth->enc_msg_len);
    if (!plain) {
      sodium_memzero(enc_key, sizeof(m_enc_key_t));
      return otrng_false;
    }

    int err = crypto_stream_xor(plain, auth->enc_msg, auth->enc_msg_len,
                                auth->nonce, enc_key);
    if (err != 0) {
      otrng_error_message(dst, ERR_MSG_UNDECRYPTABLE);
      free(plain);
      plain = NULL;
      sodium_memzero(enc_key, sizeof(m_enc_key_t));
      return otrng_false;
    }

    if (strnlen((string_t)plain, auth->enc_msg_len))
      *dst = otrng_strndup((char *)plain, auth->enc_msg_len);

    free(plain);
    plain = NULL;
    sodium_memzero(enc_key, sizeof(enc_key));

    uint8_t *to_store_mac = malloc(MAC_KEY_BYTES);
    if (to_store_mac == NULL) {
      return otrng_false;
    }

    memcpy(to_store_mac, mac_key, MAC_KEY_BYTES);
    otr->keys->old_mac_keys =
        otrng_list_add(to_store_mac, otr->keys->old_mac_keys);
  } else {
    /* auth_mac_k = KDF_2(0x01 || tmp_k */
    uint8_t magic[1] = {0x01};
    uint8_t auth_mac_k[HASH_BYTES];
    shake_256_kdf(auth_mac_k, sizeof(auth_mac_k), magic, otr->keys->tmp_key,
                  HASH_BYTES);

    /* Auth MAC = KDF_2(auth_mac_k || t) */
    uint8_t auth_mac[HASH_BYTES];
    shake_256_mac(auth_mac, HASH_BYTES, auth_mac_k, HASH_BYTES, t, t_len);
    if (0 != otrl_mem_differ(auth_mac, auth->auth_mac, sizeof auth_mac)) {
      free(t);
      t = NULL;
      return otrng_false;
    }
  }

  free(t);
  t = NULL;

  return err;
}

tstatic otrng_err_t receive_non_interactive_auth_message(
    otrng_response_t *response, const uint8_t *buff, size_t buff_len,
    otrng_t *otr) {
  if (otr->state == OTRNG_STATE_FINISHED)
    return SUCCESS; /* ignore the message */

  dake_non_interactive_auth_message_t auth[1];
  auth->enc_msg = NULL;

  if (otrng_dake_non_interactive_auth_message_deserialize(auth, buff, buff_len))
    return ERROR;

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    otrng_dake_non_interactive_auth_message_destroy(auth);
    return SUCCESS;
  }

  received_instance_tag(auth->sender_instance_tag, otr);

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile) {
    otrng_dake_non_interactive_auth_message_destroy(auth);
    return ERROR;
  }

  otrng_key_manager_set_their_ecdh(auth->X, otr->keys);
  otrng_key_manager_set_their_dh(auth->A, otr->keys);
  otrng_user_profile_copy(otr->their_profile, auth->profile);

  /* tmp_k = KDF_2(K_ecdh ||
   * ECDH(x, our_shared_prekey.secret, their_ecdh) ||
   * ECDH(Ska, X) || k_dh) */
  if (generate_tmp_key_i(otr->keys->tmp_key, otr) == ERROR) {
    otrng_dake_non_interactive_auth_message_destroy(auth);
    return ERROR;
  }

  if (double_ratcheting_init(1, false, otr)) {
    otrng_dake_non_interactive_auth_message_destroy(auth);
    return ERROR;
  }

  if (verify_non_interactive_auth_message(response, auth, otr) == otrng_false) {
    free(auth->enc_msg);
    auth->enc_msg = NULL;
    otrng_dake_non_interactive_auth_message_destroy(auth);
    return ERROR;
  }

  if (auth->enc_msg) {
    free(auth->enc_msg);
    auth->enc_msg = NULL;
  }
  otrng_dake_non_interactive_auth_message_destroy(auth);

  otrng_fingerprint_t fp;
  if (!otrng_serialize_fingerprint(fp, otr->their_profile->pub_key))
    fingerprint_seen_cb_v4(fp, otr->conversation);

  return SUCCESS;
}

tstatic otrng_err_t receive_identity_message_on_state_start(
    string_t *dst, dake_identity_message_t *identity_message, otrng_t *otr) {

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile)
    return ERROR;

  otrng_key_manager_set_their_ecdh(identity_message->Y, otr->keys);
  otrng_key_manager_set_their_dh(identity_message->B, otr->keys);
  otrng_user_profile_copy(otr->their_profile, identity_message->profile);

  if (otrng_key_manager_generate_ephemeral_keys(otr->keys))
    return ERROR;

  if (reply_with_auth_r_msg(dst, otr))
    return ERROR;

  otr->state = OTRNG_STATE_WAITING_AUTH_I;
  return SUCCESS;
}

tstatic void forget_our_keys(otrng_t *otr) {
  otrng_key_manager_destroy(otr->keys);
  otrng_key_manager_init(otr->keys);
}

tstatic otrng_err_t receive_identity_message_on_waiting_auth_r(
    string_t *dst, dake_identity_message_t *msg, otrng_t *otr) {
  int cmp = gcry_mpi_cmp(OUR_DH(otr), msg->B);

  /* If our is higher, ignore. */
  if (cmp > 0) {
    // TODO: this should resend the prev identity message
    return SUCCESS;
  }

  forget_our_keys(otr);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

tstatic otrng_err_t receive_identity_message_on_waiting_auth_i(
    string_t *dst, dake_identity_message_t *msg, otrng_t *otr) {
  otrng_user_profile_free(otr->their_profile);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

tstatic otrng_err_t receive_identity_message(string_t *dst, const uint8_t *buff,
                                             size_t buflen, otrng_t *otr) {
  otrng_err_t err = ERROR;
  dake_identity_message_t m[1];

  if (otrng_dake_identity_message_deserialize(m, buff, buflen))
    return err;

  if (m->receiver_instance_tag != 0) {
    otrng_dake_identity_message_destroy(m);
    return SUCCESS;
  }

  received_instance_tag(m->sender_instance_tag, otr);

  if (otrng_valid_received_values(m->Y, m->B, m->profile)) {
    otrng_dake_identity_message_destroy(m);
    return err;
  }

  switch (otr->state) {
  case OTRNG_STATE_START:
    err = receive_identity_message_on_state_start(dst, m, otr);
    break;
  case OTRNG_STATE_WAITING_AUTH_R:
    err = receive_identity_message_on_waiting_auth_r(dst, m, otr);
    break;
  case OTRNG_STATE_WAITING_AUTH_I:
    err = receive_identity_message_on_waiting_auth_i(dst, m, otr);
    break;
  case OTRNG_STATE_NONE:
  case OTRNG_STATE_ENCRYPTED_MESSAGES:
  case OTRNG_STATE_FINISHED:
    /* Ignore the message, but it is not an error. */
    err = SUCCESS;
  }

  otrng_dake_identity_message_destroy(m);
  return err;
}

tstatic otrng_err_t serialize_and_encode_auth_i(string_t *dst,
                                                const dake_auth_i_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrng_dake_auth_i_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic otrng_err_t reply_with_auth_i_msg(string_t *dst,
                                          const user_profile_t *their,
                                          otrng_t *otr) {
  dake_auth_i_t msg[1];
  msg->sender_instance_tag = otr->our_instance_tag;
  msg->receiver_instance_tag = otr->their_instance_tag;

  unsigned char *t = NULL;
  size_t t_len = 0;

  if (build_auth_message(&t, &t_len, 1, get_my_user_profile(otr), their,
                         OUR_ECDH(otr), THEIR_ECDH(otr), OUR_DH(otr),
                         THEIR_DH(otr), otr->conversation->client->phi))
    return ERROR;

  otrng_snizkpk_authenticate(msg->sigma, otr->conversation->client->keypair,
                             their->pub_key, THEIR_ECDH(otr), t, t_len);
  free(t);
  t = NULL;

  otrng_err_t err = serialize_and_encode_auth_i(dst, msg);
  otrng_dake_auth_i_destroy(msg);

  return err;
}

tstatic otrng_bool_t valid_auth_r_message(const dake_auth_r_t *auth,
                                          otrng_t *otr) {
  uint8_t *t = NULL;
  size_t t_len = 0;

  if (otrng_valid_received_values(auth->X, auth->A, auth->profile))
    return otrng_false;

  if (build_auth_message(&t, &t_len, 0, get_my_user_profile(otr), auth->profile,
                         OUR_ECDH(otr), auth->X, OUR_DH(otr), auth->A,
                         otr->conversation->client->phi))
    return otrng_false;

  /* Verif({g^I, g^R, g^i}, sigma, msg) */
  otrng_bool_t err =
      otrng_snizkpk_verify(auth->sigma, auth->profile->pub_key,     /* g^R */
                           otr->conversation->client->keypair->pub, /* g^I */
                           OUR_ECDH(otr),                           /* g^  */
                           t, t_len);

  free(t);
  t = NULL;

  return err;
}

tstatic otrng_err_t receive_auth_r(string_t *dst, const uint8_t *buff,
                                   size_t buff_len, otrng_t *otr) {
  if (otr->state != OTRNG_STATE_WAITING_AUTH_R)
    return SUCCESS; /* ignore the message */

  dake_auth_r_t auth[1];
  if (otrng_dake_auth_r_deserialize(auth, buff, buff_len))
    return ERROR;

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    otrng_dake_auth_r_destroy(auth);
    return SUCCESS;
  }

  received_instance_tag(auth->sender_instance_tag, otr);

  if (valid_auth_r_message(auth, otr) == otrng_false) {
    otrng_dake_auth_r_destroy(auth);
    return ERROR;
  }

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile) {
    otrng_dake_auth_r_destroy(auth);
    return ERROR;
  }

  otrng_key_manager_set_their_ecdh(auth->X, otr->keys);
  otrng_key_manager_set_their_dh(auth->A, otr->keys);
  otrng_user_profile_copy(otr->their_profile, auth->profile);

  if (reply_with_auth_i_msg(dst, otr->their_profile, otr)) {
    otrng_dake_auth_r_destroy(auth);
    return ERROR;
  }

  otrng_dake_auth_r_destroy(auth);

  otrng_fingerprint_t fp;
  if (!otrng_serialize_fingerprint(fp, otr->their_profile->pub_key))
    fingerprint_seen_cb_v4(fp, otr->conversation);

  return double_ratcheting_init(0, true, otr);
}

tstatic otrng_bool_t valid_auth_i_message(const dake_auth_i_t *auth,
                                          otrng_t *otr) {
  uint8_t *t = NULL;
  size_t t_len = 0;

  if (build_auth_message(&t, &t_len, 1, otr->their_profile,
                         get_my_user_profile(otr), THEIR_ECDH(otr),
                         OUR_ECDH(otr), THEIR_DH(otr), OUR_DH(otr),
                         otr->conversation->client->phi))
    return otrng_false;

  otrng_bool_t err = otrng_snizkpk_verify(
      auth->sigma, otr->their_profile->pub_key,
      otr->conversation->client->keypair->pub, OUR_ECDH(otr), t, t_len);
  free(t);
  t = NULL;

  return err;
}

tstatic otrng_err_t receive_auth_i(const uint8_t *buff, size_t buff_len,
                                   otrng_t *otr) {
  if (otr->state != OTRNG_STATE_WAITING_AUTH_I)
    return SUCCESS; /* Ignore the message */

  dake_auth_i_t auth[1];
  if (otrng_dake_auth_i_deserialize(auth, buff, buff_len))
    return ERROR;

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    otrng_dake_auth_i_destroy(auth);
    return SUCCESS;
  }

  if (valid_auth_i_message(auth, otr) == otrng_false) {
    otrng_dake_auth_i_destroy(auth);
    return ERROR;
  }

  otrng_dake_auth_i_destroy(auth);

  otrng_fingerprint_t fp;
  if (!otrng_serialize_fingerprint(fp, otr->their_profile->pub_key))
    fingerprint_seen_cb_v4(fp, otr->conversation);

  return double_ratcheting_init(1, true, otr);
}

// TODO: this is the same as otrng_close
INTERNAL otrng_err_t otrng_expire_session(string_t *to_send, otrng_t *otr) {
  tlv_list_t *disconnected = otrng_tlv_list_one(otrng_tlv_disconnected_new());
  if (!disconnected)
    return ERROR;

  otrng_err_t err = otrng_prepare_to_send_message(
      to_send, "", &disconnected, MSGFLAGS_IGNORE_UNREADABLE, otr);

  otrng_tlv_list_free(disconnected);
  forget_our_keys(otr);
  otr->state = OTRNG_STATE_START;
  gone_insecure_cb_v4(otr->conversation);

  return err;
}

tstatic void extract_tlvs(tlv_list_t **tlvs, const uint8_t *src, size_t len) {
  if (!tlvs)
    return;

  uint8_t *tlvs_start = memchr(src, 0, len);
  if (!tlvs_start)
    return;

  size_t tlvs_len = len - (tlvs_start + 1 - src);
  *tlvs = otrng_parse_tlvs(tlvs_start + 1, tlvs_len);
}

tstatic otrng_err_t decrypt_data_msg(otrng_response_t *response,
                                     const m_enc_key_t enc_key,
                                     const data_message_t *msg) {
  string_t *dst = &response->to_display;
  tlv_list_t **tlvs = &response->tlvs;

#ifdef DEBUG
  printf("DECRYPTING\n");
  printf("enc_key = ");
  otrng_memdump(enc_key, sizeof(m_enc_key_t));
  printf("nonce = ");
  otrng_memdump(msg->nonce, DATA_MSG_NONCE_BYTES);
#endif

  uint8_t *plain = malloc(msg->enc_msg_len);
  if (!plain)
    return ERROR;

  int err = crypto_stream_xor(plain, msg->enc_msg, msg->enc_msg_len, msg->nonce,
                              enc_key);

  if (strnlen((string_t)plain, msg->enc_msg_len))
    *dst = otrng_strndup((char *)plain, msg->enc_msg_len);

  extract_tlvs(tlvs, plain, msg->enc_msg_len);

  free(plain);
  plain = NULL;

  if (err == 0) {
    return SUCCESS;
  }

  // TODO: correctly free
  otrng_tlv_list_free(*tlvs);
  return ERROR;
}

tstatic tlv_t *otrng_process_smp(otrng_smp_event_t event, smp_context_t smp,
                                 const tlv_t *tlv) {
  event = OTRNG_SMPEVENT_NONE;
  tlv_t *to_send = NULL;

  switch (tlv->type) {
  case OTRNG_TLV_SMP_MSG_1:
    event = otrng_process_smp_msg1(tlv, smp);
    break;

  case OTRNG_TLV_SMP_MSG_2:
    event = otrng_process_smp_msg2(&to_send, tlv, smp);
    break;

  case OTRNG_TLV_SMP_MSG_3:
    event = otrng_process_smp_msg3(&to_send, tlv, smp);
    break;

  case OTRNG_TLV_SMP_MSG_4:
    event = otrng_process_smp_msg4(tlv, smp);
    break;

  case OTRNG_TLV_SMP_ABORT:
    smp->state = SMPSTATE_EXPECT1;
    to_send = otrng_tlv_new(OTRNG_TLV_SMP_ABORT, 0, NULL);
    if (!to_send)
      return NULL;

    event = OTRNG_SMPEVENT_ABORT;

    break;
  case OTRNG_TLV_NONE:
  case OTRNG_TLV_PADDING:
  case OTRNG_TLV_DISCONNECTED:
  case OTRNG_TLV_SYM_KEY:
    // Ignore. They should not be passed to this function.
    break;
  }

  if (!event)
    event = OTRNG_SMPEVENT_IN_PROGRESS;

  return to_send;
}

tstatic unsigned int extract_word(unsigned char *bufp) {
  unsigned int use =
      (bufp[0] << 24) | (bufp[1] << 16) | (bufp[2] << 8) | bufp[3];
  return use;
}

tstatic tlv_t *process_tlv(const tlv_t *tlv, otrng_t *otr) {
  if (tlv->type == OTRNG_TLV_NONE || tlv->type == OTRNG_TLV_PADDING) {
    return NULL;
  }

  if (tlv->type == OTRNG_TLV_DISCONNECTED) {
    forget_our_keys(otr);
    otr->state = OTRNG_STATE_FINISHED;
    gone_insecure_cb_v4(otr->conversation);
    return NULL;
  }

  if (tlv->type == OTRNG_TLV_SYM_KEY && tlv->len >= 4) {
    if (otr->keys->extra_key > 0) {
      uint32_t use = extract_word(tlv->data);

      received_symkey_cb_v4(otr->conversation, use, tlv->data + 4, tlv->len - 4,
                            otr->keys->extra_key);
      sodium_memzero(otr->keys->extra_key, sizeof(otr->keys->extra_key));
    }
    return NULL;
  }

  tlv_t *out = otrng_process_smp(OTRNG_SMPEVENT_NONE, otr->smp, tlv);
  handle_smp_event_cb_v4(OTRNG_SMPEVENT_NONE, otr->smp->progress,
                         otr->smp->msg1 ? otr->smp->msg1->question : NULL,
                         otr->smp->msg1 ? otr->smp->msg1->q_len : 0,
                         otr->conversation);
  return out;
}

tstatic otrng_err_t receive_tlvs(tlv_list_t **to_send,
                                 otrng_response_t *response, otrng_t *otr) {
  const tlv_list_t *current = response->tlvs;
  while (current) {
    tlv_t *ret = process_tlv(current->data, otr);
    current = current->next;

    if (ret) {
      *to_send = otrng_append_tlv(*to_send, ret);
      if (!*to_send)
        return ERROR;
    }
  }

  return SUCCESS;
}

tstatic otrng_err_t get_receiving_msg_keys(m_enc_key_t enc_key,
                                           m_mac_key_t mac_key,
                                           const data_message_t *msg,
                                           otrng_t *otr) {
  if (otrng_key_manager_ensure_on_ratchet(otr->keys) == ERROR)
    return ERROR;

  if (otrng_key_manager_retrieve_receiving_message_keys(
          enc_key, mac_key, msg->message_id, otr->keys)) {
    sodium_memzero(enc_key, sizeof(m_enc_key_t));
    sodium_memzero(mac_key, sizeof(m_mac_key_t));
    return ERROR;
  }

  return SUCCESS;
}

tstatic otrng_err_t otrng_receive_data_message(otrng_response_t *response,
                                               const uint8_t *buff,
                                               size_t buflen, otrng_t *otr) {
  data_message_t *msg = otrng_data_message_new();
  m_enc_key_t enc_key;
  m_mac_key_t mac_key;

  memset(enc_key, 0, sizeof enc_key);
  memset(mac_key, 0, sizeof mac_key);

  // TODO: check this case with Nik on v3
  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    otrng_error_message(&response->to_send, ERR_MSG_NOT_PRIVATE);
    free(msg);
    msg = NULL;
    return ERROR;
  }

  size_t read = 0;
  if (otrng_data_message_deserialize(msg, buff, buflen, &read)) {
    otrng_data_message_free(msg);
    return ERROR;
  }

  otrng_key_manager_set_their_keys(msg->ecdh, msg->dh, otr->keys);

  do {
    if (msg->receiver_instance_tag != otr->our_instance_tag) {
      response->to_display = NULL;
      otrng_data_message_free(msg);

      return SUCCESS;
    }

    if (get_receiving_msg_keys(enc_key, mac_key, msg, otr))
      continue;

    if (otrng_valid_data_message(mac_key, msg)) {
      sodium_memzero(enc_key, sizeof(enc_key));
      sodium_memzero(mac_key, sizeof(mac_key));
      response->to_display = NULL;
      otrng_data_message_free(msg);

      response->warning = OTRNG_WARN_RECEIVED_NOT_VALID;
      return MSG_NOT_VALID;
    }

    if (decrypt_data_msg(response, enc_key, msg)) {
      if (msg->flags != MSGFLAGS_IGNORE_UNREADABLE) {
        otrng_error_message(&response->to_send, ERR_MSG_UNDECRYPTABLE);
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        response->to_display = NULL;
        otrng_data_message_free(msg);

        return ERROR;
      } else if (msg->flags == MSGFLAGS_IGNORE_UNREADABLE) {
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        response->to_display = NULL;
        otrng_data_message_free(msg);

        return ERROR;
      }
    }

    sodium_memzero(enc_key, sizeof(enc_key));
    sodium_memzero(mac_key, sizeof(mac_key));

    tlv_list_t *reply_tlvs = NULL;

    // TODO: Securely delete receiving chain keys older than message_id-1.
    if (receive_tlvs(&reply_tlvs, response, otr)) {
      otrng_tlv_list_free(reply_tlvs);
      continue;
    }

    otrng_key_manager_prepare_to_ratchet(otr->keys);

    if (reply_tlvs) {
      if (otrng_prepare_to_send_message(&response->to_send, "", &reply_tlvs,
                                        MSGFLAGS_IGNORE_UNREADABLE, otr)) {
        otrng_tlv_list_free(reply_tlvs);
        continue;
      }
      otrng_tlv_list_free(reply_tlvs);
    }

    uint8_t *to_store_mac = malloc(MAC_KEY_BYTES);
    if (to_store_mac == NULL) {
      response->to_display = NULL;
      otrng_data_message_free(msg);
      return ERROR;
    }

    memcpy(to_store_mac, mac_key, MAC_KEY_BYTES);
    otr->keys->old_mac_keys =
        otrng_list_add(to_store_mac, otr->keys->old_mac_keys);

    otrng_data_message_free(msg);
    return SUCCESS;
  } while (0);

  otrng_data_message_free(msg);

  return ERROR;
}

tstatic otrng_err_t extract_header(otrng_header_t *dst, const uint8_t *buffer,
                                   const size_t bufflen) {
  if (bufflen == 0) {
    return ERROR;
  }

  size_t read = 0;
  uint16_t version = 0;
  uint8_t type = 0;
  if (otrng_deserialize_uint16(&version, buffer, bufflen, &read))
    return ERROR;

  buffer += read;

  if (otrng_deserialize_uint8(&type, buffer, bufflen - read, &read))
    return ERROR;

  dst->version = OTRNG_ALLOW_NONE;
  if (version == 0x04) {
    dst->version = OTRNG_ALLOW_V4;
  } else if (version == 0x03) {
    dst->version = OTRNG_ALLOW_V3;
  }
  dst->type = type;

  return SUCCESS;
}

tstatic otrng_err_t receive_decoded_message(otrng_response_t *response,
                                            const uint8_t *decoded,
                                            size_t dec_len, otrng_t *otr) {
  otrng_header_t header;
  if (extract_header(&header, decoded, dec_len))
    return ERROR;

  if (!allow_version(otr, header.version))
    return ERROR;

  // TODO: Why the version in the header is a ALLOWED VERSION?
  // This is the message version, not the version the protocol allows
  if (header.version != OTRNG_ALLOW_V4)
    return ERROR;

  // TODO: how to prevent version rollback?
  maybe_create_keys(otr->conversation);

  response->to_send = NULL;
  otrng_err_t err;

  switch (header.type) {
  case IDENTITY_MSG_TYPE:
    otr->running_version = OTRNG_VERSION_4;
    return receive_identity_message(&response->to_send, decoded, dec_len, otr);
  case AUTH_R_MSG_TYPE:
    err = receive_auth_r(&response->to_send, decoded, dec_len, otr);
    if (otr->state == OTRNG_STATE_ENCRYPTED_MESSAGES) {
      otrng_dh_priv_key_destroy(otr->keys->our_dh);
      otrng_ec_scalar_destroy(otr->keys->our_ecdh->priv);
    }
    return err;
  case AUTH_I_MSG_TYPE:
    return receive_auth_i(decoded, dec_len, otr);
  case PRE_KEY_MSG_TYPE:
    return receive_prekey_message(&response->to_send, decoded, dec_len, otr);
  case NON_INT_AUTH_MSG_TYPE:
    return receive_non_interactive_auth_message(response, decoded, dec_len,
                                                otr);
  case DATA_MSG_TYPE:
    return otrng_receive_data_message(response, decoded, dec_len, otr);
  default:
    /* error. bad message type */
    return ERROR;
  }

  return ERROR;
}

tstatic otrng_err_t receive_encoded_message(otrng_response_t *response,
                                            const string_t message,
                                            otrng_t *otr) {
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  if (otrl_base64_otr_decode(message, &decoded, &dec_len))
    return ERROR;

  otrng_err_t err = receive_decoded_message(response, decoded, dec_len, otr);
  free(decoded);

  return err;
}

// TODO: only display the human readable part
tstatic otrng_err_t receive_error_message(otrng_response_t *response,
                                          const string_t message,
                                          otrng_t *otr) {
  if (strcmp(&message[18], "2") || strcmp(&message[18], "1")) {
    response->to_display = otrng_strndup(message, strlen(message));
    return SUCCESS;
  }

  return ERROR;
}

tstatic otrng_in_message_type_t get_message_type(const string_t message) {
  if (message_contains_tag(message) == otrng_false) {
    return IN_MSG_TAGGED_PLAINTEXT;
  } else if (message_is_query(message)) {
    return IN_MSG_QUERY_STRING;
  } else if (message_is_otr_error(message)) {
    return IN_MSG_OTR_ERROR;
  } else if (message_is_otr_encoded(message)) {
    return IN_MSG_OTR_ENCODED;
  }

  return IN_MSG_PLAINTEXT;
}

tstatic otrng_err_t receive_message_v4_only(otrng_response_t *response,
                                            const string_t message,
                                            otrng_t *otr) {
  switch (get_message_type(message)) {
  case IN_MSG_NONE:
    return ERROR;

  case IN_MSG_PLAINTEXT:
    receive_plaintext(response, message, otr);
    return SUCCESS;

  case IN_MSG_TAGGED_PLAINTEXT:
    return receive_tagged_plaintext(response, message, otr);

  case IN_MSG_QUERY_STRING:
    return receive_query_message(response, message, otr);

  case IN_MSG_OTR_ENCODED:
    return receive_encoded_message(response, message, otr);

  case IN_MSG_OTR_ERROR:
    return receive_error_message(response, message, otr);
  }

  return SUCCESS;
}

/* Receive a possibly OTR message. */
INTERNAL otrng_err_t otrng_receive_message(otrng_response_t *response,
                                           const string_t message,
                                           otrng_t *otr) {
  // TODO: why it is always mandatory to have a response?
  if (!message || !response)
    return ERROR;

  response->to_display = otrng_strndup(NULL, 0);

  /* A DH-Commit sets our running version to 3 */
  if (otr->running_version == OTRNG_VERSION_NONE &&
      allow_version(otr, OTRNG_ALLOW_V3) && strstr(message, "?OTR:AAMC"))
    otr->running_version = OTRNG_VERSION_3;

  switch (otr->running_version) {
  case OTRNG_VERSION_3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, message, otr->v3_conn);
  case OTRNG_VERSION_4:
  case OTRNG_VERSION_NONE:
    return receive_message_v4_only(response, message, otr);
  }

  return SUCCESS;
}

tstatic otrng_err_t serialize_and_encode_data_msg(
    string_t *dst, const m_mac_key_t mac_key, uint8_t *to_reveal_mac_keys,
    size_t to_reveal_mac_keys_len, const data_message_t *data_msg) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if (otrng_data_message_body_asprintf(&body, &bodylen, data_msg))
    return ERROR;

  size_t serlen = bodylen + MAC_KEY_BYTES + to_reveal_mac_keys_len;
  uint8_t *ser = malloc(serlen);
  if (!ser) {
    free(body);
    body = NULL;
    return ERROR;
  }

  memcpy(ser, body, bodylen);
  free(body);
  body = NULL;

  otrng_err_t err = otrng_data_message_authenticator(
      ser + bodylen, MAC_KEY_BYTES, mac_key, ser, bodylen);
  if (err == ERROR)
    return ERROR;

  otrng_serialize_bytes_array(ser + bodylen + DATA_MSG_MAC_BYTES,
                              to_reveal_mac_keys, to_reveal_mac_keys_len);

  *dst = otrl_base64_otr_encode(ser, serlen);
  free(ser);
  ser = NULL;

  return SUCCESS;
}

tstatic otrng_err_t send_data_message(string_t *to_send, const uint8_t *message,
                                      size_t message_len, otrng_t *otr,
                                      int heartbeat, unsigned char flags) {
  data_message_t *data_msg = NULL;

  size_t serlen = otrng_list_len(otr->keys->old_mac_keys) * MAC_KEY_BYTES;

  uint8_t *ser_mac_keys =
      otrng_key_manager_old_mac_keys_serialize(otr->keys->old_mac_keys);
  otr->keys->old_mac_keys = NULL;

  if (otrng_key_manager_prepare_next_chain_key(otr->keys)) {
    free(ser_mac_keys);
    ser_mac_keys = NULL;
    return ERROR;
  }

  m_enc_key_t enc_key;
  m_mac_key_t mac_key;
  memset(enc_key, 0, sizeof enc_key);
  memset(mac_key, 0, sizeof mac_key);

  if (otrng_key_manager_retrieve_sending_message_keys(enc_key, mac_key,
                                                      otr->keys)) {
    free(ser_mac_keys);
    ser_mac_keys = NULL;
    return ERROR;
  }

  data_msg = generate_data_msg(otr);
  if (!data_msg) {
    sodium_memzero(enc_key, sizeof(m_enc_key_t));
    sodium_memzero(mac_key, sizeof(m_mac_key_t));
    free(ser_mac_keys);
    ser_mac_keys = NULL;
    return ERROR;
  }

  data_msg->flags = flags;

  if (heartbeat) {
    data_msg->flags = MSGFLAGS_IGNORE_UNREADABLE;
  }

  data_msg->sender_instance_tag = otr->our_instance_tag;
  data_msg->receiver_instance_tag = otr->their_instance_tag;

  otrng_err_t err = ERROR;

  if (encrypt_data_message(data_msg, message, message_len, enc_key) ==
          SUCCESS &&
      serialize_and_encode_data_msg(to_send, mac_key, ser_mac_keys, serlen,
                                    data_msg) == SUCCESS) {

    // TODO: Change the spec to say this should be incremented after the message
    // is sent.
    otr->keys->j++;
    HEARTBEAT(otr)->last_msg_sent = time(0);
    err = SUCCESS;
  }

  sodium_memzero(enc_key, sizeof(m_enc_key_t));
  sodium_memzero(mac_key, sizeof(m_mac_key_t));
  free(ser_mac_keys);
  ser_mac_keys = NULL;
  otrng_data_message_free(data_msg);

  return err;
}

tstatic otrng_err_t serialize_tlvs(uint8_t **dst, size_t *dstlen,
                                   const tlv_list_t *tlvs) {
  const tlv_list_t *current = tlvs;
  uint8_t *cursor = NULL;

  *dst = NULL;
  *dstlen = 0;

  if (!tlvs)
    return SUCCESS;

  for (*dstlen = 0; current; current = current->next)
    *dstlen += current->data->len + 4;

  *dst = malloc(*dstlen);
  if (!*dst)
    return ERROR;

  cursor = *dst;
  for (current = tlvs; current; current = current->next) {
    cursor += otrng_serialize_uint16(cursor, current->data->type);
    cursor += otrng_serialize_uint16(cursor, current->data->len);
    cursor += otrng_serialize_bytes_array(cursor, current->data->data,
                                          current->data->len);
  }

  return SUCCESS;
}

tstatic otrng_err_t append_tlvs(uint8_t **dst, size_t *dstlen,
                                const string_t message,
                                const tlv_list_t *tlvs) {
  uint8_t *ser = NULL;
  size_t len = 0;

  if (serialize_tlvs(&ser, &len, tlvs))
    return ERROR;

  *dstlen = strlen(message) + 1 + len;
  *dst = malloc(*dstlen);
  if (!*dst) {
    free(ser);
    ser = NULL;
    return ERROR;
  }

  memcpy(stpcpy((char *)*dst, message) + 1, ser, len);

  free(ser);
  ser = NULL;
  return SUCCESS;
}

tstatic otrng_err_t otrng_prepare_to_send_data_message(string_t *to_send,
                                                       const string_t message,
                                                       const tlv_list_t *tlvs,
                                                       otrng_t *otr,
                                                       unsigned char flags) {
  uint8_t *msg = NULL;
  size_t msg_len = 0;

  if (otr->state == OTRNG_STATE_FINISHED)
    return ERROR; // Should restart

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return STATE_NOT_ENCRYPTED; // TODO: queue message
  }

  if (append_tlvs(&msg, &msg_len, message, tlvs))
    return ERROR;

  // TODO: due to the addition of the flag to the tlvs, this will
  // make the extra sym key, the disconneted and smp, a heartbeat
  // msg as it is right now
  int is_heartbeat =
      strlen(message) == 0 && otr->smp->state == SMPSTATE_EXPECT1 ? 1 : 0;

  otrng_err_t err =
      send_data_message(to_send, msg, msg_len, otr, is_heartbeat, flags);
  free(msg);
  msg = NULL;

  return err;
}

tstatic size_t tlv_serialized_length(tlv_t *tlv) {
  size_t result = 0;

  result += 2; // [type] length
  result += 2; // [len] length
  result += tlv->len;

  return result;
}

tstatic size_t tlv_list_serialized_length(tlv_list_t *tlvs) {
  size_t result = 0;

  for (tlv_list_t *current = tlvs; current; current = current->next)
    result += tlv_serialized_length(current->data);

  return result;
}

/**
 * @todo Move this documentation to header file later
 *
 * @param [tlvs] it is an ERROR to send in null as this parameter.
 *    it can _point_ to NULL though.
 **/
INTERNAL otrng_err_t otrng_prepare_to_send_message(string_t *to_send,
                                                   const string_t message,
                                                   tlv_list_t **tlvs,
                                                   uint8_t flags,
                                                   otrng_t *otr) {
  if (!otr)
    return ERROR;

  if (otr->conversation->client->pad) {
    *tlvs = otrng_append_padding_tlv(
        *tlvs, strlen(message) + tlv_list_serialized_length(*tlvs));
    if (!*tlvs)
      return ERROR;
  }

  const tlv_list_t *const_tlvs = NULL;
  if (tlvs)
    const_tlvs = *tlvs;

  switch (otr->running_version) {
  case OTRNG_VERSION_3:
    return otrng_v3_send_message(to_send, message, const_tlvs, otr->v3_conn);
  case OTRNG_VERSION_4:
    return otrng_prepare_to_send_data_message(to_send, message, const_tlvs, otr,
                                              flags);
  case OTRNG_VERSION_NONE:
    return ERROR;
  }

  return SUCCESS;
}

tstatic otrng_err_t otrng_close_v4(string_t *to_send, otrng_t *otr) {
  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES)
    return SUCCESS;

  tlv_list_t *disconnected = otrng_tlv_list_one(otrng_tlv_disconnected_new());
  if (!disconnected)
    return ERROR;

  otrng_err_t err = otrng_prepare_to_send_message(
      to_send, "", &disconnected, MSGFLAGS_IGNORE_UNREADABLE, otr);

  otrng_tlv_list_free(disconnected);
  forget_our_keys(otr);
  otr->state = OTRNG_STATE_START;
  gone_insecure_cb_v4(otr->conversation);

  return err;
}

INTERNAL otrng_err_t otrng_close(string_t *to_send, otrng_t *otr) {
  if (!otr)
    return ERROR;

  switch (otr->running_version) {
  case OTRNG_VERSION_3:
    otrng_v3_close(to_send, otr->v3_conn);  // TODO: This should return an error
                                            // but errors are reported on a
                                            // callback
    gone_insecure_cb_v4(otr->conversation); // TODO: Only if success
    return SUCCESS;
  case OTRNG_VERSION_4:
    return otrng_close_v4(to_send, otr);
  case OTRNG_VERSION_NONE:
    return ERROR;
  }

  return ERROR;
}

tstatic otrng_err_t otrng_send_symkey_message_v4(
    string_t *to_send, unsigned int use, const unsigned char *usedata,
    size_t usedatalen, otrng_t *otr, unsigned char *extra_key) {
  if (usedatalen > 0 && !usedata)
    return ERROR;

  if (otr->state == OTRNG_STATE_ENCRYPTED_MESSAGES) {
    unsigned char *tlv_data = malloc(usedatalen + 4);

    tlv_data[0] = (use >> 24) & 0xff;
    tlv_data[1] = (use >> 16) & 0xff;
    tlv_data[2] = (use >> 8) & 0xff;
    tlv_data[3] = (use)&0xff;
    if (usedatalen > 0)
      memmove(tlv_data + 4, usedata, usedatalen);

    memmove(extra_key, otr->keys->extra_key, HASH_BYTES);

    tlv_list_t *tlvs = otrng_tlv_list_one(
        otrng_tlv_new(OTRNG_TLV_SYM_KEY, usedatalen + 4, tlv_data));
    free(tlv_data);
    if (!tlvs)
      return ERROR;

    // TODO: in v3 the extra_key is passed as a param to this
    // do the same?
    if (otrng_prepare_to_send_message(to_send, "", &tlvs,
                                      MSGFLAGS_IGNORE_UNREADABLE, otr)) {
      otrng_tlv_list_free(tlvs);
      return ERROR;
    }
    otrng_tlv_list_free(tlvs);
    return SUCCESS;
  }
  return ERROR;
}

API otrng_err_t otrng_send_symkey_message(string_t *to_send, unsigned int use,
                                          const unsigned char *usedata,
                                          size_t usedatalen, uint8_t *extra_key,
                                          otrng_t *otr) {
  if (!otr)
    return ERROR;

  switch (otr->running_version) {
  case OTRNG_VERSION_3:
    otrng_v3_send_symkey_message(
        to_send, otr->v3_conn, use, usedata, usedatalen,
        extra_key); // TODO: This should return an error
                    // but errors are reported on a
                    // callback
    return SUCCESS;
  case OTRNG_VERSION_4:
    return otrng_send_symkey_message_v4(to_send, use, usedata, usedatalen, otr,
                                        extra_key);
  case OTRNG_VERSION_NONE:
    return ERROR;
  }

  return ERROR;
}

tstatic tlv_t *otrng_smp_initiate(const user_profile_t *initiator,
                                  const user_profile_t *responder,
                                  const uint8_t *question, const size_t q_len,
                                  const uint8_t *secret, const size_t secretlen,
                                  uint8_t *ssid, smp_context_t smp,
                                  otrng_conversation_state_t *conversation) {

  smp_msg_1_t msg[1];
  uint8_t *to_send = NULL;
  size_t len = 0;

  otrng_fingerprint_t our_fp, their_fp;
  otrng_serialize_fingerprint(our_fp, initiator->pub_key);
  otrng_serialize_fingerprint(their_fp, responder->pub_key);
  otrng_generate_smp_secret(&smp->secret, our_fp, their_fp, ssid, secret,
                            secretlen);

  do {
    if (otrng_generate_smp_msg_1(msg, smp))
      continue;

    msg->q_len = q_len;
    msg->question = otrng_memdup(question, q_len);

    if (otrng_smp_msg_1_asprintf(&to_send, &len, msg))
      continue;

    smp->state = SMPSTATE_EXPECT2;
    smp->progress = 25;
    handle_smp_event_cb_v4(OTRNG_SMPEVENT_IN_PROGRESS, smp->progress, question,
                           q_len, conversation);

    tlv_t *tlv = otrng_tlv_new(OTRNG_TLV_SMP_MSG_1, len, to_send);
    if (!tlv) {
      otrng_smp_msg_1_destroy(msg);
      free(to_send);
      return NULL;
    }

    otrng_smp_msg_1_destroy(msg);
    free(to_send);
    to_send = NULL;
    return tlv;
  } while (0);

  otrng_smp_msg_1_destroy(msg);
  handle_smp_event_cb_v4(OTRNG_SMPEVENT_ERROR, smp->progress,
                         smp->msg1->question, smp->msg1->q_len, conversation);

  return NULL;
}

INTERNAL otrng_err_t otrng_smp_start(string_t *to_send, const uint8_t *question,
                                     const size_t q_len, const uint8_t *secret,
                                     const size_t secretlen, otrng_t *otr) {
  if (!otr)
    return ERROR;

  switch (otr->running_version) {
  case OTRNG_VERSION_3:
    // FIXME: missing fragmentation
    return otrng_v3_smp_start(to_send, question, q_len, secret, secretlen,
                              otr->v3_conn);
  case OTRNG_VERSION_4:
    if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES)
      return ERROR;

    tlv_list_t *tlvs = otrng_tlv_list_one(otrng_smp_initiate(
        get_my_user_profile(otr), otr->their_profile, question, q_len, secret,
        secretlen, otr->keys->ssid, otr->smp, otr->conversation));
    if (!tlvs)
      return ERROR;

    if (otrng_prepare_to_send_message(to_send, "", &tlvs,
                                      MSGFLAGS_IGNORE_UNREADABLE, otr)) {
      otrng_tlv_list_free(tlvs);
      return ERROR;
    }
    otrng_tlv_list_free(tlvs);
    return SUCCESS;
  case OTRNG_VERSION_NONE:
    return ERROR;
  }

  return ERROR;
}

tstatic tlv_t *otrng_smp_provide_secret(otrng_smp_event_t *event,
                                        smp_context_t smp,
                                        const user_profile_t *our_profile,
                                        const user_profile_t *their_profile,
                                        uint8_t *ssid, const uint8_t *secret,
                                        const size_t secretlen) {
  // TODO: If state is not CONTINUE_SMP then error.
  tlv_t *smp_reply = NULL;

  otrng_fingerprint_t our_fp, their_fp;
  otrng_serialize_fingerprint(our_fp, our_profile->pub_key);
  otrng_serialize_fingerprint(their_fp, their_profile->pub_key);
  otrng_generate_smp_secret(&smp->secret, their_fp, our_fp, ssid, secret,
                            secretlen);

  *event = otrng_reply_with_smp_msg_2(&smp_reply, smp);

  return smp_reply;
}

tstatic otrng_err_t smp_continue_v4(string_t *to_send, const uint8_t *secret,
                                    const size_t secretlen, otrng_t *otr) {
  if (!otr)
    return ERROR;

  otrng_smp_event_t event = OTRNG_SMPEVENT_NONE;
  tlv_list_t *tlvs = otrng_tlv_list_one(otrng_smp_provide_secret(
      &event, otr->smp, get_my_user_profile(otr), otr->their_profile,
      otr->keys->ssid, secret, secretlen));
  if (!tlvs)
    return ERROR;

  if (!event)
    event = OTRNG_SMPEVENT_IN_PROGRESS;

  handle_smp_event_cb_v4(event, otr->smp->progress, otr->smp->msg1->question,
                         otr->smp->msg1->q_len, otr->conversation);

  if (otrng_prepare_to_send_message(
          to_send, "", &tlvs, MSGFLAGS_IGNORE_UNREADABLE, otr) == SUCCESS) {
    otrng_tlv_list_free(tlvs);
    return SUCCESS;
  }

  otrng_tlv_list_free(tlvs);
  return ERROR;
}

INTERNAL otrng_err_t otrng_smp_continue(string_t *to_send,
                                        const uint8_t *secret,
                                        const size_t secretlen, otrng_t *otr) {
  switch (otr->running_version) {
  case OTRNG_VERSION_3:
    // FIXME: missing fragmentation
    return otrng_v3_smp_continue(to_send, secret, secretlen, otr->v3_conn);
  case OTRNG_VERSION_4:
    return smp_continue_v4(to_send, secret, secretlen, otr);
  case OTRNG_VERSION_NONE:
    return ERROR;
  }

  return ERROR; // TODO: IMPLEMENT
}

tstatic otrng_err_t otrng_smp_abort_v4(string_t *to_send, otrng_t *otr) {
  tlv_list_t *tlvs =
      otrng_tlv_list_one(otrng_tlv_new(OTRL_TLV_SMP_ABORT, 0, NULL));

  if (!tlvs)
    return ERROR;

  otr->smp->state = SMPSTATE_EXPECT1;
  if (otrng_prepare_to_send_message(to_send, "", &tlvs,
                                    MSGFLAGS_IGNORE_UNREADABLE, otr)) {
    otrng_tlv_list_free(tlvs);
    return ERROR;
  }

  otrng_tlv_list_free(tlvs);

  return SUCCESS;
}

API otrng_err_t otrng_smp_abort(string_t *to_send, otrng_t *otr) {
  switch (otr->running_version) {
  case OTRNG_VERSION_3:
    return otrng_v3_smp_abort(otr->v3_conn);
  case OTRNG_VERSION_4:
    return otrng_smp_abort_v4(to_send, otr);
  case OTRNG_VERSION_NONE:
    return ERROR;
  }
  return ERROR;
}

API otrng_err_t otrng_heartbeat_checker(string_t *to_send, otrng_t *otr) {
  if (difftime(time(0), HEARTBEAT(otr)->last_msg_sent) >=
      HEARTBEAT(otr)->time) {
    const string_t heartbeat_msg = "";
    return otrng_prepare_to_send_message(to_send, heartbeat_msg, NULL, 0, otr);
  }
  return SUCCESS;
}

static int otrl_initialized = 0;
API void otrng_v3_init(void) {
  if (otrl_initialized)
    return;

  if (otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB))
    exit(1);

  otrl_initialized = 1;
}
