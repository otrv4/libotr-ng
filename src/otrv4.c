#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libotr/b64.h>
#include <libotr/mem.h>

#define OTRV4_OTRV4_PRIVATE

#include "gcrypt.h"
#include "constants.h"
#include "dake.h"
#include "data_message.h"
#include "deserialize.h"
#include "otrv4.h"
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

tstatic void create_privkey_cb_v4(const otr4_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  // TODO: Change to receive conv->client
  conv->client->callbacks->create_privkey(conv->client->client_id);
}

tstatic void gone_secure_cb_v4(const otr4_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  conv->client->callbacks->gone_secure(conv);
}

tstatic void gone_insecure_cb_v4(const otr4_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  conv->client->callbacks->gone_insecure(conv);
}

tstatic void fingerprint_seen_cb_v4(const otrv4_fingerprint_t fp,
                                const otr4_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  conv->client->callbacks->fingerprint_seen(fp, conv);
}

tstatic void handle_smp_event_cb_v4(const otr4_smp_event_t event,
                                const uint8_t progress_percent,
                                const char *question,
                                const otr4_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  switch (event) {
  case OTRV4_SMPEVENT_ASK_FOR_SECRET:
    conv->client->callbacks->smp_ask_for_secret(conv);
    break;
  case OTRV4_SMPEVENT_ASK_FOR_ANSWER:
    conv->client->callbacks->smp_ask_for_answer(question, conv);
    break;
  case OTRV4_SMPEVENT_CHEATED:
  case OTRV4_SMPEVENT_IN_PROGRESS:
  case OTRV4_SMPEVENT_SUCCESS:
  case OTRV4_SMPEVENT_FAILURE:
  case OTRV4_SMPEVENT_ABORT:
  case OTRV4_SMPEVENT_ERROR:
    conv->client->callbacks->smp_update(event, progress_percent, conv);
    break;
  default:
    // OTRV4_SMPEVENT_NONE. Should not be used.
    break;
  }
}

tstatic void received_symkey_cb_v4(const otr4_conversation_state_t *conv,
                               unsigned int use, const unsigned char *usedata,
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

tstatic void maybe_create_keys(const otr4_conversation_state_t *conv) {
  if (!conv->client->keypair)
    create_privkey_cb_v4(conv);
}

tstatic int allow_version(const otrv4_t *otr, otrv4_supported_version version) {
  return (otr->supported_versions & version);
}

/* dst must be at least 3 bytes long. */
tstatic void allowed_versions(string_t dst, const otrv4_t *otr) {
  if (allow_version(otr, OTRV4_ALLOW_V4))
    *dst++ = '4';

  if (allow_version(otr, OTRV4_ALLOW_V3))
    *dst++ = '3';

  *dst = 0;
}

tstatic const user_profile_t *get_my_user_profile(otrv4_t *otr) {
  if (otr->profile)
    return otr->profile;

  char versions[3] = {0};
  allowed_versions(versions, otr);
  maybe_create_keys(otr->conversation);

  // This is a temporary measure for the pidgin plugin to work
  // This will be removed later
  uint8_t sym_key[ED448_PRIVATE_BYTES] = {0x01};
  otrv4_client_state_add_shared_prekey_v4(otr->conversation->client, sym_key);

  otr->profile =
      user_profile_build(versions, otr->conversation->client->keypair,
                         otr->conversation->client->shared_prekey_pair);
  return otr->profile;
}

INTERNAL otrv4_t *otrv4_new(otr4_client_state_t *state, otrv4_policy_t policy) {
  otrv4_t *otr = malloc(sizeof(otrv4_t));
  if (!otr)
    return NULL;

  // TODO: Move to constructor
  otr->conversation = malloc(sizeof(otr4_conversation_state_t));
  otr->conversation->client = state;
  otr->conversation->peer = NULL;

  otr->state = OTRV4_STATE_START;
  otr->running_version = OTRV4_VERSION_NONE;
  otr->supported_versions = policy.allows;

  otr->their_instance_tag = 0;
  otr->our_instance_tag = otrv4_client_state_get_instance_tag(state);
  otr->profile = NULL;
  otr->their_profile = NULL;

  otr->keys = malloc(sizeof(key_manager_t));
  if (!otr->keys) {
    free(otr);
    otr = NULL;
    return NULL;
  }

  key_manager_init(otr->keys);
  smp_context_init(otr->smp);

  otr->frag_ctx = fragment_context_new();
  otr->otr3_conn = NULL;

  return otr;
}

tstatic void otrv4_destroy(/*@only@ */ otrv4_t *otr) {
  if (otr->conversation) {
    free(otr->conversation->peer);
    otr->conversation->peer = NULL;
    free(otr->conversation);
    otr->conversation = NULL;
  }

  key_manager_destroy(otr->keys);
  free(otr->keys);
  otr->keys = NULL;

  user_profile_free(otr->profile);
  otr->profile = NULL;

  user_profile_free(otr->their_profile);
  otr->their_profile = NULL;

  smp_destroy(otr->smp);

  fragment_context_free(otr->frag_ctx);

  otr3_conn_free(otr->otr3_conn);
  otr->otr3_conn = NULL;
}

INTERNAL void otrv4_free(/*@only@ */ otrv4_t *otr) {
  if (otr == NULL) {
    return;
  }

  otrv4_destroy(otr);
  free(otr);
  otr = NULL;
}

INTERNAL otrv4_err_t otrv4_build_query_message(string_t *dst, const string_t message,
                                      const otrv4_t *otr) {
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

API otrv4_err_t otrv4_build_whitespace_tag(string_t *whitespace_tag,
                                       const string_t message,
                                       const otrv4_t *otr) {
  size_t m_size = WHITESPACE_TAG_BASE_BYTES + strlen(message) + 1;
  int allows_v4 = allow_version(otr, OTRV4_ALLOW_V4);
  int allows_v3 = allow_version(otr, OTRV4_ALLOW_V3);
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

tstatic otrv4_bool_t message_contains_tag(const string_t message) {
  return strstr(message, tag_base) != NULL;
}

tstatic void set_to_display(otrv4_response_t *response, const string_t message) {
  size_t msg_len = strlen(message);
  response->to_display = otrv4_strndup(message, msg_len);
}

tstatic otrv4_err_t message_to_display_without_tag(otrv4_response_t *response,
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

  response->to_display = otrv4_strndup(buff, chars);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic void set_running_version_from_tag(otrv4_t *otr, const string_t message) {
  if (allow_version(otr, OTRV4_ALLOW_V4) && strstr(message, tag_version_v4)) {
    otr->running_version = OTRV4_VERSION_4;
    return;
  }

  if (allow_version(otr, OTRV4_ALLOW_V3) && strstr(message, tag_version_v3)) {
    otr->running_version = OTRV4_VERSION_3;
    return;
  }
}

tstatic bool message_is_query(const string_t message) {
  return strstr(message, query_header) != NULL;
}

tstatic void set_running_version_from_query_msg(otrv4_t *otr,
                                               const string_t message) {
  if (allow_version(otr, OTRV4_ALLOW_V4) && strstr(message, "4")) {
    otr->running_version = OTRV4_VERSION_4;
    return;
  }

  if (allow_version(otr, OTRV4_ALLOW_V3) && strstr(message, "3")) {
    otr->running_version = OTRV4_VERSION_3;
    return;
  }
}

tstatic bool message_is_otr_encoded(const string_t message) {
  return strstr(message, otr_header) != NULL;
}

tstatic bool message_is_otr_error(const string_t message) {
  return strstr(message, otr_error_header) != NULL;
}

INTERNAL otrv4_response_t *otrv4_response_new(void) {
  otrv4_response_t *response = malloc(sizeof(otrv4_response_t));
  if (!response)
    return NULL;

  response->to_display = NULL;
  response->to_send = NULL;
  response->warning = OTRV4_WARN_NONE;
  response->tlvs = NULL;

  return response;
}

INTERNAL void otrv4_response_free(otrv4_response_t *response) {
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

  response->warning = OTRV4_WARN_NONE;

  otrv4_tlv_free(response->tlvs);
  response->tlvs = NULL;

  free(response);
  response = NULL;
}

// TODO: Is not receiving a plaintext a problem?
tstatic void receive_plaintext(otrv4_response_t *response,
                              const string_t message, const otrv4_t *otr) {
  set_to_display(response, message);

  if (otr->state != OTRV4_STATE_START)
    response->warning = OTRV4_WARN_RECEIVED_UNENCRYPTED;
}

tstatic otrv4_err_t
serialize_and_encode_prekey_message(string_t *dst,
                                    const dake_prekey_message_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrv4_dake_prekey_message_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic otrv4_err_t otrv4_build_prekey_message(otrv4_server_t *server,
                                              otrv4_t *otr) {
  dake_prekey_message_t *m = NULL;
  otrv4_err_t err = ERROR;

  m = otrv4_dake_prekey_message_new(get_my_user_profile(otr));
  if (!m)
    return err;

  m->sender_instance_tag = otr->our_instance_tag;
  m->receiver_instance_tag = otr->their_instance_tag;

  ec_point_copy(m->Y, OUR_ECDH(otr));
  m->B = dh_mpi_copy(OUR_DH(otr));

  if (serialize_and_encode_prekey_message(&server->prekey_message, m)) {
    otrv4_dake_prekey_message_free(m);
    return err;
  }

  otrv4_dake_prekey_message_free(m);

  return SUCCESS;
}

tstatic otrv4_err_t reply_with_prekey_msg_to_server(otrv4_server_t *server,
                                                   otrv4_t *otr) {
  return otrv4_build_prekey_message(server, otr);
}

API void reply_with_prekey_msg_from_server(otrv4_server_t *server,
                                       otrv4_response_t *response) {
  response->to_send = server->prekey_message;
}

tstatic otrv4_err_t
serialize_and_encode_identity_message(string_t *dst,
                                      const dake_identity_message_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrv4_dake_identity_message_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic otrv4_err_t reply_with_identity_msg(otrv4_response_t *response,
                                           otrv4_t *otr) {
  dake_identity_message_t *m = NULL;
  otrv4_err_t err = ERROR;

  m = otrv4_dake_identity_message_new(get_my_user_profile(otr));
  if (!m)
    return err;

  m->sender_instance_tag = otr->our_instance_tag;
  m->receiver_instance_tag = otr->their_instance_tag;

  ec_point_copy(m->Y, OUR_ECDH(otr));
  m->B = dh_mpi_copy(OUR_DH(otr));

  if (serialize_and_encode_identity_message(&response->to_send, m)) {
    otrv4_dake_identity_message_free(m);
    return err;
  }

  otrv4_dake_identity_message_free(m);

  return SUCCESS;
}

tstatic otrv4_err_t start_dake(otrv4_response_t *response, otrv4_t *otr) {
  if (key_manager_generate_ephemeral_keys(otr->keys) == ERROR)
    return ERROR;

  otr->state = OTRV4_STATE_WAITING_AUTH_R;
  maybe_create_keys(otr->conversation);
  return reply_with_identity_msg(response, otr);
}

API otrv4_err_t start_non_interactive_dake(otrv4_server_t *server, otrv4_t *otr) {
  if (key_manager_generate_ephemeral_keys(otr->keys) == ERROR)
    return ERROR;

  otr->state = OTRV4_STATE_START; // needed?
  maybe_create_keys(otr->conversation);

  return reply_with_prekey_msg_to_server(server, otr);
}

tstatic otrv4_err_t receive_tagged_plaintext(otrv4_response_t *response,
                                            const string_t message,
                                            otrv4_t *otr) {
  set_running_version_from_tag(otr, message);

  switch (otr->running_version) {
  case OTRV4_VERSION_4:
    if (message_to_display_without_tag(response, message, strlen(message))) {
      return ERROR;
    }
    dh_priv_key_destroy(otr->keys->our_dh);
    ec_scalar_destroy(otr->keys->our_ecdh->priv);
    return start_dake(response, otr);
    break;
  case OTRV4_VERSION_3:
    return otrv3_receive_message(&response->to_send, &response->to_display,
                                 &response->tlvs, message, otr->otr3_conn);
    break;
  case OTRV4_VERSION_NONE:
    /* ignore */
    return SUCCESS;
  }

  return ERROR;
}

tstatic otrv4_err_t receive_query_message(otrv4_response_t *response,
                                         const string_t message, otrv4_t *otr) {
  set_running_version_from_query_msg(otr, message);

  switch (otr->running_version) {
  case OTRV4_VERSION_4:
    dh_priv_key_destroy(otr->keys->our_dh);
    ec_scalar_destroy(otr->keys->our_ecdh->priv);
    return start_dake(response, otr);
    break;
  case OTRV4_VERSION_3:
    return otrv3_receive_message(&response->to_send, &response->to_display,
                                 &response->tlvs, message, otr->otr3_conn);
    break;
  case OTRV4_VERSION_NONE:
    /* ignore */
    return SUCCESS;
  }

  return ERROR;
}

tstatic otrv4_err_t
build_auth_message(uint8_t **msg, size_t *msg_len, const uint8_t type,
                   const user_profile_t *i_profile,
                   const user_profile_t *r_profile, const ec_point_t i_ecdh,
                   const ec_point_t r_ecdh, const dh_mpi_t i_dh,
                   const dh_mpi_t r_dh, char *phi) {
  uint8_t *ser_i_profile = NULL, *ser_r_profile = NULL;
  size_t ser_i_profile_len, ser_r_profile_len = 0;
  uint8_t ser_i_ecdh[ED448_POINT_BYTES], ser_r_ecdh[ED448_POINT_BYTES];
  uint8_t ser_i_dh[DH3072_MOD_LEN_BYTES], ser_r_dh[DH3072_MOD_LEN_BYTES];
  size_t ser_i_dh_len = 0, ser_r_dh_len = 0;
  uint8_t hash_ser_i_profile[HASH_BYTES];
  uint8_t hash_ser_r_profile[HASH_BYTES];
  uint8_t hash_phi[HASH_BYTES];

  serialize_ec_point(ser_i_ecdh, i_ecdh);
  serialize_ec_point(ser_r_ecdh, r_ecdh);

  if (serialize_dh_public_key(ser_i_dh, &ser_i_dh_len, i_dh))
    return ERROR;

  if (serialize_dh_public_key(ser_r_dh, &ser_r_dh_len, r_dh))
    return ERROR;

  do {
    if (user_profile_asprintf(&ser_i_profile, &ser_i_profile_len, i_profile))
      continue;

    if (user_profile_asprintf(&ser_r_profile, &ser_r_profile_len, r_profile))
      continue;

    char *phi_val = NULL;
    if (!phi) {
      phi = "";
    }
    phi_val = otrv4_strdup(phi);
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

tstatic otrv4_err_t serialize_and_encode_auth_r(string_t *dst,
                                               const dake_auth_r_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrv4_dake_auth_r_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic otrv4_err_t reply_with_auth_r_msg(string_t *dst, otrv4_t *otr) {
  dake_auth_r_t msg[1];

  msg->sender_instance_tag = otr->our_instance_tag;
  msg->receiver_instance_tag = otr->their_instance_tag;

  user_profile_copy(msg->profile, get_my_user_profile(otr));

  ec_point_copy(msg->X, OUR_ECDH(otr));
  msg->A = dh_mpi_copy(OUR_DH(otr));

  unsigned char *t = NULL;
  size_t t_len = 0;

  if (build_auth_message(&t, &t_len, 0, otr->their_profile,
                         get_my_user_profile(otr), THEIR_ECDH(otr),
                         OUR_ECDH(otr), THEIR_DH(otr), OUR_DH(otr),
                         otr->conversation->client->phi))
    return ERROR;

  /* sigma = Auth(g^R, R, {g^I, g^R, g^i}, msg) */
  otrv4_snizkpk_authenticate(msg->sigma,
                       otr->conversation->client->keypair, /* g^R and R */
                       otr->their_profile->pub_key,        /* g^I */
                       THEIR_ECDH(otr),                    /* g^i -- Y */
                       t, t_len);

  free(t);
  t = NULL;

  otrv4_err_t err = serialize_and_encode_auth_r(dst, msg);
  otrv4_dake_auth_r_destroy(msg);

  return err;
}

tstatic otrv4_err_t generate_tmp_key_r(uint8_t *dst, otrv4_t *otr) {
  k_ecdh_t tmp_ecdh_k1;
  k_ecdh_t tmp_ecdh_k2;
  k_ecdh_t k_ecdh;
  k_dh_t k_dh;

  // TODO: this will be calculated again later
  ecdh_shared_secret(k_ecdh, otr->keys->our_ecdh, otr->keys->their_ecdh);
  // TODO: this will be calculated again later
  if (dh_shared_secret(k_dh, sizeof(k_dh_t), otr->keys->our_dh->priv,
                       otr->keys->their_dh))
    return ERROR;

  brace_key_t brace_key;
  hash_hash(brace_key, sizeof(brace_key_t), k_dh, sizeof(k_dh_t));

#ifdef DEBUG
  printf("GENERATING TEMP KEY R\n");
  printf("K_ecdh = ");
  otrv4_memdump(k_ecdh, sizeof(k_ecdh_t));
  printf("brace_key = ");
  otrv4_memdump(brace_key, sizeof(brace_key_t));
#endif

  ecdh_shared_secret(tmp_ecdh_k1, otr->keys->our_ecdh,
                     otr->keys->their_shared_prekey);
  ecdh_shared_secret(tmp_ecdh_k2, otr->keys->our_ecdh,
                     otr->their_profile->pub_key);

  decaf_shake256_ctx_t hd;
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
  otrv4_memdump(dst, HASH_BYTES);
#endif

  sodium_memzero(tmp_ecdh_k1, ED448_POINT_BYTES);
  sodium_memzero(tmp_ecdh_k2, ED448_POINT_BYTES);

  return SUCCESS;
}

tstatic otrv4_err_t build_non_interactive_auth_message(
    uint8_t **msg, size_t *msg_len, const user_profile_t *i_profile,
    const user_profile_t *r_profile, const ec_point_t i_ecdh,
    const ec_point_t r_ecdh, const dh_mpi_t i_dh, const dh_mpi_t r_dh,
    const otrv4_shared_prekey_pub_t r_shared_prekey, char *phi) {
  uint8_t *ser_i_profile = NULL, *ser_r_profile = NULL;
  size_t ser_i_profile_len, ser_r_profile_len = 0;
  uint8_t ser_i_ecdh[ED448_POINT_BYTES], ser_r_ecdh[ED448_POINT_BYTES];
  uint8_t ser_i_dh[DH3072_MOD_LEN_BYTES], ser_r_dh[DH3072_MOD_LEN_BYTES];
  size_t ser_i_dh_len = 0, ser_r_dh_len = 0;
  uint8_t ser_r_shared_prekey[ED448_SHARED_PREKEY_BYTES];
  uint8_t hash_ser_i_profile[HASH_BYTES];
  uint8_t hash_ser_r_profile[HASH_BYTES];
  uint8_t hash_phi[HASH_BYTES];

  serialize_ec_point(ser_i_ecdh, i_ecdh);
  serialize_ec_point(ser_r_ecdh, r_ecdh);

  if (serialize_dh_public_key(ser_i_dh, &ser_i_dh_len, i_dh))
    return ERROR;

  if (serialize_dh_public_key(ser_r_dh, &ser_r_dh_len, r_dh))
    return ERROR;

  serialize_otrv4_shared_prekey(ser_r_shared_prekey, r_shared_prekey);

  otrv4_err_t err = ERROR;

  do {
    if (user_profile_asprintf(&ser_i_profile, &ser_i_profile_len, i_profile))
      continue;

    if (user_profile_asprintf(&ser_r_profile, &ser_r_profile_len, r_profile))
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

tstatic otrv4_err_t serialize_and_encode_non_interactive_auth(
    string_t *dst, const dake_non_interactive_auth_message_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrv4_dake_non_interactive_auth_message_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic data_message_t *generate_data_msg(const otrv4_t *otr) {
  data_message_t *data_msg = data_message_new();
  if (!data_msg)
    return NULL;

  data_msg->sender_instance_tag = otr->our_instance_tag;
  data_msg->receiver_instance_tag = otr->their_instance_tag;
  data_msg->message_id = otr->keys->j;
  ec_point_copy(data_msg->ecdh, OUR_ECDH(otr));
  data_msg->dh = dh_mpi_copy(OUR_DH(otr));

  return data_msg;
}

tstatic otrv4_err_t encrypt_data_message(data_message_t *data_msg,
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
  otrv4_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
  printf("msg = ");
  otrv4_memdump(message, message_len);
  printf("cipher = ");
  otrv4_memdump(c, message_len);
#endif

  return SUCCESS;
}

tstatic otrv4_err_t encrypt_msg_on_non_interactive_auth(
    dake_non_interactive_auth_message_t *auth, uint8_t *message,
    size_t message_len, uint8_t nonce[DATA_MSG_NONCE_BYTES], otrv4_t *otr) {
  auth->message_id = otr->keys->j;

  m_enc_key_t enc_key;
  m_mac_key_t mac_key;
  memset(enc_key, 0, sizeof enc_key);
  memset(mac_key, 0, sizeof mac_key);

  if (key_manager_retrieve_sending_message_keys(enc_key, mac_key, otr->keys)) {
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
  otrv4_memdump(nonce, DATA_MSG_NONCE_BYTES);
  printf("msg = ");
  otrv4_memdump(message, message_len);
  printf("cipher = ");
  otrv4_memdump(c, message_len);
#endif

  sodium_memzero(enc_key, sizeof(m_enc_key_t));

  return SUCCESS;
}

tstatic otrv4_err_t data_message_body_on_non_interactive_asprintf(
    uint8_t **body, size_t *bodylen,
    const dake_non_interactive_auth_message_t *auth) {
  size_t s = 4 + DATA_MSG_NONCE_BYTES + auth->enc_msg_len + 4;

  uint8_t *dst = malloc(s);
  if (!dst)
    return ERROR;

  uint8_t *cursor = dst;
  cursor += serialize_uint32(cursor, auth->message_id);
  cursor += serialize_bytes_array(cursor, auth->nonce, DATA_MSG_NONCE_BYTES);
  cursor += serialize_data(cursor, auth->enc_msg, auth->enc_msg_len);

  if (body)
    *body = dst;

  if (bodylen)
    *bodylen = cursor - dst;

  return SUCCESS;
}

tstatic otrv4_err_t reply_with_non_interactive_auth_msg(string_t *dst,
                                                       uint8_t *message,
                                                       size_t msglen,
                                                       otrv4_t *otr) {
  dake_non_interactive_auth_message_t auth[1];
  auth->enc_msg = NULL;
  auth->enc_msg_len = 0;

  auth->sender_instance_tag = otr->our_instance_tag;
  auth->receiver_instance_tag = otr->their_instance_tag;

  user_profile_copy(auth->profile, get_my_user_profile(otr));

  ec_point_copy(auth->X, OUR_ECDH(otr));
  auth->A = dh_mpi_copy(OUR_DH(otr));

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
    otrv4_dake_non_interactive_auth_message_destroy(auth);

    return ERROR;
  }

  /* sigma = Auth(g^R, R, {g^I, g^R, g^i}, msg) */
  otrv4_snizkpk_authenticate(auth->sigma,
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
      otrv4_dake_non_interactive_auth_message_destroy(auth);
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
      otrv4_dake_non_interactive_auth_message_destroy(auth);
      free(t);
      t = NULL;
      return ERROR;
    }

    /* Auth MAC = KDF_2(auth_mac_k || t || (message_id || nonce || enc_msg)) */
    decaf_shake256_ctx_t hd;
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

  otrv4_err_t err = serialize_and_encode_non_interactive_auth(dst, auth);

  if (auth->enc_msg) {
    free(auth->enc_msg);
    auth->enc_msg = NULL;
  }
  otrv4_dake_non_interactive_auth_message_destroy(auth);

  return err;
}

tstatic otrv4_err_t generate_tmp_key_i(uint8_t *dst, otrv4_t *otr) {
  k_ecdh_t k_ecdh;
  k_dh_t k_dh;
  k_ecdh_t tmp_ecdh_k1;
  k_ecdh_t tmp_ecdh_k2;

  // TODO: this will be calculated again later
  ecdh_shared_secret(k_ecdh, otr->keys->our_ecdh, otr->keys->their_ecdh);
  // TODO: this will be calculated again later
  if (dh_shared_secret(k_dh, sizeof(k_dh_t), otr->keys->our_dh->priv,
                       otr->keys->their_dh))
    return ERROR;

  brace_key_t brace_key;
  hash_hash(brace_key, sizeof(brace_key_t), k_dh, sizeof(k_dh_t));

#ifdef DEBUG
  printf("GENERATING TEMP KEY I\n");
  printf("K_ecdh = ");
  otrv4_memdump(k_ecdh, sizeof(k_ecdh_t));
  printf("brace_key = ");
  otrv4_memdump(brace_key, sizeof(brace_key_t));
#endif

  ecdh_shared_secret_from_prekey(tmp_ecdh_k1,
                                 otr->conversation->client->shared_prekey_pair,
                                 THEIR_ECDH(otr));
  ecdh_shared_secret_from_keypair(
      tmp_ecdh_k2, otr->conversation->client->keypair, THEIR_ECDH(otr));

  decaf_shake256_ctx_t hd;
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
  otrv4_memdump(dst, HASH_BYTES);
#endif

  sodium_memzero(tmp_ecdh_k1, ED448_POINT_BYTES);
  sodium_memzero(tmp_ecdh_k2, ED448_POINT_BYTES);

  return SUCCESS;
}

tstatic void otrv4_error_message(string_t *to_send, otrv4_err_code_t err_code) {
  char *msg = NULL;
  char *err_msg = NULL;

  switch (err_code) {
  case ERR_NONE:
    break;
  case ERR_MSG_UNDECRYPTABLE:
    msg = strdup("OTR4_ERR_MSG_READABLE");
    err_msg = malloc(strlen(ERROR_PREFIX) + strlen(ERROR_CODE_1) +
                     strlen(msg) + 1);
    if (!err_msg)
      return;

    if (err_msg) {
      strcpy(err_msg, ERROR_PREFIX);
      strcpy(err_msg + strlen(ERROR_PREFIX), ERROR_CODE_1);
      strcat(err_msg, msg);
    }
    free((char *)msg);
    msg = NULL;

    *to_send = otrv4_strdup(err_msg);
    free(err_msg);
    err_msg = NULL;
    break;
  case ERR_MSG_NOT_PRIVATE:
    msg = strdup("OTR4_ERR_MSG_NOT_PRIVATE_STATE");
    err_msg = malloc(strlen(ERROR_PREFIX) + strlen(ERROR_CODE_2) +
                     strlen(msg) + 1);
    if (!err_msg)
      return;

    if (err_msg) {
      strcpy(err_msg, ERROR_PREFIX);
      strcpy(err_msg + strlen(ERROR_PREFIX), ERROR_CODE_2);
      strcat(err_msg, msg);
    }
    free((char *)msg);
    msg = NULL;

    *to_send = otrv4_strdup(err_msg);
    free(err_msg);
    err_msg = NULL;
    break;
  }
}

tstatic otrv4_err_t double_ratcheting_init(int j, bool interactive,
                                          otrv4_t *otr) {
  if (key_manager_ratcheting_init(j, interactive, otr->keys))
    return ERROR;

  otr->state = OTRV4_STATE_ENCRYPTED_MESSAGES;
  gone_secure_cb_v4(otr->conversation);

  return SUCCESS;
}

tstatic void received_instance_tag(uint32_t their_instance_tag, otrv4_t *otr) {
  // TODO: should we do any additional check?
  otr->their_instance_tag = their_instance_tag;
}

tstatic otrv4_err_t receive_prekey_message(string_t *dst, const uint8_t *buff,
                                          size_t buflen, otrv4_t *otr) {
  if (otr->state == OTRV4_STATE_FINISHED)
    return SUCCESS; /* ignore the message */

  otrv4_err_t err = ERROR;
  dake_prekey_message_t m[1];

  if (otrv4_dake_prekey_message_deserialize(m, buff, buflen))
    return err;

  if (m->receiver_instance_tag != 0) {
    otrv4_dake_prekey_message_destroy(m);
    return SUCCESS;
  }

  received_instance_tag(m->sender_instance_tag, otr);

  if (otrv4_valid_received_values(m->Y, m->B, m->profile)) {
    otrv4_dake_prekey_message_destroy(m);
    return err;
  }

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile) {
    otrv4_dake_prekey_message_destroy(m);
    return err;
  }

  key_manager_set_their_ecdh(m->Y, otr->keys);
  key_manager_set_their_dh(m->B, otr->keys);
  user_profile_copy(otr->their_profile, m->profile);

  otrv4_dake_prekey_message_destroy(m);

  if (key_manager_generate_ephemeral_keys(otr->keys))
    return err;

  memcpy(otr->keys->their_shared_prekey, otr->their_profile->shared_prekey,
         sizeof(otrv4_shared_prekey_pub_t));

  /* tmp_k = KDF_2(K_ecdh || ECDH(x, their_shared_prekey) ||
   * ECDH(x, Pkb) || k_dh) */
  if (generate_tmp_key_r(otr->keys->tmp_key, otr))
    return err;

  if (double_ratcheting_init(0, false, otr))
    return err;

  return SUCCESS;
}

API otrv4_err_t send_non_interactive_auth_msg(string_t *dst, otrv4_t *otr,
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

tstatic otrv4_bool_t valid_data_message_on_non_interactive_auth(
    unsigned char *t, size_t t_len, m_mac_key_t mac_key,
    const dake_non_interactive_auth_message_t *auth) {
  uint8_t *enc_msg = NULL;
  size_t enc_msg_len = 0;

  if (data_message_body_on_non_interactive_asprintf(&enc_msg, &enc_msg_len,
                                                    auth))
    return otrv4_false;

  uint8_t mac_tag[DATA_MSG_MAC_BYTES];
  memset(mac_tag, 0, sizeof mac_tag);

  /* Auth MAC = KDF_2(auth_mac_k || t || enc_msg) */
  decaf_shake256_ctx_t hd;

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
    return otrv4_false;
  }

  return otrv4_true;
}

tstatic otrv4_bool_t verify_non_interactive_auth_message(
    otrv4_response_t *response, const dake_non_interactive_auth_message_t *auth,
    otrv4_t *otr) {
  unsigned char *t = NULL;
  size_t t_len = 0;

  /* t = KDF_2(Bobs_User_Profile) || KDF_2(Alices_User_Profile) ||
   * Y || X || B || A || our_shared_prekey.public */
  if (build_non_interactive_auth_message(
          &t, &t_len, get_my_user_profile(otr), auth->profile, OUR_ECDH(otr),
          auth->X, OUR_DH(otr), auth->A, otr->profile->shared_prekey,
          otr->conversation->client->phi)) {
    return otrv4_false;
  }

  /* Verif({g^I, g^R, g^i}, sigma, msg) */
  otrv4_bool_t err =
      otrv4_snizkpk_verify(auth->sigma, auth->profile->pub_key,     /* g^R */
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

    if (key_manager_retrieve_receiving_message_keys(
            enc_key, mac_key, auth->message_id, otr->keys)) {
      free(t);
      t = NULL;
      sodium_memzero(enc_key, sizeof(m_enc_key_t));
      sodium_memzero(mac_key, sizeof(m_mac_key_t));
      return otrv4_false;
    }

    /* discard this mac key as it is not needed */
    sodium_memzero(mac_key, sizeof(m_mac_key_t));

    if (valid_data_message_on_non_interactive_auth(t, t_len, auth_mac_k,
                                                   auth)) {
      free(t);
      t = NULL;
      sodium_memzero(enc_key, sizeof(m_enc_key_t));
      /* here no warning should be passed */
      return otrv4_false;
    }

    free(t);
    t = NULL;

    string_t *dst = &response->to_display;
    uint8_t *plain = malloc(auth->enc_msg_len);
    if (!plain) {
      sodium_memzero(enc_key, sizeof(m_enc_key_t));
      return otrv4_false;
    }

    int err = crypto_stream_xor(plain, auth->enc_msg, auth->enc_msg_len,
                                auth->nonce, enc_key);
    if (err != 0) {
      otrv4_error_message(dst, ERR_MSG_UNDECRYPTABLE);
      free(plain);
      plain = NULL;
      sodium_memzero(enc_key, sizeof(m_enc_key_t));
      return otrv4_false;
    }

    if (strnlen((string_t)plain, auth->enc_msg_len))
      *dst = otrv4_strndup((char *)plain, auth->enc_msg_len);

    free(plain);
    plain = NULL;
    sodium_memzero(enc_key, sizeof(enc_key));

    uint8_t *to_store_mac = malloc(MAC_KEY_BYTES);
    if (to_store_mac == NULL) {
      return otrv4_false;
    }

    memcpy(to_store_mac, mac_key, MAC_KEY_BYTES);
    otr->keys->old_mac_keys = list_add(to_store_mac, otr->keys->old_mac_keys);
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
      return otrv4_false;
    }
  }

  free(t);
  t = NULL;

  return err;
}

tstatic otrv4_err_t
receive_non_interactive_auth_message(otrv4_response_t *response,
                                     const uint8_t *buff, size_t buff_len,
                                     otrv4_t *otr) {
  if (otr->state == OTRV4_STATE_FINISHED)
    return SUCCESS; /* ignore the message */

  dake_non_interactive_auth_message_t auth[1];
  auth->enc_msg = NULL;

  if (otrv4_dake_non_interactive_auth_message_deserialize(auth, buff, buff_len))
    return ERROR;

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    otrv4_dake_non_interactive_auth_message_destroy(auth);
    return SUCCESS;
  }

  received_instance_tag(auth->sender_instance_tag, otr);

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile) {
    otrv4_dake_non_interactive_auth_message_destroy(auth);
    return ERROR;
  }

  key_manager_set_their_ecdh(auth->X, otr->keys);
  key_manager_set_their_dh(auth->A, otr->keys);
  user_profile_copy(otr->their_profile, auth->profile);

  /* tmp_k = KDF_2(K_ecdh ||
   * ECDH(x, our_shared_prekey.secret, their_ecdh) ||
   * ECDH(Ska, X) || k_dh) */
  if (generate_tmp_key_i(otr->keys->tmp_key, otr) == ERROR) {
    otrv4_dake_non_interactive_auth_message_destroy(auth);
    return ERROR;
  }

  if (double_ratcheting_init(1, false, otr)) {
    otrv4_dake_non_interactive_auth_message_destroy(auth);
    return ERROR;
  }

  if (verify_non_interactive_auth_message(response, auth, otr) == otrv4_false) {
    free(auth->enc_msg);
    auth->enc_msg = NULL;
    otrv4_dake_non_interactive_auth_message_destroy(auth);
    return ERROR;
  }

  if (auth->enc_msg) {
    free(auth->enc_msg);
    auth->enc_msg = NULL;
  }
  otrv4_dake_non_interactive_auth_message_destroy(auth);

  otrv4_fingerprint_t fp;
  if (!otr4_serialize_fingerprint(fp, otr->their_profile->pub_key))
    fingerprint_seen_cb_v4(fp, otr->conversation);

  return SUCCESS;
}

tstatic otrv4_err_t receive_identity_message_on_state_start(
    string_t *dst, dake_identity_message_t *identity_message, otrv4_t *otr) {

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile)
    return ERROR;

  key_manager_set_their_ecdh(identity_message->Y, otr->keys);
  key_manager_set_their_dh(identity_message->B, otr->keys);
  user_profile_copy(otr->their_profile, identity_message->profile);

  if (key_manager_generate_ephemeral_keys(otr->keys))
    return ERROR;

  if (reply_with_auth_r_msg(dst, otr))
    return ERROR;

  otr->state = OTRV4_STATE_WAITING_AUTH_I;
  return SUCCESS;
}

tstatic void forget_our_keys(otrv4_t *otr) {
  key_manager_destroy(otr->keys);
  key_manager_init(otr->keys);
}

tstatic otrv4_err_t receive_identity_message_on_waiting_auth_r(
    string_t *dst, dake_identity_message_t *msg, otrv4_t *otr) {
  int cmp = gcry_mpi_cmp(OUR_DH(otr), msg->B);

  /* If our is higher, ignore. */
  if (cmp > 0) {
    // TODO: this should resend the prev identity message
    return SUCCESS;
  }

  forget_our_keys(otr);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

tstatic otrv4_err_t receive_identity_message_on_waiting_auth_i(
    string_t *dst, dake_identity_message_t *msg, otrv4_t *otr) {
  user_profile_free(otr->their_profile);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

tstatic otrv4_err_t receive_identity_message(string_t *dst, const uint8_t *buff,
                                            size_t buflen, otrv4_t *otr) {
  otrv4_err_t err = ERROR;
  dake_identity_message_t m[1];

  if (otrv4_dake_identity_message_deserialize(m, buff, buflen))
    return err;

  if (m->receiver_instance_tag != 0) {
    otrv4_dake_identity_message_destroy(m);
    return SUCCESS;
  }

  received_instance_tag(m->sender_instance_tag, otr);

  if (otrv4_valid_received_values(m->Y, m->B, m->profile)) {
    otrv4_dake_identity_message_destroy(m);
    return err;
  }

  switch (otr->state) {
  case OTRV4_STATE_START:
    err = receive_identity_message_on_state_start(dst, m, otr);
    break;
  case OTRV4_STATE_WAITING_AUTH_R:
    err = receive_identity_message_on_waiting_auth_r(dst, m, otr);
    break;
  case OTRV4_STATE_WAITING_AUTH_I:
    err = receive_identity_message_on_waiting_auth_i(dst, m, otr);
    break;
  case OTRV4_STATE_NONE:
  case OTRV4_STATE_ENCRYPTED_MESSAGES:
  case OTRV4_STATE_FINISHED:
    /* Ignore the message, but it is not an error. */
    err = SUCCESS;
  }

  otrv4_dake_identity_message_destroy(m);
  return err;
}

tstatic otrv4_err_t serialize_and_encode_auth_i(string_t *dst,
                                               const dake_auth_i_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (otrv4_dake_auth_i_asprintf(&buff, &len, m))
    return ERROR;

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  buff = NULL;

  return SUCCESS;
}

tstatic otrv4_err_t reply_with_auth_i_msg(string_t *dst,
                                         const user_profile_t *their,
                                         otrv4_t *otr) {
  dake_auth_i_t msg[1];
  msg->sender_instance_tag = otr->our_instance_tag;
  msg->receiver_instance_tag = otr->their_instance_tag;

  unsigned char *t = NULL;
  size_t t_len = 0;

  if (build_auth_message(&t, &t_len, 1, get_my_user_profile(otr), their,
                         OUR_ECDH(otr), THEIR_ECDH(otr), OUR_DH(otr),
                         THEIR_DH(otr), otr->conversation->client->phi))
    return ERROR;

  otrv4_snizkpk_authenticate(msg->sigma, otr->conversation->client->keypair,
                       their->pub_key, THEIR_ECDH(otr), t, t_len);
  free(t);
  t = NULL;

  otrv4_err_t err = serialize_and_encode_auth_i(dst, msg);
  otrv4_dake_auth_i_destroy(msg);

  return err;
}

tstatic otrv4_bool_t valid_auth_r_message(const dake_auth_r_t *auth,
                                         otrv4_t *otr) {
  uint8_t *t = NULL;
  size_t t_len = 0;

  if (otrv4_valid_received_values(auth->X, auth->A, auth->profile))
    return otrv4_false;

  if (build_auth_message(&t, &t_len, 0, get_my_user_profile(otr), auth->profile,
                         OUR_ECDH(otr), auth->X, OUR_DH(otr), auth->A,
                         otr->conversation->client->phi))
    return otrv4_false;

  /* Verif({g^I, g^R, g^i}, sigma, msg) */
  otrv4_bool_t err =
      otrv4_snizkpk_verify(auth->sigma, auth->profile->pub_key,     /* g^R */
                     otr->conversation->client->keypair->pub, /* g^I */
                     OUR_ECDH(otr),                           /* g^  */
                     t, t_len);

  free(t);
  t = NULL;

  return err;
}

tstatic otrv4_err_t receive_auth_r(string_t *dst, const uint8_t *buff,
                                  size_t buff_len, otrv4_t *otr) {
  if (otr->state != OTRV4_STATE_WAITING_AUTH_R)
    return SUCCESS; /* ignore the message */

  dake_auth_r_t auth[1];
  if (otrv4_dake_auth_r_deserialize(auth, buff, buff_len))
    return ERROR;

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    otrv4_dake_auth_r_destroy(auth);
    return SUCCESS;
  }

  received_instance_tag(auth->sender_instance_tag, otr);

  if (valid_auth_r_message(auth, otr) == otrv4_false) {
    otrv4_dake_auth_r_destroy(auth);
    return ERROR;
  }

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile) {
    otrv4_dake_auth_r_destroy(auth);
    return ERROR;
  }

  key_manager_set_their_ecdh(auth->X, otr->keys);
  key_manager_set_their_dh(auth->A, otr->keys);
  user_profile_copy(otr->their_profile, auth->profile);

  if (reply_with_auth_i_msg(dst, otr->their_profile, otr)) {
    otrv4_dake_auth_r_destroy(auth);
    return ERROR;
  }

  otrv4_dake_auth_r_destroy(auth);

  otrv4_fingerprint_t fp;
  if (!otr4_serialize_fingerprint(fp, otr->their_profile->pub_key))
    fingerprint_seen_cb_v4(fp, otr->conversation);

  return double_ratcheting_init(0, true, otr);
}

tstatic otrv4_bool_t valid_auth_i_message(const dake_auth_i_t *auth,
                                         otrv4_t *otr) {
  uint8_t *t = NULL;
  size_t t_len = 0;

  if (build_auth_message(&t, &t_len, 1, otr->their_profile,
                         get_my_user_profile(otr), THEIR_ECDH(otr),
                         OUR_ECDH(otr), THEIR_DH(otr), OUR_DH(otr),
                         otr->conversation->client->phi))
    return otrv4_false;

  otrv4_bool_t err = otrv4_snizkpk_verify(auth->sigma, otr->their_profile->pub_key,
                                    otr->conversation->client->keypair->pub,
                                    OUR_ECDH(otr), t, t_len);
  free(t);
  t = NULL;

  return err;
}

tstatic otrv4_err_t receive_auth_i(const uint8_t *buff, size_t buff_len,
                                  otrv4_t *otr) {
  if (otr->state != OTRV4_STATE_WAITING_AUTH_I)
    return SUCCESS; /* Ignore the message */

  dake_auth_i_t auth[1];
  if (otrv4_dake_auth_i_deserialize(auth, buff, buff_len))
    return ERROR;

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    otrv4_dake_auth_i_destroy(auth);
    return SUCCESS;
  }

  if (valid_auth_i_message(auth, otr) == otrv4_false) {
    otrv4_dake_auth_i_destroy(auth);
    return ERROR;
  }

  otrv4_dake_auth_i_destroy(auth);

  otrv4_fingerprint_t fp;
  if (!otr4_serialize_fingerprint(fp, otr->their_profile->pub_key))
    fingerprint_seen_cb_v4(fp, otr->conversation);

  return double_ratcheting_init(1, true, otr);
}

// TODO: this is the same as otrv4_close
INTERNAL otrv4_err_t otrv4_expire_session(string_t *to_send, otrv4_t *otr) {
  tlv_t *disconnected = otrv4_disconnected_tlv_new();
  if (!disconnected)
    return ERROR;

  otrv4_err_t err = otrv4_prepare_to_send_message(
      to_send, "", &disconnected, MSGFLAGS_IGNORE_UNREADABLE, otr);

  otrv4_tlv_free(disconnected);
  forget_our_keys(otr);
  otr->state = OTRV4_STATE_START;
  gone_insecure_cb_v4(otr->conversation);

  return err;
}

tstatic void extract_tlvs(tlv_t **tlvs, const uint8_t *src, size_t len) {
  if (!tlvs)
    return;

  uint8_t *tlvs_start = NULL;
  tlvs_start = memchr(src, 0, len);
  if (!tlvs_start)
    return;

  size_t tlvs_len = len - (tlvs_start + 1 - src);
  *tlvs = otrv4_parse_tlvs(tlvs_start + 1, tlvs_len);
}

tstatic otrv4_err_t decrypt_data_msg(otrv4_response_t *response,
                                    const m_enc_key_t enc_key,
                                    const data_message_t *msg) {
  string_t *dst = &response->to_display;
  tlv_t **tlvs = &response->tlvs;

#ifdef DEBUG
  printf("DECRYPTING\n");
  printf("enc_key = ");
  otrv4_memdump(enc_key, sizeof(m_enc_key_t));
  printf("nonce = ");
  otrv4_memdump(msg->nonce, DATA_MSG_NONCE_BYTES);
#endif

  uint8_t *plain = malloc(msg->enc_msg_len);
  if (!plain)
    return ERROR;

  int err = crypto_stream_xor(plain, msg->enc_msg, msg->enc_msg_len, msg->nonce,
                              enc_key);

  if (strnlen((string_t)plain, msg->enc_msg_len))
    *dst = otrv4_strndup((char *)plain, msg->enc_msg_len);

  extract_tlvs(tlvs, plain, msg->enc_msg_len);

  free(plain);
  plain = NULL;

  if (err == 0) {
    return SUCCESS;
  }

  // TODO: correctly free
  otrv4_tlv_free(*tlvs);
  return ERROR;
}

tstatic tlv_t *otrv4_process_smp(otr4_smp_event_t event, smp_context_t smp,
                                const tlv_t *tlv) {
  event = OTRV4_SMPEVENT_NONE;
  tlv_t *to_send = NULL;

  switch (tlv->type) {
  case OTRV4_TLV_SMP_MSG_1:
    event = process_smp_msg1(tlv, smp);
    break;

  case OTRV4_TLV_SMP_MSG_2:
    event = process_smp_msg2(&to_send, tlv, smp);
    break;

  case OTRV4_TLV_SMP_MSG_3:
    event = process_smp_msg3(&to_send, tlv, smp);
    break;

  case OTRV4_TLV_SMP_MSG_4:
    event = process_smp_msg4(tlv, smp);
    break;

  case OTRV4_TLV_SMP_ABORT:
    // If smpstate is not the receive message:
    // Set smpstate to SMPSTATE_EXPECT1
    // send a SMP abort to other peer.
    smp->state = SMPSTATE_EXPECT1;
    to_send = otrv4_tlv_new(OTRV4_TLV_SMP_ABORT, 0, NULL);
    if (!to_send)
      return NULL;

    event = OTRV4_SMPEVENT_ABORT;

    break;
  case OTRV4_TLV_NONE:
  case OTRV4_TLV_PADDING:
  case OTRV4_TLV_DISCONNECTED:
  case OTRV4_TLV_SYM_KEY:
    // Ignore. They should not be passed to this function.
    break;
  }

  if (!event)
    event = OTRV4_SMPEVENT_IN_PROGRESS;

  return to_send;
}

tstatic unsigned int extract_word(unsigned char *bufp) {
  unsigned int use =
      (bufp[0] << 24) | (bufp[1] << 16) | (bufp[2] << 8) | bufp[3];
  return use;
}

tstatic tlv_t *process_tlv(const tlv_t *tlv, otrv4_t *otr) {
  if (tlv->type == OTRV4_TLV_NONE) {
    return NULL;
  }

  if (tlv->type == OTRV4_TLV_PADDING) {
    return NULL;
  }

  if (tlv->type == OTRV4_TLV_DISCONNECTED) {
    forget_our_keys(otr);
    otr->state = OTRV4_STATE_FINISHED;
    gone_insecure_cb_v4(otr->conversation);
    return NULL;
  }

  if (tlv->type == OTRV4_TLV_SYM_KEY && tlv->len >= 4) {
    if (otr->keys->extra_key > 0) {
      uint32_t use = extract_word(tlv->data);

      received_symkey_cb_v4(otr->conversation, use, tlv->data + 4, tlv->len - 4,
                         otr->keys->extra_key);
      sodium_memzero(otr->keys->extra_key, sizeof(otr->keys->extra_key));
      return NULL;
    }
    return NULL;
  }

  otr4_smp_event_t event = OTRV4_SMPEVENT_NONE;
  tlv_t *out = otrv4_process_smp(event, otr->smp, tlv);
  handle_smp_event_cb_v4(event, otr->smp->progress,
                      otr->smp->msg1 ? otr->smp->msg1->question : NULL,
                      otr->conversation);
  return out;
}

tstatic otrv4_err_t receive_tlvs(tlv_t **to_send, otrv4_response_t *response,
                                otrv4_t *otr) {
  tlv_t *cursor = NULL;

  const tlv_t *current = response->tlvs;
  while (current) {
    tlv_t *ret = process_tlv(current, otr);
    current = current->next;

    if (!ret)
      continue;

    if (cursor)
      cursor = cursor->next;

    cursor = ret;
  }

  *to_send = cursor;

  return SUCCESS;
}

tstatic otrv4_err_t get_receiving_msg_keys(m_enc_key_t enc_key,
                                          m_mac_key_t mac_key,
                                          const data_message_t *msg,
                                          otrv4_t *otr) {
  if (key_manager_ensure_on_ratchet(otr->keys) == ERROR)
    return ERROR;

  if (key_manager_retrieve_receiving_message_keys(enc_key, mac_key,
                                                  msg->message_id, otr->keys)) {
    sodium_memzero(enc_key, sizeof(m_enc_key_t));
    sodium_memzero(mac_key, sizeof(m_mac_key_t));
    return ERROR;
  }

  return SUCCESS;
}

tstatic otrv4_err_t otrv4_receive_data_message(otrv4_response_t *response,
                                              const uint8_t *buff,
                                              size_t buflen, otrv4_t *otr) {
  data_message_t *msg = data_message_new();
  m_enc_key_t enc_key;
  m_mac_key_t mac_key;

  memset(enc_key, 0, sizeof enc_key);
  memset(mac_key, 0, sizeof mac_key);

  // TODO: check this case with Nik on otr3
  if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES) {
    otrv4_error_message(&response->to_send, ERR_MSG_NOT_PRIVATE);
    free(msg);
    msg = NULL;
    return ERROR;
  }

  size_t read = 0;
  if (data_message_deserialize(msg, buff, buflen, &read)) {
    data_message_free(msg);
    return ERROR;
  }

  key_manager_set_their_keys(msg->ecdh, msg->dh, otr->keys);

  tlv_t *reply_tlv = NULL;

  do {
    if (msg->receiver_instance_tag != otr->our_instance_tag) {
      response->to_display = NULL;
      data_message_free(msg);

      return SUCCESS;
    }

    if (get_receiving_msg_keys(enc_key, mac_key, msg, otr))
      continue;

    if (valid_data_message(mac_key, msg)) {
      sodium_memzero(enc_key, sizeof(enc_key));
      sodium_memzero(mac_key, sizeof(mac_key));
      response->to_display = NULL;
      data_message_free(msg);

      response->warning = OTRV4_WARN_RECEIVED_NOT_VALID;
      return MSG_NOT_VALID;
    }

    if (decrypt_data_msg(response, enc_key, msg)) {
      if (msg->flags != MSGFLAGS_IGNORE_UNREADABLE) {
        otrv4_error_message(&response->to_send, ERR_MSG_UNDECRYPTABLE);
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        response->to_display = NULL;
        data_message_free(msg);

        return ERROR;
      } else if (msg->flags == MSGFLAGS_IGNORE_UNREADABLE) {
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        response->to_display = NULL;
        data_message_free(msg);

        return ERROR;
      }
    }

    sodium_memzero(enc_key, sizeof(enc_key));
    sodium_memzero(mac_key, sizeof(mac_key));

    // TODO: Securely delete receiving chain keys older than message_id-1.
    if (receive_tlvs(&reply_tlv, response, otr))
      continue;

    key_manager_prepare_to_ratchet(otr->keys);

    if (reply_tlv) {
      if (otrv4_prepare_to_send_message(&response->to_send, "", &reply_tlv,
                                        MSGFLAGS_IGNORE_UNREADABLE, otr))
        continue;
    }

    uint8_t *to_store_mac = malloc(MAC_KEY_BYTES);
    if (to_store_mac == NULL) {
      response->to_display = NULL;
      data_message_free(msg);
      return ERROR;
    }

    memcpy(to_store_mac, mac_key, MAC_KEY_BYTES);
    otr->keys->old_mac_keys = list_add(to_store_mac, otr->keys->old_mac_keys);

    data_message_free(msg);
    otrv4_tlv_free(reply_tlv);
    return SUCCESS;
  } while (0);

  data_message_free(msg);
  otrv4_tlv_free(reply_tlv);

  return ERROR;
}

tstatic otrv4_err_t extract_header(otrv4_header_t *dst, const uint8_t *buffer,
                           const size_t bufflen) {
  if (bufflen == 0) {
    return ERROR;
  }

  size_t read = 0;
  uint16_t version = 0;
  uint8_t type = 0;
  if (deserialize_uint16(&version, buffer, bufflen, &read))
    return ERROR;

  buffer += read;

  if (deserialize_uint8(&type, buffer, bufflen - read, &read))
    return ERROR;

  dst->version = OTRV4_ALLOW_NONE;
  if (version == 0x04) {
    dst->version = OTRV4_ALLOW_V4;
  } else if (version == 0x03) {
    dst->version = OTRV4_ALLOW_V3;
  }
  dst->type = type;

  return SUCCESS;
}

tstatic otrv4_err_t receive_decoded_message(otrv4_response_t *response,
                                           const uint8_t *decoded,
                                           size_t dec_len, otrv4_t *otr) {
  otrv4_header_t header;
  if (extract_header(&header, decoded, dec_len))
    return ERROR;

  if (!allow_version(otr, header.version))
    return ERROR;

  // TODO: Why the version in the header is a ALLOWED VERSION?
  // This is the message version, not the version the protocol allows
  if (header.version != OTRV4_ALLOW_V4)
    return ERROR;

  // TODO: how to prevent version rollback?
  maybe_create_keys(otr->conversation);

  response->to_send = NULL;
  otrv4_err_t err;

  switch (header.type) {
  case IDENTITY_MSG_TYPE:
    otr->running_version = OTRV4_VERSION_4;
    return receive_identity_message(&response->to_send, decoded, dec_len, otr);
  case AUTH_R_MSG_TYPE:
    err = receive_auth_r(&response->to_send, decoded, dec_len, otr);
    if (otr->state == OTRV4_STATE_ENCRYPTED_MESSAGES) {
      dh_priv_key_destroy(otr->keys->our_dh);
      ec_scalar_destroy(otr->keys->our_ecdh->priv);
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
    return otrv4_receive_data_message(response, decoded, dec_len, otr);
  default:
    /* error. bad message type */
    return ERROR;
  }

  return ERROR;
}

tstatic otrv4_err_t receive_encoded_message(otrv4_response_t *response,
                                           const string_t message,
                                           otrv4_t *otr) {
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  if (otrl_base64_otr_decode(message, &decoded, &dec_len))
    return ERROR;

  otrv4_err_t err = receive_decoded_message(response, decoded, dec_len, otr);
  free(decoded);
  decoded = NULL;

  return err;
}

// TODO: only display the human readable part
tstatic otrv4_err_t receive_error_message(otrv4_response_t *response,
                                         const string_t message, otrv4_t *otr) {
  if (strcmp(&message[18], "2") || strcmp(&message[18], "1")) {
    response->to_display = otrv4_strndup(message, strlen(message));
    return SUCCESS;
  }

  return ERROR;
}

tstatic otrv4_in_message_type_t get_message_type(const string_t message) {
  if (message_contains_tag(message) == otrv4_false) {
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

tstatic otrv4_err_t receive_message_v4_only(otrv4_response_t *response,
                                           const string_t message,
                                           otrv4_t *otr) {

  switch (get_message_type(message)) {
  case IN_MSG_NONE:
    return ERROR;
  case IN_MSG_PLAINTEXT:
    receive_plaintext(response, message, otr);
    return SUCCESS;
    break;

  case IN_MSG_TAGGED_PLAINTEXT:
    return receive_tagged_plaintext(response, message, otr);
    break;

  case IN_MSG_QUERY_STRING:
    return receive_query_message(response, message, otr);
    break;

  case IN_MSG_OTR_ENCODED:
    return receive_encoded_message(response, message, otr);
    break;

  case IN_MSG_OTR_ERROR:
    return receive_error_message(response, message, otr);
    break;
  }

  return SUCCESS;
}

/* Receive a possibly OTR message. */
INTERNAL otrv4_err_t otrv4_receive_message(otrv4_response_t *response,
                                  const string_t message, otrv4_t *otr) {

  if (!message || !response)
    return ERROR;

  response->to_display = otrv4_strndup(NULL, 0);

  /* A DH-Commit sets our running version to 3 */
  if (otr->running_version == OTRV4_VERSION_NONE &&
      allow_version(otr, OTRV4_ALLOW_V3) && strstr(message, "?OTR:AAMC"))
    otr->running_version = OTRV4_VERSION_3;

  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    return otrv3_receive_message(&response->to_send, &response->to_display,
                                 &response->tlvs, message, otr->otr3_conn);
  case OTRV4_VERSION_4:
  case OTRV4_VERSION_NONE:
    return receive_message_v4_only(response, message, otr);
  }

  return SUCCESS;
}

tstatic otrv4_err_t serialize_and_encode_data_msg(
    string_t *dst, const m_mac_key_t mac_key, uint8_t *to_reveal_mac_keys,
    size_t to_reveal_mac_keys_len, const data_message_t *data_msg) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if (data_message_body_asprintf(&body, &bodylen, data_msg))
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

  shake_256_mac(ser + bodylen, MAC_KEY_BYTES, mac_key, sizeof(m_mac_key_t), ser,
                bodylen);

  serialize_bytes_array(ser + bodylen + DATA_MSG_MAC_BYTES, to_reveal_mac_keys,
                        to_reveal_mac_keys_len);

  *dst = otrl_base64_otr_encode(ser, serlen);
  free(ser);
  ser = NULL;

  return SUCCESS;
}

tstatic otrv4_err_t send_data_message(string_t *to_send, const uint8_t *message,
                                     size_t message_len, otrv4_t *otr,
                                     int isHeartbeat, unsigned char flags) {
  data_message_t *data_msg = NULL;

  size_t serlen = list_len(otr->keys->old_mac_keys) * MAC_KEY_BYTES;

  uint8_t *ser_mac_keys =
      key_manager_old_mac_keys_serialize(otr->keys->old_mac_keys);
  otr->keys->old_mac_keys = NULL;

  if (key_manager_prepare_next_chain_key(otr->keys)) {
    free(ser_mac_keys);
    ser_mac_keys = NULL;
    return ERROR;
  }

  m_enc_key_t enc_key;
  m_mac_key_t mac_key;
  memset(enc_key, 0, sizeof enc_key);
  memset(mac_key, 0, sizeof mac_key);

  if (key_manager_retrieve_sending_message_keys(enc_key, mac_key, otr->keys)) {
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

  if (isHeartbeat) {
    data_msg->flags = MSGFLAGS_IGNORE_UNREADABLE;
  }

  data_msg->sender_instance_tag = otr->our_instance_tag;
  data_msg->receiver_instance_tag = otr->their_instance_tag;

  otrv4_err_t err = ERROR;

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
  data_message_free(data_msg);

  return err;
}

tstatic otrv4_err_t serialize_tlvs(uint8_t **dst, size_t *dstlen,
                                  const tlv_t *tlvs) {
  const tlv_t *current = tlvs;
  uint8_t *cursor = NULL;

  *dst = NULL;
  *dstlen = 0;

  if (!tlvs)
    return SUCCESS;

  for (*dstlen = 0; current; current = current->next)
    *dstlen += current->len + 4;

  *dst = malloc(*dstlen);
  if (!*dst)
    return ERROR;

  cursor = *dst;
  for (current = tlvs; current; current = current->next) {
    cursor += serialize_uint16(cursor, current->type);
    cursor += serialize_uint16(cursor, current->len);
    cursor += serialize_bytes_array(cursor, current->data, current->len);
  }

  return SUCCESS;
}

tstatic otrv4_err_t append_tlvs(uint8_t **dst, size_t *dstlen,
                               const string_t message, const tlv_t *tlvs) {
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

tstatic otrv4_err_t otrv4_prepare_to_send_data_message(string_t *to_send,
                                                      const string_t message,
                                                      const tlv_t *tlvs,
                                                      otrv4_t *otr,
                                                      unsigned char flags) {
  uint8_t *msg = NULL;
  size_t msg_len = 0;

  if (otr->state == OTRV4_STATE_FINISHED)
    return ERROR; // Should restart

  if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES) {
    return STATE_NOT_ENCRYPTED; // TODO: queue message
  }

  if (append_tlvs(&msg, &msg_len, message, tlvs))
    return ERROR;

  // TODO: due to the addition of the flag to the tlvs, this will
  // make the extra sym key, the disconneted and smp, a heartbeat
  // msg as it is right now
  int is_heartbeat =
      strlen(message) == 0 && otr->smp->state == SMPSTATE_EXPECT1 ? 1 : 0;

  otrv4_err_t err =
      send_data_message(to_send, msg, msg_len, otr, is_heartbeat, flags);
  free(msg);
  msg = NULL;

  return err;
}

INTERNAL otrv4_err_t otrv4_prepare_to_send_message(string_t *to_send,
                                          const string_t message, tlv_t **tlvs,
                                          uint8_t flags, otrv4_t *otr) {
  if (!otr)
    return ERROR;

  // Optional. Client might want or not to disguise the length of
  // message

  // TODO if we need to pad, merge the padding tlv and the user's tlvs to send
  if (otr->conversation->client->pad) {
    if (append_padding_tlv(tlvs, strlen(message)))
      return ERROR;
  }

  const tlv_t *const_tlvs = NULL;
  if (tlvs)
    const_tlvs = *tlvs;

  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    return otrv3_send_message(to_send, message, const_tlvs, otr->otr3_conn);
  case OTRV4_VERSION_4:
    return otrv4_prepare_to_send_data_message(to_send, message, const_tlvs, otr,
                                              flags);
  case OTRV4_VERSION_NONE:
    return ERROR;
  }

  return SUCCESS;
}

tstatic otrv4_err_t otrv4_close_v4(string_t *to_send, otrv4_t *otr) {
  if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
    return SUCCESS;

  tlv_t *disconnected = otrv4_disconnected_tlv_new();
  if (!disconnected)
    return ERROR;

  otrv4_err_t err = otrv4_prepare_to_send_message(
      to_send, "", &disconnected, MSGFLAGS_IGNORE_UNREADABLE, otr);

  otrv4_tlv_free(disconnected);
  forget_our_keys(otr);
  otr->state = OTRV4_STATE_START;
  gone_insecure_cb_v4(otr->conversation);

  return err;
}

INTERNAL otrv4_err_t otrv4_close(string_t *to_send, otrv4_t *otr) {
  if (!otr)
    return ERROR;

  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    otrv3_close(to_send, otr->otr3_conn); // TODO: This should return an error
                                          // but errors are reported on a
                                          // callback
    gone_insecure_cb_v4(otr->conversation);  // TODO: Only if success
    return SUCCESS;
  case OTRV4_VERSION_4:
    return otrv4_close_v4(to_send, otr);
  case OTRV4_VERSION_NONE:
    return ERROR;
  }

  return ERROR;
}

tstatic otrv4_err_t otrv4_send_symkey_message_v4(string_t *to_send,
                                                unsigned int use,
                                                const unsigned char *usedata,
                                                size_t usedatalen, otrv4_t *otr,
                                                unsigned char *extra_key) {
  if (usedatalen > 0 && !usedata)
    return ERROR;

  if (otr->state == OTRV4_STATE_ENCRYPTED_MESSAGES) {
    unsigned char *tlv_data = malloc(usedatalen + 4);

    tlv_data[0] = (use >> 24) & 0xff;
    tlv_data[1] = (use >> 16) & 0xff;
    tlv_data[2] = (use >> 8) & 0xff;
    tlv_data[3] = (use)&0xff;
    if (usedatalen > 0)
      memmove(tlv_data + 4, usedata, usedatalen);

    tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_SYM_KEY, usedatalen + 4, tlv_data);
    free(tlv_data);
    tlv_data = NULL;

    memmove(extra_key, otr->keys->extra_key, HASH_BYTES);

    // TODO: in otrv3 the extra_key is passed as a param to this
    // do the same?
    if (otrv4_prepare_to_send_message(to_send, "", &tlv,
                                      MSGFLAGS_IGNORE_UNREADABLE, otr)) {
      otrv4_tlv_free(tlv);
      return ERROR;
    }
    otrv4_tlv_free(tlv);
    return SUCCESS;
  }
  return ERROR;
}

API otrv4_err_t otrv4_send_symkey_message(string_t *to_send, unsigned int use,
                                      const unsigned char *usedata,
                                      size_t usedatalen, uint8_t *extra_key,
                                      otrv4_t *otr) {
  if (!otr)
    return ERROR;

  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    otrv3_send_symkey_message(to_send, otr->otr3_conn, use, usedata, usedatalen,
                              extra_key); // TODO: This should return an error
                                          // but errors are reported on a
                                          // callback
    return SUCCESS;
  case OTRV4_VERSION_4:
    return otrv4_send_symkey_message_v4(to_send, use, usedata, usedatalen, otr,
                                        extra_key);
  case OTRV4_VERSION_NONE:
    return ERROR;
  }

  return ERROR;
}

tstatic tlv_t *otrv4_smp_initiate(const user_profile_t *initiator,
                                 const user_profile_t *responder,
                                 const string_t question, const size_t q_len,
                                 const uint8_t *secret, const size_t secretlen,
                                 uint8_t *ssid, smp_context_t smp,
                                 otr4_conversation_state_t *conversation) {

  smp_msg_1_t msg[1];
  uint8_t *to_send = NULL;
  size_t len = 0;

  otrv4_fingerprint_t our_fp, their_fp;
  otr4_serialize_fingerprint(our_fp, initiator->pub_key);
  otr4_serialize_fingerprint(their_fp, responder->pub_key);
  generate_smp_secret(&smp->secret, our_fp, their_fp, ssid, secret, secretlen);

  do {
    if (generate_smp_msg_1(msg, smp))
      continue;

    if (q_len > 0 && question) {
      msg->q_len = q_len;
      msg->question = otrv4_strdup(question);
    }

    if (smp_msg_1_asprintf(&to_send, &len, msg))
      continue;

    smp->state = SMPSTATE_EXPECT2;
    smp->progress = 25;
    handle_smp_event_cb_v4(OTRV4_SMPEVENT_IN_PROGRESS, smp->progress, question,
                        conversation);

    tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_1, len, to_send);
    if (!tlv) {
      smp_msg_1_destroy(msg);
      free(to_send);
      to_send = NULL;
      return NULL;
    }

    smp_msg_1_destroy(msg);
    free(to_send);
    to_send = NULL;
    return tlv;
  } while (0);

  smp_msg_1_destroy(msg);
  handle_smp_event_cb_v4(OTRV4_SMPEVENT_ERROR, smp->progress, smp->msg1->question,
                      conversation);

  return NULL;
}

INTERNAL otrv4_err_t otrv4_smp_start(string_t *to_send, const string_t question,
                            const size_t q_len, const uint8_t *secret,
                            const size_t secretlen, otrv4_t *otr) {
  tlv_t *smp_start_tlv = NULL;

  if (!otr)
    return ERROR;

  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    // FIXME: missing fragmentation
    return otrv3_smp_start(to_send, question, secret, secretlen,
                           otr->otr3_conn);
    break;
  case OTRV4_VERSION_4:
    if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
      return ERROR;

    smp_start_tlv = otrv4_smp_initiate(
        get_my_user_profile(otr), otr->their_profile, question, q_len, secret,
        secretlen, otr->keys->ssid, otr->smp, otr->conversation);
    if (otrv4_prepare_to_send_message(to_send, "", &smp_start_tlv,
                                      MSGFLAGS_IGNORE_UNREADABLE, otr)) {
      otrv4_tlv_free(smp_start_tlv);
      return ERROR;
    }
    otrv4_tlv_free(smp_start_tlv);
    return SUCCESS;
    break;
  case OTRV4_VERSION_NONE:
    return ERROR;
  }

  return ERROR;
}

tstatic tlv_t *otrv4_smp_provide_secret(otr4_smp_event_t *event,
                                       smp_context_t smp,
                                       const user_profile_t *our_profile,
                                       const user_profile_t *their_profile,
                                       uint8_t *ssid, const uint8_t *secret,
                                       const size_t secretlen) {
  // TODO: If state is not CONTINUE_SMP then error.
  tlv_t *smp_reply = NULL;

  otrv4_fingerprint_t our_fp, their_fp;
  otr4_serialize_fingerprint(our_fp, our_profile->pub_key);
  otr4_serialize_fingerprint(their_fp, their_profile->pub_key);
  generate_smp_secret(&smp->secret, their_fp, our_fp, ssid, secret, secretlen);

  *event = reply_with_smp_msg_2(&smp_reply, smp);

  return smp_reply;
}

tstatic otrv4_err_t smp_continue_otrv4(string_t *to_send, const uint8_t *secret,
                                      const size_t secretlen, otrv4_t *otr) {
  otrv4_err_t err = ERROR;
  tlv_t *smp_reply = NULL;

  if (!otr)
    return err;

  otr4_smp_event_t event = OTRV4_SMPEVENT_NONE;
  smp_reply = otrv4_smp_provide_secret(
      &event, otr->smp, get_my_user_profile(otr), otr->their_profile,
      otr->keys->ssid, secret, secretlen);

  if (!event)
    event = OTRV4_SMPEVENT_IN_PROGRESS;

  handle_smp_event_cb_v4(event, otr->smp->progress, otr->smp->msg1->question,
                      otr->conversation);

  // clang-format off
  if (smp_reply && otrv4_prepare_to_send_message(to_send, "", &smp_reply,
                                                 MSGFLAGS_IGNORE_UNREADABLE, otr) == SUCCESS)
    err = SUCCESS;
  // clang-format on

  otrv4_tlv_free(smp_reply);
  return err;
}

INTERNAL otrv4_err_t otrv4_smp_continue(string_t *to_send, const uint8_t *secret,
                               const size_t secretlen, otrv4_t *otr) {
  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    // FIXME: missing fragmentation
    return otrv3_smp_continue(to_send, secret, secretlen, otr->otr3_conn);
  case OTRV4_VERSION_4:
    return smp_continue_otrv4(to_send, secret, secretlen, otr);
  case OTRV4_VERSION_NONE:
    return ERROR;
  }

  return ERROR; // TODO: IMPLEMENT
}

tstatic otrv4_err_t otrv4_smp_abort_v4(string_t *to_send, otrv4_t *otr) {
  tlv_t *tlv = otrv4_tlv_new(OTRL_TLV_SMP_ABORT, 0, NULL);

  otr->smp->state = SMPSTATE_EXPECT1;
  if (otrv4_prepare_to_send_message(to_send, "", &tlv,
                                    MSGFLAGS_IGNORE_UNREADABLE, otr)) {
    otrv4_tlv_free(tlv);
    return ERROR;
  }

  otrv4_tlv_free(tlv);

  return SUCCESS;
}

API otrv4_err_t otrv4_smp_abort(string_t *to_send, otrv4_t *otr) {
  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    return otrv3_smp_abort(otr->otr3_conn);
  case OTRV4_VERSION_4:
    return otrv4_smp_abort_v4(to_send, otr);
  case OTRV4_VERSION_NONE:
    return ERROR;
  }
  return ERROR;
}

API otrv4_err_t otrv4_heartbeat_checker(string_t *to_send, otrv4_t *otr) {
  if (difftime(time(0), HEARTBEAT(otr)->last_msg_sent) >=
      HEARTBEAT(otr)->time) {
    const string_t heartbeat_msg = "";
    return otrv4_prepare_to_send_message(to_send, heartbeat_msg, NULL, 0, otr);
  }
  return SUCCESS;
}


static int otrl_initialized = 0;
API void otrv3_init(void) {
  if (otrl_initialized)
    return;

  if (otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB))
    exit(1);

  otrl_initialized = 1;
}
