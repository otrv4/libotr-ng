#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gcrypt.h"

#include "b64.h"
#include "constants.h"
#include "dake.h"
#include "data_message.h"
#include "deserialize.h"
#include "key_management.h"
#include "otrv3.h"
#include "otrv4.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"
#include "smp.c"
#include "str.h"
#include "tlv.h"

#include "debug.h"

#define OUR_ECDH(s) s->keys->our_ecdh->pub
#define OUR_DH(s) s->keys->our_dh->pub
#define THEIR_ECDH(s) s->keys->their_ecdh
#define THEIR_DH(s) s->keys->their_dh

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
static const string_t otr_header = "?OTR:";

static void create_privkey_cb(const otr4_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  // TODO: Change to receive conv->client
  conv->client->callbacks->create_privkey(conv->client->client_id);
}

static void gone_secure_cb(const otr4_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  conv->client->callbacks->gone_secure(conv);
}

static void gone_insecure_cb(const otr4_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  conv->client->callbacks->gone_insecure(conv);
}

static void fingerprint_seen_cb(const otrv4_fingerprint_t fp,
                                const otr4_conversation_state_t *conv) {
  if (!conv || !conv->client || !conv->client->callbacks)
    return;

  conv->client->callbacks->fingerprint_seen(fp, conv);
}

static void handle_smp_event_cb(const otr4_smp_event_t event,
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

static void maybe_create_keys(const otr4_conversation_state_t *conv) {
  if (!conv->client->keypair)
    create_privkey_cb(conv);
}

static int allow_version(const otrv4_t *otr, otrv4_supported_version version) {
  return (otr->supported_versions & version);
}

/* dst must be at least 3 bytes long. */
static void allowed_versions(string_t dst, const otrv4_t *otr) {
  if (allow_version(otr, OTRV4_ALLOW_V4))
    *dst++ = '4';

  if (allow_version(otr, OTRV4_ALLOW_V3))
    *dst++ = '3';

  *dst = 0;
}

static const user_profile_t *get_my_user_profile(otrv4_t *otr) {
  if (otr->profile)
    return otr->profile;

  char versions[3] = {0};
  allowed_versions(versions, otr);
  maybe_create_keys(otr->conversation);
  otr->profile =
      user_profile_build(versions, otr->conversation->client->keypair);
  return otr->profile;
}

otrv4_t *otrv4_new(otr4_client_state_t *state, otrv4_policy_t policy) {
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
  otr->our_instance_tag = otr4_client_state_get_instance_tag(state);
  otr->profile = NULL;
  otr->their_profile = NULL;

  otr->keys = malloc(sizeof(key_manager_t));
  if (!otr->keys)
    return NULL;

  key_manager_init(otr->keys);
  smp_context_init(otr->smp);

  otr->frag_ctx = fragment_context_new();
  otr->otr3_conn = NULL;

  return otr;
}

void otrv4_destroy(/*@only@ */ otrv4_t *otr) {
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

void otrv4_free(/*@only@ */ otrv4_t *otr) {
  if (otr == NULL) {
    return;
  }

  otrv4_destroy(otr);
  free(otr);
}

otr4_err_t otrv4_build_query_message(string_t *dst, const string_t message,
                                     const otrv4_t *otr) {
  // size = qm tag + versions + msg length + versions + question mark +
  // whitespace + null byte
  size_t qm_size = QUERY_MESSAGE_TAG_BYTES + 3 + strlen(message) + 2 + 1;
  string_t buff = NULL;
  char allowed[3] = {0};

  *dst = NULL;
  allowed_versions(allowed, otr);

  buff = malloc(qm_size);
  if (!buff)
    return OTR4_ERROR;

  char *cursor = stpcpy(buff, query_header);
  cursor = stpcpy(cursor, allowed);
  cursor = stpcpy(cursor, "? ");

  int rem = cursor - buff;
  if (*stpncpy(cursor, message, qm_size - rem)) {
    free(buff);
    return OTR4_ERROR; // could not zero-terminate the string
  }

  *dst = buff;
  return OTR4_SUCCESS;
}

otr4_err_t otrv4_build_whitespace_tag(string_t *whitespace_tag,
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
    return OTR4_ERROR;

  cursor = stpcpy(buff, tag_base);

  if (allows_v4)
    cursor = stpcpy(cursor, tag_version_v4);

  if (allows_v3)
    cursor = stpcpy(cursor, tag_version_v3);

  if (*stpncpy(cursor, message, m_size - strlen(buff))) {
    free(buff);
    return OTR4_ERROR;
  }

  *whitespace_tag = buff;
  return OTR4_SUCCESS;
}

static bool message_contains_tag(const string_t message) {
  return strstr(message, tag_base) != NULL;
}

static void set_to_display(otrv4_response_t *response, const string_t message) {
  size_t msg_len = strlen(message);
  response->to_display = otrv4_strndup(message, msg_len);
}

static otr4_err_t message_to_display_without_tag(otrv4_response_t *response,
                                                 const string_t message,
                                                 const char *tag_version,
                                                 size_t msg_len) {
  size_t tag_length = WHITESPACE_TAG_BASE_BYTES + WHITESPACE_TAG_VERSION_BYTES;
  size_t chars = msg_len - tag_length;

  if (msg_len < tag_length) {
    return OTR4_ERROR;
  }

  string_t buff = malloc(chars + 1);
  if (buff == NULL) {
    return OTR4_ERROR;
  }

  char *found_at = strstr(message, tag_base);
  if (!found_at) {
    return OTR4_ERROR;
  }
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

  return OTR4_SUCCESS;
}

static void set_running_version_from_tag(otrv4_t *otr, const string_t message) {
  if (allow_version(otr, OTRV4_ALLOW_V4) && strstr(message, tag_version_v4)) {
    otr->running_version = OTRV4_VERSION_4;
    return;
  }

  if (allow_version(otr, OTRV4_ALLOW_V3) && strstr(message, tag_version_v3)) {
    otr->running_version = OTRV4_VERSION_3;
    return;
  }
}

static bool message_is_query(const string_t message) {
  return strstr(message, query_header) != NULL;
}

static void set_running_version_from_query_msg(otrv4_t *otr,
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

static bool message_is_otr_encoded(const string_t message) {
  return strstr(message, otr_header) != NULL;
}

otrv4_response_t *otrv4_response_new(void) {
  otrv4_response_t *response = malloc(sizeof(otrv4_response_t));
  if (!response)
    return NULL;

  response->to_display = NULL;
  response->to_send = NULL;
  response->warning = OTRV4_WARN_NONE;
  response->tlvs = NULL;

  return response;
}

void otrv4_response_free(otrv4_response_t *response) {
  if (!response)
    return;

  free(response->to_display);
  response->to_display = NULL;

  free(response->to_send);
  response->to_send = NULL;

  otrv4_tlv_free(response->tlvs);
  response->tlvs = NULL;

  free(response);
  response = NULL;
}

// TODO: Is not receiving a plaintext a problem?
static void receive_plaintext(otrv4_response_t *response,
                              const string_t message, const otrv4_t *otr) {
  set_to_display(response, message);

  if (otr->state != OTRV4_STATE_START)
    response->warning = OTRV4_WARN_RECEIVED_UNENCRYPTED;
}

static otr4_err_t
serialize_and_encode_identity_message(string_t *dst,
                                      const dake_identity_message_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (dake_identity_message_asprintf(&buff, &len, m))
    return OTR4_ERROR;

  *dst = otrl_base64_otr_encode(buff, len);
  free(buff);
  return OTR4_SUCCESS;
}

static otr4_err_t reply_with_identity_msg(otrv4_response_t *response,
                                          otrv4_t *otr) {
  dake_identity_message_t *m = NULL;
  otr4_err_t err = OTR4_ERROR;

  m = dake_identity_message_new(get_my_user_profile(otr));
  if (!m)
    return err;

  m->sender_instance_tag = otr->our_instance_tag;
  m->receiver_instance_tag = otr->their_instance_tag;

  ec_point_copy(m->Y, OUR_ECDH(otr));
  m->B = dh_mpi_copy(OUR_DH(otr));

  if (serialize_and_encode_identity_message(&response->to_send, m)) {
    dake_identity_message_free(m);
    return err;
  }

  err = OTR4_SUCCESS;
  dake_identity_message_free(m);

  return err;
}

static otr4_err_t start_dake(otrv4_response_t *response, otrv4_t *otr) {
  if (key_manager_generate_ephemeral_keys(otr->keys))
    return OTR4_ERROR;

  otr->state = OTRV4_STATE_WAITING_AUTH_R;
  maybe_create_keys(otr->conversation);
  return reply_with_identity_msg(response, otr);
}

static otr4_err_t receive_tagged_plaintext(otrv4_response_t *response,
                                           const string_t message,
                                           otrv4_t *otr) {
  set_running_version_from_tag(otr, message);

  switch (otr->running_version) {
  case OTRV4_VERSION_4:
    if (message_to_display_without_tag(response, message, tag_version_v4,
                                       strlen(message))) {
      return OTR4_ERROR;
    }
    dh_priv_key_destroy(otr->keys->our_dh);
    return start_dake(response, otr);
    break;
  case OTRV4_VERSION_3:
    return otrv3_receive_message(&response->to_send, &response->to_display,
                                 &response->tlvs, message, otr->otr3_conn);
    break;
  case OTRV4_VERSION_NONE:
    // ignore
    return OTR4_SUCCESS;
  }

  return OTR4_ERROR;
}

static otr4_err_t receive_query_message(otrv4_response_t *response,
                                        const string_t message, otrv4_t *otr) {
  set_running_version_from_query_msg(otr, message);

  switch (otr->running_version) {
  case OTRV4_VERSION_4:
    return start_dake(response, otr);
    break;
  case OTRV4_VERSION_3:
    return otrv3_receive_message(&response->to_send, &response->to_display,
                                 &response->tlvs, message, otr->otr3_conn);
    break;
  case OTRV4_VERSION_NONE:
    // ignore
    return OTR4_SUCCESS;
  }

  return OTR4_ERROR;
}

otr4_err_t extract_header(otrv4_header_t *dst, const uint8_t *buffer,
                          const size_t bufflen) {
  if (bufflen == 0) {
    return OTR4_ERROR;
  }

  size_t read = 0;
  uint16_t version = 0;
  uint8_t type = 0;
  if (deserialize_uint16(&version, buffer, bufflen, &read)) {
    return OTR4_ERROR;
  }

  buffer += read;

  if (deserialize_uint8(&type, buffer, bufflen - read, &read)) {
    return OTR4_ERROR;
  }

  dst->version = OTRV4_ALLOW_NONE;
  if (version == 0x04) {
    dst->version = OTRV4_ALLOW_V4;
  } else if (version == 0x03) {
    dst->version = OTRV4_ALLOW_V3;
  }
  dst->type = type;

  return OTR4_SUCCESS;
}

static otr4_err_t double_ratcheting_init(int j, otrv4_t *otr) {
  if (key_manager_ratcheting_init(j, otr->keys))
    return OTR4_ERROR;

  otr->state = OTRV4_STATE_ENCRYPTED_MESSAGES;
  gone_secure_cb(otr->conversation);

  return OTR4_SUCCESS;
}

static otr4_err_t build_auth_message(uint8_t **msg, size_t *msg_len,
                                     const uint8_t type,
                                     const user_profile_t *i_profile,
                                     const user_profile_t *r_profile,
                                     const ec_point_t i_ecdh,
                                     const ec_point_t r_ecdh,
                                     const dh_mpi_t i_dh, const dh_mpi_t r_dh) {
  uint8_t *ser_i_profile = NULL, *ser_r_profile = NULL;
  size_t ser_i_profile_len, ser_r_profile_len = 0;
  uint8_t ser_i_ecdh[ED448_POINT_BYTES], ser_r_ecdh[ED448_POINT_BYTES];

  if (serialize_ec_point(ser_i_ecdh, i_ecdh)) {
    return OTR4_ERROR;
  }
  if (serialize_ec_point(ser_r_ecdh, r_ecdh)) {
    return OTR4_ERROR;
  }

  uint8_t ser_i_dh[DH3072_MOD_LEN_BYTES], ser_r_dh[DH3072_MOD_LEN_BYTES];
  size_t ser_i_dh_len = 0, ser_r_dh_len = 0;

  if (serialize_dh_public_key(ser_i_dh, &ser_i_dh_len, i_dh)) {
    return OTR4_ERROR;
  }
  if (serialize_dh_public_key(ser_r_dh, &ser_r_dh_len, r_dh)) {
    return OTR4_ERROR;
  }

  otr4_err_t err = OTR4_ERROR;

  do {
    if (user_profile_asprintf(&ser_i_profile, &ser_i_profile_len, i_profile))
      continue;

    if (user_profile_asprintf(&ser_r_profile, &ser_r_profile_len, r_profile))
      continue;

    uint8_t hash_ser_i_profile[HASH_BYTES];
    decaf_shake256_ctx_t hd_i;
    hash_init_with_dom(hd_i);
    hash_update(hd_i, ser_i_profile, ser_i_profile_len);

    hash_final(hd_i, hash_ser_i_profile, sizeof(hash_ser_i_profile));
    hash_destroy(hd_i);

    uint8_t hash_ser_r_profile[HASH_BYTES];
    decaf_shake256_ctx_t hd_r;
    hash_init_with_dom(hd_r);
    hash_update(hd_r, ser_r_profile, ser_r_profile_len);

    hash_final(hd_r, hash_ser_r_profile, sizeof(hash_ser_r_profile));
    hash_destroy(hd_r);

    size_t len = 1 + 2 * ED448_POINT_BYTES + HASH_BYTES + HASH_BYTES +
                 ser_i_dh_len + ser_r_dh_len;

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

    *msg = buff;
    *msg_len = len;
    err = OTR4_SUCCESS;
  } while (0);

  free(ser_i_profile);
  free(ser_r_profile);

  sodium_memzero(ser_i_ecdh, ED448_POINT_BYTES);
  sodium_memzero(ser_r_ecdh, ED448_POINT_BYTES);
  sodium_memzero(ser_i_dh, DH3072_MOD_LEN_BYTES);
  sodium_memzero(ser_r_dh, DH3072_MOD_LEN_BYTES);

  return err;
}

static otr4_err_t serialize_and_encode_auth_r(string_t *dst,
                                              const dake_auth_r_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (dake_auth_r_asprintf(&buff, &len, m))
    return OTR4_ERROR;

  *dst = otrl_base64_otr_encode(buff, len);
  free(buff);
  return OTR4_SUCCESS;
}

static otr4_err_t reply_with_auth_r_msg(string_t *dst, otrv4_t *otr) {
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
                         OUR_ECDH(otr), THEIR_DH(otr), OUR_DH(otr)))
    return OTR4_ERROR;

  /* sigma = Auth(g^R, R, {g^I, g^R, g^i}, msg) */
  otr4_err_t err = snizkpk_authenticate(
      msg->sigma, otr->conversation->client->keypair, /* g^R and R */
      otr->their_profile->pub_key,                    /* g^I */
      THEIR_ECDH(otr),                                /* g^i -- Y */
      t, t_len);

  if (err) {
    free(t);
    t = NULL;
    dake_auth_r_destroy(msg);
    return OTR4_ERROR;
  }

  free(t);
  t = NULL;
  err = serialize_and_encode_auth_r(dst, msg);
  dake_auth_r_destroy(msg);
  return err;
}

static otr4_err_t receive_identity_message_on_state_start(
    string_t *dst, dake_identity_message_t *identity_message, otrv4_t *otr) {
  if (!valid_dake_identity_message(identity_message))
    return OTR4_ERROR;

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile)
    return OTR4_ERROR;

  key_manager_set_their_ecdh(identity_message->Y, otr->keys);
  key_manager_set_their_dh(identity_message->B, otr->keys);
  user_profile_copy(otr->their_profile, identity_message->profile);

  if (key_manager_generate_ephemeral_keys(otr->keys))
    return OTR4_ERROR;

  if (reply_with_auth_r_msg(dst, otr))
    return OTR4_ERROR;

  otr->state = OTRV4_STATE_WAITING_AUTH_I;
  return OTR4_SUCCESS;
}

static void forget_our_keys(otrv4_t *otr) {
  key_manager_destroy(otr->keys);
  key_manager_init(otr->keys);
}

static otr4_err_t receive_identity_message_on_waiting_auth_r(
    string_t *dst, dake_identity_message_t *msg, otrv4_t *otr) {
  /* Compare X with their_ecdh */
  gcry_mpi_t x = NULL;
  gcry_mpi_t y = NULL;
  int err = 0;

  err |= gcry_mpi_scan(&x, GCRYMPI_FMT_USG, OUR_ECDH(otr),
                       sizeof(ec_public_key_t), NULL);

  err |=
      gcry_mpi_scan(&y, GCRYMPI_FMT_USG, msg->Y, sizeof(ec_public_key_t), NULL);

  if (err) {
    gcry_mpi_release(x);
    gcry_mpi_release(y);
    return OTR4_ERROR;
  }

  int cmp = gcry_mpi_cmp(x, y);
  gcry_mpi_release(x);
  gcry_mpi_release(y);

  /* If our is lower, ignore. */
  if (cmp < 0) {
    return OTR4_SUCCESS;
  } // ignore

  forget_our_keys(otr);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

static otr4_err_t receive_identity_message_on_waiting_auth_i(
    string_t *dst, dake_identity_message_t *msg, otrv4_t *otr) {
  user_profile_free(otr->their_profile);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

static void received_instance_tag(uint32_t their_instance_tag, otrv4_t *otr) {
  // TODO: should we do any additional check?
  otr->their_instance_tag = their_instance_tag;
}

static otr4_err_t receive_identity_message(string_t *dst, const uint8_t *buff,
                                           size_t buflen, otrv4_t *otr) {
  otr4_err_t err = OTR4_ERROR;
  dake_identity_message_t m[1];

  if (dake_identity_message_deserialize(m, buff, buflen))
    return err;

  if (m->receiver_instance_tag != 0) {
    dake_identity_message_destroy(m);
    return OTR4_SUCCESS;
  }

  received_instance_tag(m->sender_instance_tag, otr);

  if (!valid_received_values(m->Y, m->B, m->profile)) {
    dake_identity_message_destroy(m);
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
    // Ignore the message, but it is not an error.
    err = OTR4_SUCCESS;
  }

  dake_identity_message_destroy(m);
  return err;
}

static otr4_err_t serialize_and_encode_auth_i(string_t *dst,
                                              const dake_auth_i_t *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (dake_auth_i_asprintf(&buff, &len, m))
    return OTR4_ERROR;

  *dst = otrl_base64_otr_encode(buff, len);
  free(buff);
  return OTR4_SUCCESS;
}

static otr4_err_t reply_with_auth_i_msg(string_t *dst,
                                        const user_profile_t *their,
                                        otrv4_t *otr) {
  dake_auth_i_t msg[1];
  msg->sender_instance_tag = otr->our_instance_tag;
  msg->receiver_instance_tag = otr->their_instance_tag;

  unsigned char *t = NULL;
  size_t t_len = 0;
  if (build_auth_message(&t, &t_len, 1, get_my_user_profile(otr), their,
                         OUR_ECDH(otr), THEIR_ECDH(otr), OUR_DH(otr),
                         THEIR_DH(otr)))
    return OTR4_ERROR;

  otr4_err_t err =
      snizkpk_authenticate(msg->sigma, otr->conversation->client->keypair,
                           their->pub_key, THEIR_ECDH(otr), t, t_len);
  free(t);
  t = NULL;

  if (err == OTR4_ERROR)
    return err;

  err = serialize_and_encode_auth_i(dst, msg);
  dake_auth_i_destroy(msg);
  return err;
}

static bool valid_auth_r_message(const dake_auth_r_t *auth, otrv4_t *otr) {
  uint8_t *t = NULL;
  size_t t_len = 0;

  if (!valid_received_values(auth->X, auth->A, auth->profile))
    return false;

  if (build_auth_message(&t, &t_len, 0, get_my_user_profile(otr), auth->profile,
                         OUR_ECDH(otr), auth->X, OUR_DH(otr), auth->A))
    return false;

  /* Verif({g^I, g^R, g^i}, sigma, msg) */
  otr4_err_t err =
      snizkpk_verify(auth->sigma, auth->profile->pub_key,     /* g^R */
                     otr->conversation->client->keypair->pub, /* g^I */
                     OUR_ECDH(otr),                           /* g^  */
                     t, t_len);

  free(t);
  t = NULL;

  return err == OTR4_SUCCESS;
}

static otr4_err_t receive_auth_r(string_t *dst, const uint8_t *buff,
                                 size_t buff_len, otrv4_t *otr) {
  if (otr->state != OTRV4_STATE_WAITING_AUTH_R)
    return OTR4_SUCCESS; // ignore the message

  dake_auth_r_t auth[1];
  if (dake_auth_r_deserialize(auth, buff, buff_len))
    return OTR4_ERROR;

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    dake_auth_r_destroy(auth);
    return OTR4_SUCCESS;
  }

  received_instance_tag(auth->sender_instance_tag, otr);

  if (!valid_auth_r_message(auth, otr)) {
    dake_auth_r_destroy(auth);
    return OTR4_ERROR;
  }

  otr->their_profile = malloc(sizeof(user_profile_t));
  if (!otr->their_profile) {
    dake_auth_r_destroy(auth);
    return OTR4_ERROR;
  }

  key_manager_set_their_ecdh(auth->X, otr->keys);
  key_manager_set_their_dh(auth->A, otr->keys);
  user_profile_copy(otr->their_profile, auth->profile);

  if (reply_with_auth_i_msg(dst, otr->their_profile, otr)) {
    dake_auth_r_destroy(auth);
    return OTR4_ERROR;
  }

  dake_auth_r_destroy(auth);

  otrv4_fingerprint_t fp;
  if (!otr4_serialize_fingerprint(fp, otr->their_profile->pub_key))
    fingerprint_seen_cb(fp, otr->conversation);

  return double_ratcheting_init(0, otr);
}

static bool valid_auth_i_message(const dake_auth_i_t *auth, otrv4_t *otr) {
  uint8_t *t = NULL;
  size_t t_len = 0;

  if (build_auth_message(&t, &t_len, 1, otr->their_profile,
                         get_my_user_profile(otr), THEIR_ECDH(otr),
                         OUR_ECDH(otr), THEIR_DH(otr), OUR_DH(otr)))
    return false;

  otr4_err_t err = snizkpk_verify(auth->sigma, otr->their_profile->pub_key,
                                  otr->conversation->client->keypair->pub,
                                  OUR_ECDH(otr), t, t_len);
  free(t);
  t = NULL;

  return err == OTR4_SUCCESS;
}

static otr4_err_t receive_auth_i(string_t *dst, const uint8_t *buff,
                                 size_t buff_len, otrv4_t *otr) {
  if (otr->state != OTRV4_STATE_WAITING_AUTH_I)
    return OTR4_SUCCESS; // Ignore the message

  dake_auth_i_t auth[1];
  if (dake_auth_i_deserialize(auth, buff, buff_len))
    return OTR4_ERROR;

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    dake_auth_i_destroy(auth);
    return OTR4_SUCCESS;
  }

  if (!valid_auth_i_message(auth, otr)) {
    dake_auth_i_destroy(auth);
    return OTR4_ERROR;
  }

  dake_auth_i_destroy(auth);

  otrv4_fingerprint_t fp;
  if (!otr4_serialize_fingerprint(fp, otr->their_profile->pub_key))
    fingerprint_seen_cb(fp, otr->conversation);

  return double_ratcheting_init(1, otr);
}

static void extract_tlvs(tlv_t **tlvs, const uint8_t *src, size_t len) {
  if (!tlvs)
    return;

  uint8_t *tlvs_start = memchr(src, 0, len);
  if (!tlvs_start)
    return;

  size_t tlvs_len = len - (tlvs_start + 1 - src);
  *tlvs = otrv4_parse_tlvs(tlvs_start + 1, tlvs_len);
}

static otr4_err_t decrypt_data_msg(otrv4_response_t *response,
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
    return OTR4_ERROR;

  int err = crypto_stream_xor(plain, msg->enc_msg, msg->enc_msg_len, msg->nonce,
                              enc_key);

  if (strnlen((string_t)plain, msg->enc_msg_len))
    *dst = otrv4_strndup((char *)plain, msg->enc_msg_len);

  extract_tlvs(tlvs, plain, msg->enc_msg_len);

  free(plain);

  if (err == 0) {
    return OTR4_SUCCESS;
  }

  // TODO: correctly free
  otrv4_tlv_free(*tlvs);
  return OTR4_ERROR;
}

static tlv_t *otrv4_process_smp(otr4_smp_event_t event, smp_context_t smp,
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
    event = OTRV4_SMPEVENT_ABORT;

    break;
  case OTRV4_TLV_NONE:
  case OTRV4_TLV_PADDING:
  case OTRV4_TLV_DISCONNECTED:
    // Ignore. They should not be passed to this function.
    break;
  }

  if (!event)
    event = OTRV4_SMPEVENT_IN_PROGRESS;

  return to_send;
}

static tlv_t *process_tlv(const tlv_t *tlv, otrv4_t *otr) {
  if (tlv->type == OTRV4_TLV_NONE) {
    return NULL;
  }

  if (tlv->type == OTRV4_TLV_PADDING) {
    return NULL;
  }

  if (tlv->type == OTRV4_TLV_DISCONNECTED) {
    forget_our_keys(otr);
    otr->state = OTRV4_STATE_FINISHED;
    gone_insecure_cb(otr->conversation);
    return NULL;
  }

  otr4_smp_event_t event = OTRV4_SMPEVENT_NONE;
  tlv_t *out = otrv4_process_smp(event, otr->smp, tlv);
  handle_smp_event_cb(event, otr->smp->progress,
                      otr->smp->msg1 ? otr->smp->msg1->question : NULL,
                      otr->conversation);

  return out;
}

static otr4_err_t receive_tlvs(tlv_t **to_send, otrv4_response_t *response,
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
  return OTR4_SUCCESS;
}

static otr4_err_t get_receiving_msg_keys(m_enc_key_t enc_key,
                                         m_mac_key_t mac_key,
                                         const data_message_t *msg,
                                         otrv4_t *otr) {
  if (!key_manager_ensure_on_ratchet(otr->keys))
    return OTR4_ERROR;

  if (key_manager_retrieve_receiving_message_keys(enc_key, mac_key,
                                                  msg->message_id, otr->keys))
    return OTR4_ERROR;
  return OTR4_SUCCESS;
}

static otr4_err_t otrv4_receive_data_message(otrv4_response_t *response,
                                             const uint8_t *buff, size_t buflen,
                                             otrv4_t *otr) {
  data_message_t *msg = data_message_new();
  m_enc_key_t enc_key;
  m_mac_key_t mac_key;

  memset(enc_key, 0, sizeof(m_enc_key_t));
  memset(mac_key, 0, sizeof(m_mac_key_t));

  uint8_t *to_store_mac = malloc(MAC_KEY_BYTES);
  if (to_store_mac == NULL) {
    data_message_free(msg);
    return OTR4_ERROR;
  }

  // TODO: warn the user and send an error message with a code.
  if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES) {
    data_message_free(msg);
    free(to_store_mac);
    return OTR4_ERROR;
  }

  if (data_message_deserialize(msg, buff, buflen)) {
    data_message_free(msg);
    free(to_store_mac);
    return OTR4_ERROR;
  }

  key_manager_set_their_keys(msg->ecdh, msg->dh, otr->keys);

  tlv_t *reply_tlv = NULL;

  do {
    if (msg->receiver_instance_tag != otr->our_instance_tag) {
      response->to_display = NULL;
      data_message_free(msg);
      free(to_store_mac);

      return OTR4_SUCCESS;
    }

    if (get_receiving_msg_keys(enc_key, mac_key, msg, otr))
      continue;

    if (!valid_data_message(mac_key, msg))
      continue;

    if (decrypt_data_msg(response, enc_key, msg))
      continue;

    // TODO: Securely delete receiving chain keys older than message_id-1.

    if (receive_tlvs(&reply_tlv, response, otr))
      continue;

    key_manager_prepare_to_ratchet(otr->keys);

    if (reply_tlv)
      if (otrv4_prepare_to_send_message(&response->to_send, "", reply_tlv, otr))
        continue;

    memcpy(to_store_mac, mac_key, MAC_KEY_BYTES);
    otr->keys->old_mac_keys = list_add(to_store_mac, otr->keys->old_mac_keys);

    sodium_memzero(enc_key, sizeof(enc_key));
    sodium_memzero(mac_key, sizeof(mac_key));
    otrv4_tlv_free(reply_tlv);
    data_message_free(msg);

    return OTR4_SUCCESS;
  } while (0);

  free(to_store_mac);
  to_store_mac = NULL;

  data_message_free(msg);
  otrv4_tlv_free(reply_tlv);

  return OTR4_ERROR;
}

static otr4_err_t receive_decoded_message(otrv4_response_t *response,
                                          const uint8_t *decoded,
                                          size_t dec_len, otrv4_t *otr) {
  otrv4_header_t header;
  if (extract_header(&header, decoded, dec_len))
    return OTR4_ERROR;

  if (!allow_version(otr, header.version))
    return OTR4_ERROR;

  // TODO: Why the version in the header is a ALLOWED VERSION?
  // This is the message version, not the version the protocol allows
  if (header.version != OTRV4_ALLOW_V4)
    return OTR4_ERROR;

  // TODO: how to prevent version rollback?
  maybe_create_keys(otr->conversation);

  response->to_send = NULL;
  otr4_err_t err;

  switch (header.type) {
  case OTR_IDENTITY_MSG_TYPE:
    otr->running_version = OTRV4_VERSION_4;
    return receive_identity_message(&response->to_send, decoded, dec_len, otr);
  case OTR_AUTH_R_MSG_TYPE:
    err = receive_auth_r(&response->to_send, decoded, dec_len, otr);
    if (otr->state == OTRV4_STATE_ENCRYPTED_MESSAGES) {
      dh_priv_key_destroy(otr->keys->our_dh);
    }
    return err;
  case OTR_AUTH_I_MSG_TYPE:
    return receive_auth_i(&response->to_send, decoded, dec_len, otr);
  case OTR_DATA_MSG_TYPE:
    return otrv4_receive_data_message(response, decoded, dec_len, otr);
  default:
    // errror. bad message type
    return OTR4_ERROR;
  }

  return OTR4_ERROR;
}

static otr4_err_t receive_encoded_message(otrv4_response_t *response,
                                          const string_t message,
                                          otrv4_t *otr) {
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  if (otrl_base64_otr_decode(message, &decoded, &dec_len))
    return OTR4_ERROR;

  otr4_err_t err = receive_decoded_message(response, decoded, dec_len, otr);
  free(decoded);

  return err;
}

otrv4_in_message_type_t get_message_type(const string_t message) {
  if (message_contains_tag(message)) {
    return IN_MSG_TAGGED_PLAINTEXT;
  } else if (message_is_query(message)) {
    return IN_MSG_QUERY_STRING;
  } else if (message_is_otr_encoded(message)) {
    return IN_MSG_OTR_ENCODED;
  }

  return IN_MSG_PLAINTEXT;
}

static otr4_err_t receive_message_v4_only(otrv4_response_t *response,
                                          const string_t message,
                                          otrv4_t *otr) {
  switch (get_message_type(message)) {
  case IN_MSG_NONE:
    return OTR4_ERROR;
  case IN_MSG_PLAINTEXT:
    receive_plaintext(response, message, otr);
    return OTR4_SUCCESS;
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
  }

  return OTR4_SUCCESS;
}

/* Receive a possibly OTR message. */
otr4_err_t otrv4_receive_message(otrv4_response_t *response,
                                 const string_t message, otrv4_t *otr) {
  if (!message || !response)
    return OTR4_ERROR;

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

  return OTR4_SUCCESS;
}

static data_message_t *generate_data_msg(const otrv4_t *otr) {
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

static otr4_err_t encrypt_data_message(data_message_t *data_msg,
                                       const uint8_t *message,
                                       size_t message_len,
                                       const m_enc_key_t enc_key) {
  int err = 0;
  uint8_t *c = NULL;

  random_bytes(data_msg->nonce, sizeof(data_msg->nonce));

  c = malloc(message_len);
  if (!c)
    return OTR4_ERROR;

  // TODO: message is an UTF-8 string. Is there any problem to cast
  // it to (unsigned char *)
  err = crypto_stream_xor(c, message, message_len, data_msg->nonce, enc_key);
  if (err) {
    free(c);
    return OTR4_ERROR;
  }

  data_msg->enc_msg_len = message_len;

  data_msg->enc_msg = malloc(data_msg->enc_msg_len);
  if (!data_msg->enc_msg)
    return OTR4_ERROR;

  data_msg->enc_msg = c;

#ifdef DEBUG
  printf("nonce = ");
  otrv4_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
  printf("msg = ");
  otrv4_memdump(message, message_len);
  printf("cipher = ");
  otrv4_memdump(c, message_len);
#endif

  return OTR4_SUCCESS;
}

static otr4_err_t serialize_and_encode_data_msg(
    string_t *dst, const m_mac_key_t mac_key, uint8_t *to_reveal_mac_keys,
    size_t to_reveal_mac_keys_len, const data_message_t *data_msg) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if (data_message_body_asprintf(&body, &bodylen, data_msg))
    return OTR4_ERROR;

  size_t serlen = bodylen + MAC_KEY_BYTES + to_reveal_mac_keys_len;
  uint8_t *ser = malloc(serlen);
  if (!ser) {
    free(body);
    return OTR4_ERROR;
  }

  memcpy(ser, body, bodylen);
  free(body);

  shake_256_mac(ser + bodylen, MAC_KEY_BYTES, mac_key, sizeof(m_mac_key_t), ser,
                bodylen);

  serialize_bytes_array(ser + bodylen + DATA_MSG_MAC_BYTES, to_reveal_mac_keys,
                        to_reveal_mac_keys_len);

  *dst = otrl_base64_otr_encode(ser, serlen);
  free(ser);

  return OTR4_SUCCESS;
}

static otr4_err_t send_data_message(string_t *to_send, const uint8_t *message,
                                    size_t message_len, otrv4_t *otr) {
  data_message_t *data_msg = NULL;


  size_t serlen = list_len(otr->keys->old_mac_keys) * MAC_KEY_BYTES;

  uint8_t *ser_mac_keys =
      key_manager_old_mac_keys_serialize(otr->keys->old_mac_keys);
  otr->keys->old_mac_keys = NULL;

  if (key_manager_prepare_next_chain_key(otr->keys)) {
    free(ser_mac_keys);
    return OTR4_ERROR;
  }

  m_enc_key_t enc_key;
  m_mac_key_t mac_key;
  memset(enc_key, 0, sizeof(m_enc_key_t));
  memset(mac_key, 0, sizeof(m_mac_key_t));

  if (key_manager_retrieve_sending_message_keys(enc_key, mac_key, otr->keys)) {
    free(ser_mac_keys);
    sodium_memzero(enc_key, sizeof(m_enc_key_t));
    sodium_memzero(mac_key, sizeof(m_mac_key_t));
    return OTR4_ERROR;
  }

  data_msg = generate_data_msg(otr);
  if (!data_msg) {
    sodium_memzero(enc_key, sizeof(m_enc_key_t));
    sodium_memzero(mac_key, sizeof(m_mac_key_t));
    free(ser_mac_keys);
    return OTR4_ERROR;
  }

  data_msg->sender_instance_tag = otr->our_instance_tag;
  data_msg->receiver_instance_tag = otr->their_instance_tag;

  otr4_err_t err = OTR4_ERROR;
  if (encrypt_data_message(data_msg, message, message_len, enc_key) ==
          OTR4_SUCCESS &&
      serialize_and_encode_data_msg(to_send, mac_key, ser_mac_keys, serlen,
                                    data_msg) == OTR4_SUCCESS) {
    // TODO: Change the spec to say this should be incremented after the message
    // is sent.
    otr->keys->j++;
    err = OTR4_SUCCESS;
  }

  sodium_memzero(enc_key, sizeof(m_enc_key_t));
  sodium_memzero(mac_key, sizeof(m_mac_key_t));
  free(ser_mac_keys);
  data_message_free(data_msg);

  return err;
}

static otr4_err_t serialize_tlvs(uint8_t **dst, size_t *dstlen,
                                  const tlv_t *tlvs) {
  const tlv_t *current = tlvs;
  uint8_t *cursor = NULL;

  *dst = NULL;
  *dstlen = 0;

  if (!tlvs)
    return OTR4_SUCCESS;

  for (*dstlen = 0; current; current = current->next)
    *dstlen += current->len + 4;

  *dst = malloc(*dstlen);
  if (!*dst)
    return OTR4_ERROR;

  cursor = *dst;
  for (current = tlvs; current; current = current->next) {
    cursor += serialize_uint16(cursor, current->type);
    cursor += serialize_uint16(cursor, current->len);
    cursor += serialize_bytes_array(cursor, current->data, current->len);
  }

  return OTR4_SUCCESS;
}

static otr4_err_t append_tlvs(uint8_t **dst, size_t *dstlen,
                              const string_t message, const tlv_t *tlvs) {
  uint8_t *ser = NULL;
  size_t len = 0;

  if (serialize_tlvs(&ser, &len, tlvs))
    return OTR4_ERROR;

  *dstlen = strlen(message) + 1 + len;
  *dst = malloc(*dstlen);
  if (!*dst) {
    free(ser);
    return OTR4_ERROR;
  }

  memcpy(stpcpy((char *)*dst, message) + 1, ser, len);

  free(ser);
  return OTR4_SUCCESS;
}

static otr4_err_t otrv4_prepare_to_send_data_message(string_t *to_send,
                                                     const string_t message,
                                                     tlv_t *tlvs,
                                                     otrv4_t *otr) {
  uint8_t *msg = NULL;
  size_t msg_len = 0;

  if (otr->state == OTRV4_STATE_FINISHED)
    return OTR4_ERROR; // Should restart

  if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
    return OTR4_STATE_NOT_ENCRYPTED; // TODO: queue message

  if (append_tlvs(&msg, &msg_len, message, tlvs))
    return OTR4_ERROR;

  otr4_err_t err = send_data_message(to_send, msg, msg_len, otr);
  free(msg);

  return err;
}

otr4_err_t otrv4_prepare_to_send_message(string_t *to_send,
                                         const string_t message, tlv_t *tlvs,
                                         otrv4_t *otr) {
  if (!otr)
    return OTR4_ERROR;

  append_padding_tlv(tlvs, strlen(message));

  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    return otrv3_send_message(to_send, message, tlvs, otr->otr3_conn);
  case OTRV4_VERSION_4:
    return otrv4_prepare_to_send_data_message(to_send, message, tlvs, otr);
  case OTRV4_VERSION_NONE:
    return OTR4_ERROR;
  }

  return OTR4_SUCCESS;
}

static otr4_err_t otrv4_close_v4(string_t *to_send, otrv4_t *otr) {
  if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
    return OTR4_SUCCESS;

  tlv_t *disconnected = otrv4_disconnected_tlv_new();
  if (!disconnected)
    return OTR4_ERROR;

  otr4_err_t err =
      otrv4_prepare_to_send_message(to_send, "", disconnected, otr);
  otrv4_tlv_free(disconnected);

  forget_our_keys(otr);
  otr->state = OTRV4_STATE_START;
  gone_insecure_cb(otr->conversation);

  return err;
}

otr4_err_t otrv4_close(string_t *to_send, otrv4_t *otr) {
  if (!otr)
    return OTR4_ERROR;

  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    otrv3_close(to_send, otr->otr3_conn); // TODO: This should return an error
                                          // but errors are reported on a
                                          // callback
    gone_insecure_cb(otr->conversation);  // TODO: Only if success
    return OTR4_SUCCESS;
  case OTRV4_VERSION_4:
    return otrv4_close_v4(to_send, otr);
  case OTRV4_VERSION_NONE:
    return OTR4_ERROR;
  }

  return OTR4_ERROR;
}

static tlv_t *otrv4_smp_initiate(const user_profile_t *initiator,
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
    handle_smp_event_cb(OTRV4_SMPEVENT_IN_PROGRESS, smp->progress, question,
                        conversation);

    tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_1, len, to_send);
    smp_msg_1_destroy(msg);
    free(to_send);
    return tlv;
  } while (0);

  smp_msg_1_destroy(msg);
  handle_smp_event_cb(OTRV4_SMPEVENT_ERROR, smp->progress, smp->msg1->question,
                      conversation);
  return NULL;
}

otr4_err_t otrv4_smp_start(string_t *to_send, const string_t question,
                           const size_t q_len, const uint8_t *secret,
                           const size_t secretlen, otrv4_t *otr) {
  tlv_t *smp_start_tlv = NULL;

  if (!otr)
    return OTR4_ERROR;

  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    // FIXME: missing fragmentation
    return otrv3_smp_start(to_send, question, secret, secretlen,
                           otr->otr3_conn);
    break;
  case OTRV4_VERSION_4:
    if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
      return OTR4_ERROR;

    smp_start_tlv = otrv4_smp_initiate(
        get_my_user_profile(otr), otr->their_profile, question, q_len, secret,
        secretlen, otr->keys->ssid, otr->smp, otr->conversation);
    if (otrv4_prepare_to_send_message(to_send, "", smp_start_tlv, otr)) {
      otrv4_tlv_free(smp_start_tlv);
      return OTR4_ERROR;
    }
    otrv4_tlv_free(smp_start_tlv);
    return OTR4_SUCCESS;
    break;
  case OTRV4_VERSION_NONE:
    return OTR4_ERROR;
  }

  return OTR4_ERROR;
}

static tlv_t *otrv4_smp_provide_secret(otr4_smp_event_t *event,
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

static otr4_err_t smp_continue_otrv4(string_t *to_send, const uint8_t *secret,
                                     const size_t secretlen, otrv4_t *otr) {
  otr4_err_t err = OTR4_ERROR;
  tlv_t *smp_reply = NULL;

  if (!otr)
    return err;

  otr4_smp_event_t event = OTRV4_SMPEVENT_NONE;
  smp_reply = otrv4_smp_provide_secret(
      &event, otr->smp, get_my_user_profile(otr), otr->their_profile,
      otr->keys->ssid, secret, secretlen);

  if (!event)
    event = OTRV4_SMPEVENT_IN_PROGRESS;

  // TODO: transition to state 1 if an abort happens
  handle_smp_event_cb(event, otr->smp->progress, otr->smp->msg1->question,
                      otr->conversation);

  if (smp_reply && otrv4_prepare_to_send_message(to_send, "", smp_reply, otr) ==
                       OTR4_SUCCESS) {
    err = OTR4_SUCCESS;
  }

  otrv4_tlv_free(smp_reply);
  return err;
}

otr4_err_t otrv4_smp_continue(string_t *to_send, const uint8_t *secret,
                              const size_t secretlen, otrv4_t *otr) {
  switch (otr->running_version) {
  case OTRV4_VERSION_3:
    // FIXME: missing fragmentation
    return otrv3_smp_continue(to_send, secret, secretlen, otr->otr3_conn);
  case OTRV4_VERSION_4:
    return smp_continue_otrv4(to_send, secret, secretlen, otr);
  case OTRV4_VERSION_NONE:
    return OTR4_ERROR;
  }

  return OTR4_ERROR; // TODO: IMPLEMENT
}

otr4_err_t otrv4_smp_abort(otrv4_t *otr) {
  // TODO: implement for both OTR3 and OTR4
  return OTR4_ERROR;
}
