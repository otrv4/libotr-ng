#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "otrv4.h"
#include "otrv3.h"
#include "str.h"
#include "b64.h"
#include "deserialize.h"
#include "sha3.h"
#include "data_message.h"
#include "constants.h"
#include "debug.h"

#define QUERY_MESSAGE_TAG_BYTES 5
#define WHITESPACE_TAG_BASE_BYTES 16
#define WHITESPACE_TAG_VERSION_BYTES 8

static const char tag_base[] = {
  '\x20', '\x09', '\x20', '\x20', '\x09', '\x09', '\x09', '\x09',
  '\x20', '\x09', '\x20', '\x09', '\x20', '\x09', '\x20', '\x20',
  '\0'
};
static const char tag_version_v4[] = {
  '\x20', '\x20', '\x09', '\x09', '\x20', '\x09', '\x20', '\x20',
  '\0'
};
static const char tag_version_v3[] = {
  '\x20', '\x20', '\x09', '\x09', '\x20', '\x20', '\x09', '\x09',
  '\0'
};
static const string_t query = "?OTRv";
static const string_t otrv4 = "?OTR:";

int
otrv4_allow_version(const otrv4_t *otr, supportVersion version) {
  return (otr->supported_versions & version);
}

void
allowed_versions(string_t *dst, const otrv4_t *otr) { //generate a string with all versions allowed
  *dst = malloc(3*sizeof(char));
  if (*dst == NULL) {
    return;
  }

  memset(*dst, 0, 3*sizeof(char));
  if (otrv4_allow_version(otr, OTR_ALLOW_V4)) {
    strcat(*dst, "4");
  }

  if (otrv4_allow_version(otr, OTR_ALLOW_V3)) {
    strcat(*dst, "3");
  }

  return;
}

user_profile_t*
get_my_user_profile(const otrv4_t *otr) {
  string_t versions = NULL;
  allowed_versions(&versions, otr);

  user_profile_t *profile = user_profile_new(versions);
  if (profile == NULL) {
    free(versions);
    return NULL;
  }

  free(versions);

  #define PROFILE_EXPIRATION_SECONDS 2 * 7 * 24 * 60 * 60; //2 weeks
  time_t expires = time(NULL);
  profile->expires = expires + PROFILE_EXPIRATION_SECONDS;
  user_profile_sign(profile, otr->keypair);

  return profile;
}

otrv4_t *
otrv4_new(cs_keypair_s *keypair) {
  otrv4_t *otr = malloc(sizeof(otrv4_t));
  if(otr == NULL) {
    return NULL;
  }

  otr->keypair = keypair;
  otr->our_dh->priv = dh_mpi_new();
  otr->our_dh->pub = dh_mpi_new();
  otr->state = OTR_STATE_START;
  otr->supported_versions = OTR_ALLOW_V4;
  otr->running_version = OTR_VERSION_NONE;
  otr->profile = get_my_user_profile(otr);
  key_manager_init(otr->keys);

  return otr;
}

void
otrv4_destroy(/*@only@*/ otrv4_t *otr) {
  dh_keypair_destroy(otr->our_dh);
  key_manager_destroy(otr->keys);
  user_profile_free(otr->profile);
  otr->profile = NULL;
}

void
otrv4_free(/*@only@*/ otrv4_t *otr) {
  if(otr == NULL) {
    return;
  }

  otrv4_destroy(otr);
  free(otr);
}

void
otrv4_version_support_v3(otrv4_t *otr) {
  otr->supported_versions |= OTR_ALLOW_V3;
}

bool
otrv4_start(otrv4_t *otr) {
  otr->state = OTR_STATE_START;
  otr->supported_versions = OTR_ALLOW_V4;

  return true;
}

void
otrv4_build_query_message(string_t *query_message,
                          const otrv4_t *otr,
                          const string_t message,
                          size_t message_len) {
  //size = qm tag + msg length + versions + question mark + whitespace + null byte
  int qm_size = QUERY_MESSAGE_TAG_BYTES + message_len + 2 + 1;
  int allows_v4 = otrv4_allow_version(otr, OTR_ALLOW_V4);
  int allows_v3 = otrv4_allow_version(otr, OTR_ALLOW_V3);
  if (allows_v4) qm_size++;
  if (allows_v3) qm_size++;

  string_t buff = malloc(qm_size);
  if (buff == NULL) {
    return; //error
  }

  char *cursor = stpcpy(buff, query);

  //TODO: how to use allowed_versions here?
  if (allows_v4) {
    *cursor++ = '4';
  }

  if (allows_v3) {
    *cursor++ = '3';
  }

  cursor = stpcpy(cursor, "? ");

  //TODO: stpncpy will return cursor + n, where n > 0 is an error
  stpncpy(cursor, message, message_len + 1);

  *query_message = buff;
}

//TODO: should this care about UTF8?
bool
otrv4_build_whitespace_tag(string_t *whitespace_tag,
                           const otrv4_t *otr,
                           const string_t message,
                           size_t message_len) {
  size_t m_size = WHITESPACE_TAG_BASE_BYTES + message_len + 1;
  int allows_v4 = otrv4_allow_version(otr, OTR_ALLOW_V4);
  int allows_v3 = otrv4_allow_version(otr, OTR_ALLOW_V3);
  if (allows_v4) m_size += WHITESPACE_TAG_VERSION_BYTES;
  if (allows_v3) m_size += WHITESPACE_TAG_VERSION_BYTES;

  string_t buff = malloc(m_size);
  if (buff == NULL) {
    return false; //TODO: error
  }

  char *cursor = stpcpy(buff, tag_base);

  if (allows_v4) {
    cursor = stpcpy(cursor, tag_version_v4);
  }

  if (allows_v3) {
    cursor = stpcpy(cursor, tag_version_v3);
  }

  //TODO: stpncpy will return cursor + n, where n > 0 is an error
  stpncpy(cursor, message, message_len + 1);

  *whitespace_tag = buff;

  return true;
}

bool
otrv4_message_contains_tag(const string_t message) {
  if (strstr(message, tag_base)) {
    return true;
  } else {
    return false;
  }
}

void
otrv4_message_to_display_set(otrv4_response_t *response, const string_t message) {
  response->to_display = otrv4_strdup(message);
}

bool
otrv4_message_to_display_without_tag(otrv4_response_t *response, const string_t message, const char *tag_version) {
  //TODO: this does not remove ALL tags
  size_t msg_length = strlen(message);
  size_t tag_length = strlen(tag_base) + strlen(tag_version);
  size_t chars = msg_length - tag_length;

  if (msg_length < tag_length) {
    return false;
  }

  string_t buff = malloc(chars+1);
  if(buff == NULL) {
    return false;
  }

  strncpy(buff, message+tag_length, chars);
  buff[chars] = '\0';

  otrv4_message_to_display_set(response, buff);

  free(buff);
  return true;
}

void
otrv4_state_set(otrv4_t *otr, stateFlag target) {
  otr->state = target;
}

void
otrv4_running_version_set_from_tag(otrv4_t *otr, const string_t message) {
  if (otrv4_allow_version(otr, OTR_ALLOW_V4)) {
    if (strstr(message, tag_version_v4)) {
      otr->running_version = OTR_VERSION_4;
      return;
    }
  }

  if (otrv4_allow_version(otr, OTR_ALLOW_V3)) {
    if (strstr(message, tag_version_v3)) {
      otr->running_version = OTR_VERSION_3;
      return;
    }
  }
}

bool
otrv4_message_is_query(const string_t message) {
  if (strstr(message, query)) {
    return true;
  } else {
    return false;
  }
}

void
otrv4_running_version_set_from_query(otrv4_t *otr, const string_t message) {
  if (otrv4_allow_version(otr, OTR_ALLOW_V4)) {
      if (strstr(message, "4")) {
        otr->running_version = OTR_VERSION_4;
        return;
      }
  }

  if (otrv4_allow_version(otr, OTR_ALLOW_V3)) {
    if (strstr(message, "3")) {
      otr->running_version = OTR_VERSION_3;
      return;
    }
  }
}

bool
otrv4_message_is_data(const string_t message) {
  if (strstr(message, otrv4)) {
    return true;
  } else {
    return false;
  }
}

otrv4_response_t*
otrv4_response_new(void) {
  otrv4_response_t *response = malloc(sizeof(otrv4_response_t));
  if (response == NULL) {
    return NULL;
  }

  response->to_display = NULL;
  response->to_send = NULL;
  response->warning = OTR_WARN_NONE;

  return response;
}

void
otrv4_response_free(otrv4_response_t * response) {
  if (response == NULL) {
    return;
  }

  free(response->to_send);
  response->to_send = NULL;

  free(response->to_display);
  response->to_display = NULL;

  free(response);
}

//TODO: Is not receiving a plaintext a problem?
bool
otrv4_receive_plaintext(otrv4_response_t *response, const string_t message, const otrv4_t *otr) {
  otrv4_message_to_display_set(response, message);

  if (otr->state != OTR_STATE_START) {
    response->warning = OTR_WARN_RECEIVED_UNENCRYPTED;
  }

  return true;
}

bool
serialize_and_encode_pre_key(string_t *dst, const dake_pre_key_t* pre_key) {
  size_t ser_len = 0;
  uint8_t *serialized = NULL;
  if (!dake_pre_key_aprint(&serialized, &ser_len, pre_key)) {
    return false;
  }

  *dst = otrl_base64_otr_encode(serialized, ser_len);
  free(serialized);

  return true;
}

bool
otrv4_reply_with_pre_key(otrv4_response_t *response, const otrv4_t *otr) {
  dake_pre_key_t *pre_key = dake_pre_key_new(otr->profile);
  if (pre_key == NULL) {
    return false;
  }

  ec_public_key_copy(pre_key->Y, otr->our_ecdh->pub);
  pre_key->B = dh_mpi_copy(otr->our_dh->pub);

  bool ret = serialize_and_encode_pre_key(&response->to_send, pre_key);
  dake_pre_key_free(pre_key);

  return ret;
}

void
otrv4_generate_ephemeral_keys(otrv4_t *otr) {
  ec_keypair_generate(otr->our_ecdh);
  dh_keypair_generate(otr->our_dh);
}

bool
otrv4_start_dake(otrv4_response_t *response, const string_t message, otrv4_t *otr) {
  otrv4_generate_ephemeral_keys(otr);
  otrv4_state_set(otr, OTR_STATE_AKE_IN_PROGRESS);

  return otrv4_reply_with_pre_key(response, otr);
}

bool
otrv4_receive_tagged_plaintext(otrv4_response_t *response, const string_t message, otrv4_t *otr) {
  otrv4_running_version_set_from_tag(otr, message);
  //remove tag from message

  switch (otr->running_version) {
  case OTR_VERSION_4:
    if (!otrv4_message_to_display_without_tag(response, message, tag_version_v4)) {
      return false;
    }

    return otrv4_start_dake(response, message, otr);
    break;
  case OTR_VERSION_3:
    return otrv3_receive_message(message);
    break;
  default:
    //otrv4_message_to_display_without_tag(otr, message->raw_text, tag_version_v4);
    //TODO Do we exit(1)?
    break;
  }

  return false;
}

bool
otrv4_receive_query_message(otrv4_response_t *response, const string_t message, otrv4_t *otr) {
  otrv4_running_version_set_from_query(otr, message);

  switch (otr->running_version) {
  case OTR_VERSION_4:
    return otrv4_start_dake(response, message, otr);
    break;
  case OTR_VERSION_3:
    return otrv3_receive_message(message);
    break;
  default:
    //nothing to do
    break;
  }

  return false;
}

typedef struct {
  supportVersion version;
  uint8_t type;
} otrv4_header_t;

bool
extract_header(otrv4_header_t *dst, const uint8_t *buffer, const size_t bufflen) {
  //TODO: check the length

  size_t read = 0;
  uint16_t version = 0;
  uint8_t type = 0;
  if (!deserialize_uint16(&version, buffer, bufflen, &read)) {
    return false;
  }

  buffer += read;

  if (!deserialize_uint8(&type, buffer, bufflen - read, &read)) {
    return false;
  }

  dst->version = OTR_ALLOW_NONE;
  if (version == 0x04) {
    dst->version = OTR_ALLOW_V4;
  } else if (version == 0x03) {
    dst->version = OTR_ALLOW_V3;
  }
  dst->type = type;

  return true;
}

bool
otrv4_generate_dre_auth(dake_dre_auth_t **dst, const user_profile_t *their_profile, const otrv4_t *otr) {
  dake_dre_auth_t *dre_auth = dake_dre_auth_new(otr->profile);

  if (!dake_dre_auth_generate_gamma_phi_sigma(
      otr->keypair, otr->our_ecdh->pub, otr->our_dh->pub,
      their_profile, otr->their_ecdh, otr->their_dh, dre_auth
      )) {
    dake_dre_auth_free(dre_auth);
    return false;
  }

  *dst = dre_auth;
  return true;
}

bool
serialize_and_encode_dre_auth(string_t *dst, const dake_dre_auth_t *dre_auth) {
  size_t ser_len = 0;
  uint8_t *serialized = NULL;
  if (!dake_dre_auth_aprint(&serialized, &ser_len, dre_auth)) {
    return false;
  }

  *dst = otrl_base64_otr_encode(serialized, ser_len);
  free(serialized);

  return true;
}

bool
double_ratcheting_init(int j, otrv4_t *otr) {
  otr->keys->i = 0;
  otr->keys->j = j;

  k_ecdh_t k_ecdh;
  if (!ecdh_shared_secret(k_ecdh, sizeof(k_ecdh_t), otr->our_ecdh, otr->their_ecdh)) {
    return false;
  }

  k_dh_t k_dh;
  if (!dh_shared_secret(k_dh, sizeof(k_dh_t), otr->our_dh->priv, otr->their_dh)) {
    return false;
  }

  mix_key_t mix_key;
  if (!sha3_256(mix_key, sizeof(mix_key_t), k_dh, sizeof(k_dh_t))) {
    return false;
  }

#ifdef DEBUG
  printf("INIT DOUBLE RATCHET\n");
  printf("K_ecdh = ");
  otrv4_memdump(k_ecdh, sizeof(k_ecdh_t));
  printf("k_dh = ");
  otrv4_memdump(k_dh, sizeof(k_dh_t));
  printf("mixed_key = ");
  otrv4_memdump(mix_key, sizeof(mix_key_t));
#endif

  shared_secret_t shared;
  if (!calculate_shared_secret(shared, k_ecdh, mix_key)) {
    return false;
  }

  if (!key_manager_init_ratchet(otr->keys, shared)) {
    return false;
  }

  otr->state = OTR_STATE_ENCRYPTED_MESSAGES;
  return true;
}

bool
otrv4_receive_pre_key(string_t *dst, uint8_t *buff, size_t buflen, otrv4_t *otr) {
  dake_pre_key_t pre_key[1];
  if (!dake_pre_key_deserialize(pre_key, buff, buflen)) {
    return false;
  }

  if (otr->state == OTR_STATE_START) {
    if (!dake_pre_key_validate(pre_key)) {
      dake_pre_key_destroy(pre_key);
      return false;
    }

    ec_public_key_copy(otr->their_ecdh, pre_key->Y);
    otr->their_dh = dh_mpi_copy(pre_key->B);

    //TODO: why not use dake_dre_auth_new(otr->profile);
    dake_dre_auth_t *dre_auth = NULL;
    otrv4_generate_ephemeral_keys(otr);
    if (!otrv4_generate_dre_auth(&dre_auth, pre_key->profile, otr)) {
      dake_pre_key_destroy(pre_key);
      return false;
    }

    if (!serialize_and_encode_dre_auth(dst, dre_auth)) {
      dake_dre_auth_free(dre_auth);
      return false;
    }
    dake_dre_auth_free(dre_auth);

    return double_ratcheting_init(0, otr);
  }

  return false;
}

bool
otrv4_receive_dre_auth(string_t *dst, uint8_t *buff, size_t buflen, otrv4_t *otr) {
  if (otr->state != OTR_STATE_AKE_IN_PROGRESS) {
    return true;
  }

  dake_dre_auth_t dre_auth[1];
  if (!dake_dre_auth_deserialize(dre_auth, buff, buflen)) {
    return false;
  }

  if (!dake_dre_auth_validate(otr->their_ecdh, &otr->their_dh,
      otr->profile, otr->keypair, otr->our_ecdh->pub,
      otr->our_dh->pub, dre_auth)) {
    dake_dre_auth_destroy(dre_auth);
    return false;
  }

  *dst = NULL;
  dake_dre_auth_destroy(dre_auth);
  return double_ratcheting_init(1, otr);
}

bool
data_message_decrypt(uint8_t **dst, const m_enc_key_t enc_key, const data_message_t *data_msg) {
  uint8_t *plain = malloc(data_msg->enc_msg_len);
  if (plain == NULL)
    return false;

  if (0 != crypto_stream_xor(plain, data_msg->enc_msg, data_msg->enc_msg_len, data_msg->nonce, enc_key)) {
    free(plain);
    return false;
  }

  *dst = plain;
  return true;
}

bool
derive_encription_and_mac_keys(m_enc_key_t enc_key, m_mac_key_t mac_key, const chain_key_t chain_key) {
  uint8_t magic1[1] = {0x1};
  if(!sha3_256_kdf(enc_key, sizeof(m_enc_key_t), magic1, chain_key, sizeof(chain_key_t))) {
    return false;
  }

  uint8_t magic2[1] = {0x2};
  if(!sha3_512_kdf(mac_key, sizeof(m_mac_key_t), magic2, chain_key, sizeof(chain_key_t))) {
    return false;
  }

  return true;
}

bool
retrieve_receiving_message_keys(m_enc_key_t enc_key, m_mac_key_t mac_key, int ratchet_id, int message_id, const otrv4_t *otr) {
  chain_key_t receiving;
  if (!key_manager_get_receiving_chain_key_by_id(receiving, ratchet_id, message_id, otr->our_ecdh->pub, otr->their_ecdh, otr->keys)) {
    return false;
  }

  return derive_encription_and_mac_keys(enc_key, mac_key, receiving);
}

bool
otrv4_receive_data_message(otrv4_response_t *response, uint8_t *buff, size_t buflen, otrv4_t *otr) {
  response->to_display = NULL;
  response->to_send = NULL;
  response->warning = OTR_WARN_NONE;

  if (otr->state != OTR_STATE_ENCRYPTED_MESSAGES) {
    //TODO: warn the user and send an error message with a code.
    return false;
  }

  data_message_t data_message;
  if (!data_message_deserialize(&data_message, buff, buflen)) {
    return false;
  }

  m_enc_key_t enc_key;
  m_mac_key_t mac_key;

  if (!retrieve_receiving_message_keys(enc_key, mac_key, data_message.ratchet_id, data_message.message_id, otr)) {
    return false;
  }

#ifdef DEBUG
  printf("DECRYPTING\n");
  printf("enc_key = ");
  otrv4_memdump(enc_key, sizeof(m_enc_key_t));
  printf("mac_key = ");
  otrv4_memdump(mac_key, sizeof(m_mac_key_t));
  printf("nonce = ");
  otrv4_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
#endif

  if (!data_message_validate(mac_key, &data_message)) {
    return false;
  }

  if (!data_message_decrypt((uint8_t**) &response->to_display, enc_key, &data_message)) {
    return false;
  }

  //TODO: to_send = depends on the TLVs we proccess

  return true;
}

bool
otrv4_receive_encoded_message(otrv4_response_t *response, const string_t message, otrv4_t *otr) {
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  int err = otrl_base64_otr_decode(message, &decoded, &dec_len);
  if (err) {
    return false;
  }

  otrv4_header_t header;
  if (!extract_header(&header, decoded, dec_len)) {
    free(decoded);
    return false;
  }

  if (!otrv4_allow_version(otr, header.version)) {
    free(decoded);
    return false;
  }

  //TODO: how to prevent version rollback?
  //TODO: where should we ignore messages to a different instance tag?

  switch (header.type) {
  case OTR_PRE_KEY_MSG_TYPE:
    if (!otrv4_receive_pre_key(&response->to_send, decoded, dec_len, otr)) {
      free(decoded);
      return false;
    }
    break;
  case OTR_DRE_AUTH_MSG_TYPE:
    if (!otrv4_receive_dre_auth(&response->to_send, decoded, dec_len, otr)) {
      free(decoded);
      return false;
    }
    break;
  case OTR_DATA_MSG_TYPE:
    if (!otrv4_receive_data_message(response, decoded, dec_len, otr)) {
      free(decoded);
      return false;
    }
    break;
  default:
    //errror. bad message type
    return false;
    break;
  }

  free(decoded);
  return true;
}

otrv4_in_message_type_t
get_message_type(const string_t message) {
  if (otrv4_message_contains_tag(message)) {
    return IN_MSG_TAGGED_PLAINTEXT;
  } else if (otrv4_message_is_query(message)) {
    return IN_MSG_QUERY_STRING;
  } else if (otrv4_message_is_data(message)) { //TODO: not only data, but also DAKE
    return IN_MSG_CYPHERTEXT;
  }

  return IN_MSG_PLAINTEXT;
}

// Receive a possibly OTR message.
bool
otrv4_receive_message(otrv4_response_t* response, otrv4_t *otr, const string_t message) {
  if (message == NULL) {
    return false;
  }

  otrv4_message_to_display_set(response, NULL);
  response->to_send = NULL;

  switch (get_message_type(message)) {
  case IN_MSG_NONE:
    return false;
  case IN_MSG_PLAINTEXT:
    return otrv4_receive_plaintext(response, message, otr);
    break;

  case IN_MSG_TAGGED_PLAINTEXT:
    return otrv4_receive_tagged_plaintext(response, message, otr);
    break;

  case IN_MSG_QUERY_STRING:
    return otrv4_receive_query_message(response, message, otr);
    break;

  case IN_MSG_CYPHERTEXT:
    return otrv4_receive_encoded_message(response, message, otr);
    break;
  }

  return true;
}

int
retrieve_sending_message_keys(m_enc_key_t enc_key, m_mac_key_t mac_key, const otrv4_t *otr) {
  chain_key_t sending;
  int message_id = key_manager_get_sending_chain_key(sending, otr->keys, otr->our_ecdh->pub, otr->their_ecdh);

  if (!derive_encription_and_mac_keys(enc_key, mac_key, sending)) {
    return -1;
  }

  return message_id;
}

bool
otrv4_send_data_message(uint8_t **to_send, const uint8_t *message, size_t message_len, otrv4_t *otr) {
  //ratchet_if_need_to()

  data_message_t *data_msg = data_message_new();
  if (data_msg == NULL)
    return false;

  m_enc_key_t enc_key;
  m_mac_key_t mac_key;

  int message_id = retrieve_sending_message_keys(enc_key, mac_key, otr);
  if (message_id < 0) {
    return false;
  }

#ifdef DEBUG
  printf("ENCRYPTING\n");
  printf("enc_key = ");
  otrv4_memdump(enc_key, sizeof(m_enc_key_t));
  printf("mac_key = ");
  otrv4_memdump(mac_key, sizeof(m_mac_key_t));
#endif

  data_msg->sender_instance_tag = otr->our_instance_tag;
  data_msg->receiver_instance_tag = otr->their_instance_tag;
  data_msg->ratchet_id = otr->keys->current->id;
  data_msg->message_id = message_id;
  ec_public_key_copy(data_msg->our_ecdh, otr->our_ecdh->pub);
  data_msg->our_dh = dh_mpi_copy(otr->our_dh->pub);

  random_bytes(data_msg->nonce, sizeof(data_msg->nonce));
  uint8_t *c = malloc(message_len);
  if (c == NULL)
    return false;

  if (0 != crypto_stream_xor(c, message, message_len, data_msg->nonce, enc_key)) {
    free(c);
    return false;
  }

  data_msg->enc_msg = c;
  data_msg->enc_msg_len = message_len;

#ifdef DEBUG
  printf("nonce = ");
  otrv4_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
  printf("msg = ");
  otrv4_memdump(message, message_len);
  printf("cipher = ");
  otrv4_memdump(c, message_len);
#endif

  uint8_t *body = NULL;
  size_t bodylen = 0;
  if (!data_message_body_aprint(&body, &bodylen, data_msg)) {
    return false;
  }

  data_message_free(data_msg);

  //TODO: append old mac keys to be revealed
  size_t serlen = bodylen + DATA_MSG_MAC_BYTES;
  uint8_t *ser = malloc(serlen);
  if (ser == NULL) {
    free(body);
    return false;
  }

  memcpy(ser, body, bodylen);
  free(body);

  if (!sha3_512_mac(ser+bodylen, DATA_MSG_MAC_BYTES, mac_key, sizeof(m_mac_key_t), ser, bodylen)) {
    free(ser);
    return false;
  }

  *to_send = (uint8_t*) otrl_base64_otr_encode(ser, serlen);
  free(ser);
  return true;
}

bool
otrv4_send_message(uint8_t **to_send, const uint8_t *message, size_t message_len, otrv4_t *otr) {
  if (otr->state == OTR_STATE_FINISHED) {
    return false; //Should restart
  }

  if (otr->state != OTR_STATE_ENCRYPTED_MESSAGES) {
    //TODO: queue message
    return false;
  }

  return otrv4_send_data_message(to_send, message, message_len, otr);
}
