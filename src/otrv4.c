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
  otr->state = OTR_STATE_START;
  otr->supported_versions = OTR_ALLOW_V4;
  otr->running_version = OTR_VERSION_NONE;
  otr->profile = get_my_user_profile(otr);
  key_manager_init(otr->keys);

  return otr;
}

void
otrv4_free(/*@only@*/ otrv4_t *otr) {
  if(otr == NULL) {
    return;
  }

  key_manager_destroy(otr->keys);
  user_profile_free(otr->profile);
  dh_keypair_destroy(otr->our_dh);
  ec_keypair_destroy(otr->our_ecdh);

  dh_mpi_release(otr->their_dh);
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
otrv4_build_query_message(/*@unique@*/ string_t *query_message, const otrv4_t *otr, const string_t message) {
  size_t s = strlen(query)+strlen(message)+4+1;
  string_t buff = malloc(s);
  if (buff == NULL) {
    return; //error
  }

  string_t cursor = stpcpy(buff, query);

  //TODO: how to use allowed_versions here?
  if (otrv4_allow_version(otr, OTR_ALLOW_V4)) {
    *cursor++ = '4';
  }

  if (otrv4_allow_version(otr, OTR_ALLOW_V3)) {
    *cursor++ = '3';
  }

  cursor = stpcpy(cursor, "? ");
  stpcpy(cursor, message);

  *query_message = buff;
}

//TODO: should this care about UTF8?
//TODO: should this deal with buffer overflows?
bool
otrv4_build_whitespace_tag(/*@unique@*/ string_t whitespace_tag, const otrv4_t *otr, const string_t message) {

  strcpy(whitespace_tag, tag_base);

  if (otrv4_allow_version(otr, OTR_ALLOW_V4)) {
    strcat(whitespace_tag, tag_version_v4);
  }

  if (otrv4_allow_version(otr, OTR_ALLOW_V3)) {
    strcat(whitespace_tag, tag_version_v3);
  }

  strcat(whitespace_tag, message);

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
otrv4_generate_dre_auth(dake_dre_auth_t **dst, const user_profile_t *sender_profile, const otrv4_t *otr) {
  dake_dre_auth_t *dre_auth = dake_dre_auth_new(otr->profile);

  if (!dake_dre_auth_generate_gamma_phi_sigma(
      otr->keypair, otr->our_ecdh->pub, otr->our_dh->pub,
      sender_profile, otr->their_ecdh, otr->their_dh, dre_auth
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
  dake_pre_key_t pre_key;
  if (!dake_pre_key_deserialize(&pre_key, buff, buflen)) {
    return false;
  }

  if (otr->state == OTR_STATE_START) {
    if (!dake_pre_key_validate(&pre_key)) {
      return false;
    }

    ec_public_key_copy(otr->their_ecdh, pre_key.Y);
    otr->their_dh = dh_mpi_copy(pre_key.B);

    dake_dre_auth_t *dre_auth = NULL;
    otrv4_generate_ephemeral_keys(otr);
    if (!otrv4_generate_dre_auth(&dre_auth, pre_key.profile, otr)) {
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

  dake_dre_auth_t dre_auth;
  if (!dake_dre_auth_deserialize(&dre_auth, buff, buflen)) {
    return false;
  }

  if (!dake_dre_auth_validate(otr->their_ecdh, &otr->their_dh,
      otr->profile, otr->keypair, otr->our_ecdh->pub,
      otr->our_dh->pub, &dre_auth)) {
    return false;
  }

  *dst = NULL;
  return double_ratcheting_init(1, otr);
}

bool
otrv4_receive_data_message(otrv4_response_t *response, const string_t message, otrv4_t *otr) {
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
    return otrv4_receive_data_message(response, message, otr);
    break;
  }

  return true;
}

