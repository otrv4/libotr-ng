#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "otrv4.h"
#include "otrv3.h"
#include "str.h"
#include "b64.h"
#include "deserialize.h"

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
  otr->pre_key = NULL;

  return otr;
}

void
otrv4_free(/*@only@*/ otrv4_t *otr) {
    if(otr == NULL) {
        return;
    }

    if (otr->pre_key != NULL) {
      dake_pre_key_free(otr->pre_key);
      otr->pre_key = NULL;
    }

    free(otr);
}

static int
otrv4_allow_version(const otrv4_t *otr, supportVersion version) {
  return (otr->supported_versions & version);
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

static void
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

void
otrv4_build_query_message(/*@unique@*/ string_t *query_message, const otrv4_t *otr, const string_t message) {
  *query_message = malloc(strlen(query)+strlen(message)+4);
  if (*query_message == NULL) {
    return; //error
  }

  strcpy(*query_message, query);

  //TODO: how to use allowed_versions here?
  if (otrv4_allow_version(otr, OTR_ALLOW_V4)) {
    strcat(*query_message, "4");
  }

  if (otrv4_allow_version(otr, OTR_ALLOW_V3)) {
    strcat(*query_message, "3");
  }

  strcat(*query_message, "? ");
  strcat(*query_message, message);
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

static bool
otrv4_message_contains_tag(const string_t message) {
  if (strstr(message, tag_base)) {
    return true;
  } else {
    return false;
  }
}

static void
otrv4_message_to_display_without_tag(otrv4_response_t *response, const string_t message, const char *tag_version) {
  size_t msg_length = strlen(message);
  size_t tag_length = strlen(tag_base) + strlen(tag_version);
  size_t chars = msg_length - tag_length;

  //assert(response->to_display == NULL);
  response->to_display = malloc(chars+1);
  if(response->to_display == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }
  strncpy(response->to_display, message+tag_length, chars);
  response->to_display[chars] = '\0';
}

static void
otrv4_message_to_display_set(otrv4_response_t *response, const string_t message) {
  if(response->to_display != NULL) {
      free(response->to_display);
  }
  response->to_display = otrv4_strdup(message);
}

static void
otrv4_state_set(otrv4_t *otr, stateFlag target) {
  otr->state = target;
}

static void
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

static bool
otrv4_message_is_query(const string_t message) {
  if (strstr(message, query)) {
    return true;
  } else {
    return false;
  }
}

static void
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

static void
otrv4_pre_key_set(otrv4_t *otr, /*@only@*/ dake_pre_key_t *pre_key) {
  if(otr->pre_key != NULL) {
    free(otr->pre_key);
  }
  otr->pre_key = pre_key;
}

static bool
otrv4_message_is_data(const string_t message) {
  if (strstr(message, otrv4)) {
    return true;
  } else {
    return false;
  }
}

static void
otrv4_in_message_parse(otrv4_in_message_t *target, const string_t message) {
  if (otrv4_message_contains_tag(message)) {
    target->type = IN_MSG_TAGGED_PLAINTEXT;
  } else if (otrv4_message_is_query(message)) {
    target->type = IN_MSG_QUERY_STRING;
  } else if (otrv4_message_is_data(message)) {
    target->type = IN_MSG_CYPHERTEXT;
  printf("message type is cypher text\n");
    size_t dec_len = 0;
    uint8_t *decoded = NULL;
    int res = otrl_base64_otr_decode(message, &decoded, &dec_len);
    if (res != 0) {
      // TODO: handle error
      printf("result is %d\n", res);
      return;
    }

    if (target->raw_text != NULL) {
      free(target->raw_text);
    }
    target->raw_text = (string_t) decoded;
    return;
  } else {
    target->type = IN_MSG_PLAINTEXT;
  }

  if (target->raw_text != NULL) {
    free(target->raw_text);
  }
  target->raw_text = otrv4_strdup(message);
}

static otrv4_response_t* response_new(void) {
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

  free(response->to_send);
  response->to_send = NULL;

  free(response->to_display);
  response->to_display = NULL;

  free(response);
}

static otrv4_response_t *
otrv4_receive_plaintext(otrv4_t *otr, const otrv4_in_message_t *message) {
  otrv4_response_t *response = response_new();
  if (response == NULL) {
    return NULL;
  }

  if (message->raw_text == NULL) {
    return response;
  }

  otrv4_message_to_display_set(response, message->raw_text);
  if (otr->state != OTR_STATE_START) {
    response->warning = OTR_WARN_RECEIVED_UNENCRYPTED;
  }

  return response;
}

static otrv4_response_t *
otrv4_receive_tagged_plaintext(otrv4_t *otr, const otrv4_in_message_t *message) {
  otrv4_response_t *response = response_new();
  if (response == NULL) {
    return NULL;
  }

  if (message->raw_text == NULL) {
    //TODO: this is an error.
    return response;
  }

  otrv4_running_version_set_from_tag(otr, message->raw_text);
  //remove tag from message

  switch (otr->running_version) {
  case OTR_VERSION_4:
    otrv4_state_set(otr, OTR_STATE_AKE_IN_PROGRESS);
    otrv4_message_to_display_without_tag(response, message->raw_text, tag_version_v4);
    otrv4_pre_key_set(otr, dake_pre_key_new(NULL));
    break;
  case OTR_VERSION_3:
    otrv3_receive_message(message->raw_text);
    break;
  default:
    //otrv4_message_to_display_without_tag(otr, message->raw_text, tag_version_v4);
    //TODO Do we exit(1)?
    break;
  }

  return response;
}

static user_profile_t*
get_my_user_profile(const otrv4_t *otr) {
  string_t versions = NULL;
  allowed_versions(&versions, otr);

  user_profile_t *profile = user_profile_new(versions);

  #define PROFILE_EXPIRATION_SECONDS 2 * 7 * 24 * 60 * 60; //2 weeks
  time_t expires = time(NULL);
  profile->expires = expires + PROFILE_EXPIRATION_SECONDS;
  user_profile_sign(profile, otr->keypair);

  free(versions);
  return profile;
}

static inline string_t
serialize_and_encode_pre_key(const dake_pre_key_t* pre_key) {
    size_t ser_len = 0;
    uint8_t *serialized = NULL;
    if (!dake_pre_key_aprint(&serialized, &ser_len, pre_key)) {
      //TODO: error
      return NULL;
    }

    string_t encoded = otrl_base64_otr_encode(serialized, ser_len);
    free(serialized);

    return encoded;
}

static otrv4_response_t*
otrv4_receive_query_string(otrv4_t *otr, const otrv4_in_message_t *message) {
  user_profile_t *profile = NULL;

  otrv4_response_t *response = response_new();
  if (response == NULL) {
    return NULL;
  }

  if (message->raw_text == NULL) {
    return NULL;
  }

  otrv4_running_version_set_from_query(otr, message->raw_text);

  switch (otr->running_version) {
  case OTR_VERSION_4:
    profile = get_my_user_profile(otr);
    otrv4_state_set(otr, OTR_STATE_AKE_IN_PROGRESS);
    otrv4_pre_key_set(otr, dake_pre_key_new(profile));

    //generate ephmeral ECDH and DH keys
    ec_gen_keypair(otr->our_ecdh);
    dh_gen_keypair(otr->our_dh);

    ec_public_key_copy(otr->pre_key->Y, otr->our_ecdh->pub);
    otr->pre_key->B = otr->our_dh->pub; //TODO: make a copy?

    response->to_display = NULL;
    response->to_send = serialize_and_encode_pre_key(otr->pre_key);
    break;
  case OTR_VERSION_3:
    otrv3_receive_message(message->raw_text);
    break;
  default:
    //nothing to do
    break;
  }

  user_profile_free(profile);
  return response;
}

typedef struct {
  supportVersion version;
  uint8_t type;
} otrv4_header_t;

static bool
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

static bool
otrv4_receive_pre_key(otrv4_response_t *response, uint8_t *buff, size_t buflen, otrv4_t *otr) {
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

    //TODO get our profile and replace
    //dake_dre_auth_t *dre_auth = dake_dre_auth_new(pre_key.sender_profile);
    //uint8_t *ser_dre_aut = {0};
    //dake_dre_auth_aprint(uint8_t **dst, size_t *nbytes, const dake_dre_auth_t *dre_auth);

    otr->state = OTR_STATE_ENCRYPTED_MESSAGES;
  }

  return true;
}

static otrv4_response_t *
otrv4_receive_data_message(otrv4_t *otr, otrv4_in_message_t *message) {
  otrv4_response_t *response = response_new();
  if (response == NULL) {
    return NULL;
  }

  if (message->raw_text == NULL) {
    // ??? is it heartbeat?
    return NULL;
  }
  
  otrv4_header_t header;
  if (!extract_header(&header, (const uint8_t*) message->raw_text, 3)) { //TODO: we need the len of raw_text
    return NULL;
  }

  if (!otrv4_allow_version(otr, header.version)) {
    return NULL; //ignore this message
  }

  switch (header.type) {
  case OTR_PRE_KEY_MSG_TYPE:
    //we received a pre key
    if (!otrv4_receive_pre_key(response, (uint8_t*) message->raw_text, 1000, otr)) {
      return NULL;
    }
    break;
  case OTR_DRE_AUTH_MSG_TYPE:
    break;
  case OTR_DATA_MSG_TYPE:
    break;
  default:
    //errror. bad message type
    break;
  }

  return response;
}

static otrv4_in_message_t *
otrv4_in_message_new() {
  otrv4_in_message_t *input = malloc(sizeof(otrv4_in_message_t));

  if (input == NULL) {
    return NULL;
  }

  input->type = 0;
  input->raw_text = NULL;

  return input;
}

otrv4_response_t*
otrv4_receive_message(otrv4_t *otr, const string_t message) {
  otrv4_in_message_t *input = otrv4_in_message_new();
  if (input == NULL) {
      return NULL;
  }

  otrv4_in_message_parse(input, message);

  otrv4_response_t *response = NULL;
  switch (input->type) {
  case IN_MSG_PLAINTEXT:
    response = otrv4_receive_plaintext(otr, input);
    break;

  case IN_MSG_TAGGED_PLAINTEXT:
   response =  otrv4_receive_tagged_plaintext(otr, input);
    break;

  case IN_MSG_QUERY_STRING:
    response = otrv4_receive_query_string(otr, input);
    break;

  case IN_MSG_CYPHERTEXT:
    response = otrv4_receive_data_message(otr, input);
    break;
  }

  free(input->raw_text);
  free(input);

  return response;
}
