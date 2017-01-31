#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "otrv4.h"
#include "otrv3.h"
#include "str.h"
#include "b64.h"

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
  otr->message_to_display = NULL;
  otr->message_to_respond = NULL;
  otr->warning = NULL;
  otr->pre_key = NULL;

  return otr;
}

void
otrv4_free(/*@only@*/ otrv4_t *otr) {
    if(otr == NULL) {
        return;
    }

    free(otr->message_to_display);
    otr->message_to_display = NULL;

    free(otr->message_to_respond = NULL);
    otr->message_to_respond = NULL;

    free(otr->warning);
    otr->warning = NULL;

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
otrv4_message_to_display_without_tag(otrv4_t *otr, const string_t message, const char *tag_version) {
  size_t msg_length = strlen(message);
  size_t tag_length = strlen(tag_base) + strlen(tag_version);
  size_t chars = msg_length - tag_length;
  if(otr->message_to_display != NULL) {
    free(otr->message_to_display);
  }
  otr->message_to_display = malloc(chars+1);
  if(otr->message_to_display == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }
  strncpy(otr->message_to_display, message+tag_length, chars);
  otr->message_to_display[chars] = '\0';
}

static void
otrv4_message_to_display_set(otrv4_t *otr, const string_t message) {
  if(otr->message_to_display != NULL) {
      free(otr->message_to_display);
  }
  otr->message_to_display = otrv4_strdup(message);
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
  } else {
    target->type = IN_MSG_PLAINTEXT;
  }

  if (target->raw_text != NULL) {
    free(target->raw_text);
  }
  target->raw_text = otrv4_strdup(message);
}

static void
otrv4_receive_plaintext(otrv4_t *otr, const otrv4_in_message_t *message) {
  if (message->raw_text == NULL) {
    return;
  }

  otrv4_message_to_display_set(otr, message->raw_text);
  if (otr->state != OTR_STATE_START) {
    if(otr->warning != NULL) {
      free(otr->warning);
    }
    otr->warning = otrv4_strdup("The above message was received unencrypted.");
  }
}

static void
otrv4_receive_tagged_plaintext(otrv4_t *otr, const otrv4_in_message_t *message) {
  if (message->raw_text == NULL) {
    return;
  }
  otrv4_running_version_set_from_tag(otr, message->raw_text);
  //remove tag from message

  switch (otr->running_version) {
  case OTR_VERSION_4:
    otrv4_state_set(otr, OTR_STATE_AKE_IN_PROGRESS);
    otrv4_message_to_display_without_tag(otr, message->raw_text, tag_version_v4);
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

static response_t* response_new(void) {
  response_t *response = malloc(sizeof(response_t));
  if (response == NULL) {
    return NULL;
  }

  response->to_display = NULL;
  response->to_send = NULL;
  response->warning = OTR_WARN_NONE;

  return response;
}

static response_t*
otrv4_receive_query_string(otrv4_t *otr, const otrv4_in_message_t *message) {
  user_profile_t *profile = NULL;

  response_t *response = response_new();
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

    response->to_display = NULL;
    uint8_t  *serialized;
    if (!user_profile_aprint(&serialized, NULL, profile)) {
      //TODO: error
      return NULL;
    }

    uint8_t encoded[sizeof(serialized) + 1] = { 0 };
    otrl_base64_encode((char *) encoded, serialized, sizeof(serialized) + 1);
    response->to_send = strdup((char *) encoded);

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

static void
otrv4_receive_data_message(otrv4_t *otr, otrv4_in_message_t *message) {
  if (message->raw_text == NULL) {
    // ??? is it heartbeat?
    return;
  }

  otrv4_state_set(otr, OTR_STATE_ENCRYPTED_MESSAGES);
  otr->running_version = OTR_VERSION_4;
  if (otr->message_to_respond == NULL) {
    otr->message_to_respond = malloc(1000);
  }
  otr->message_to_respond = otrv4_strdup("tenga su dre-auth msg\n");
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

response_t*
otrv4_receive_message(otrv4_t *otr, const string_t message) {
  otrv4_in_message_t *input = otrv4_in_message_new();
  if (input == NULL) {
      return NULL;
  }

  otrv4_in_message_parse(input, message);

  response_t *response = NULL;
  switch (input->type) {
  case IN_MSG_PLAINTEXT:
    otrv4_receive_plaintext(otr, input);
    break;

  case IN_MSG_TAGGED_PLAINTEXT:
    otrv4_receive_tagged_plaintext(otr, input);
    break;

  case IN_MSG_QUERY_STRING:
    response = otrv4_receive_query_string(otr, input);
    break;

  case IN_MSG_CYPHERTEXT:
    otrv4_receive_data_message(otr, input);
    break;
  }

  free(input->raw_text);
  free(input);

  return response;
}
