#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mem.h"
#include "otr.h"
#include "otrv3.h"
#include "str.h"

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
static const char *query = "?OTRv";

otrv4_t *
otrv4_new(void) {
  otrv4_t *otr = malloc(sizeof(otrv4_t));
  if(otr == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  otr->state = OTR_STATE_START;
  otr->supported_versions = OTR_ALLOW_V4;
  otr->running_version = 0;
  otr->message_to_display = NULL;
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

    free(otr->warning);
    otr->warning = NULL;

    free(otr->pre_key);
    otr->pre_key = NULL;

    free(otr);
}

void
otrv4_version_support_v3(otrv4_t *otr) {
  otr->supported_versions |= OTR_ALLOW_V3;
}

int
otrv4_start(otrv4_t *otr) {
  otr->state = OTR_STATE_START;
  otr->supported_versions = OTR_ALLOW_V4;

  return 0;
}

void
otrv4_build_query_message(/*@unique@*/ char *query_message, const otrv4_t *otr, const char *message) {
  strcpy(query_message, query);

  if ((otr->supported_versions & OTR_ALLOW_V3) > 0) {
    strcat(query_message, "3");
  }

  if ((otr->supported_versions & OTR_ALLOW_V4) > 0) {
    strcat(query_message, "4");
  }

  strcat(query_message, "? ");
  strcat(query_message, message);
}

//TODO: should this care about UTF8?
//TODO: should this deal with buffer overflows?
int
otrv4_build_whitespace_tag(/*@unique@*/ char *whitespace_tag, const otrv4_t *otr, const char *message) {

  strcpy(whitespace_tag, tag_base);

  if ((otr->supported_versions & OTR_ALLOW_V4) > 0) {
    strcat(whitespace_tag, tag_version_v4);
  }

  if ((otr->supported_versions & OTR_ALLOW_V3) > 0) {
    strcat(whitespace_tag, tag_version_v3);
  }

  strcat(whitespace_tag, message);

  return 0;
}

static int
otrv4_message_contains_tag(const char *message) {
  if (strstr(message, tag_base)) {
    return 1;
  } else {
    return 0;
  }
}

static void
otrv4_message_to_display_without_tag(otrv4_t *otr, const char *message, const char *tag_version) {
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
otrv4_message_to_display_set(otrv4_t *otr, const char *message) {
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
otrv4_running_version_set_from_tag(otrv4_t *otr, const char *message) {
    char *tag_v4;
    char *tag_v3;
    tag_v4 = strstr(message, tag_version_v4);
    if (tag_v4) {
      otr->running_version = V4;
      return;
    }
    tag_v3 = strstr(message, tag_version_v3);
    if (tag_v3) {
      otr->running_version = V3;
      return;
    }
}

static int
otrv4_message_is_query(const char *message) {
  if (strstr(message, query)) {
    return 1;
  } else {
    return 0;
  }
}

static void
otrv4_running_version_set_from_query(otrv4_t *otr, const char *message) {
  char *v4;
  char *v3;
  v4 = strstr(message, "4");
    if (v4) {
      otr->running_version = V4;
      return;
    }
  v3 = strstr(message, "3");
    if (v3) {
      otr->running_version = V3;
      return;
    }
}

static void
otrv4_pre_key_set(otrv4_t *otr, /*@only@*/ dake_pre_key_t *pre_key) {
  if(otr->pre_key != NULL) {
    free(otr->pre_key);
  }
  otr->pre_key = pre_key;
}

static void
otrv4_in_message_parse(otrv4_in_message_t *target, const char *message) {
  if (otrv4_message_contains_tag(message) != 0) {
    target->type = IN_MSG_TAGGED_PLAINTEXT;
  } else if (otrv4_message_is_query(message) != 0) {
    target->type = IN_MSG_QUERY_STRING;
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
  otrv4_state_set(otr, OTR_STATE_AKE_IN_PROGRESS);

  switch (otr->running_version) {
  case V4:
    otrv4_message_to_display_without_tag(otr, message->raw_text, tag_version_v4);
    otrv4_pre_key_set(otr, dake_compute_pre_key());
    break;
  case V3:
    otrv3_receive_message(message->raw_text);
    break;
  default:
      //TODO Do we exit(1)?
    break;
  }
}

static void
otrv4_receive_query_string(otrv4_t *otr, otrv4_in_message_t *message) {
  if (message->raw_text == NULL) {
    return;
  }
  otrv4_running_version_set_from_query(otr, message->raw_text);
  otrv4_state_set(otr, OTR_STATE_AKE_IN_PROGRESS);

  switch (otr->running_version) {
  case V4:
    otrv4_pre_key_set(otr, dake_compute_pre_key());
    break;
  case V3:
    otrv3_receive_message(message->raw_text);
    break;
  default:
      //TODO Do we exit(1)?
    break;
  }
}

static otrv4_in_message_t *
otrv4_in_message_new() {
  otrv4_in_message_t *input = malloc(sizeof(otrv4_in_message_t));

  if(input == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  input->type = 0;
  input->raw_text = NULL;

  return input;
}

void
otrv4_receive_message(otrv4_t *otr, const char *message) {
  otrv4_in_message_t *input = otrv4_in_message_new();
  otrv4_in_message_parse(input, message);

  switch (input->type) {
  case IN_MSG_PLAINTEXT:
    otrv4_receive_plaintext(otr, input);
    break;

  case IN_MSG_TAGGED_PLAINTEXT:
    otrv4_receive_tagged_plaintext(otr, input);
    break;

  case IN_MSG_QUERY_STRING:
    otrv4_receive_query_string(otr, input);
    break;
  }

  free(input->raw_text);
  free(input);
}
