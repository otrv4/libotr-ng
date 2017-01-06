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

otr_t *
otr_new(void) {
  otr_t *otr = malloc(sizeof(otr_t));
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
otr_free(/*@only@*/ otr_t *otr) {
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
otr_version_support_v3(otr_t *otr) {
  otr->supported_versions |= OTR_ALLOW_V3;
}

int
otr_start(otr_t *otr) {
  otr->state = OTR_STATE_START;
  otr->supported_versions = OTR_ALLOW_V4;

  return 0;
}

void
otr_build_query_message(/*@unique@*/ char *query_message, const otr_t *otr, const char *message) {
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
otr_build_whitespace_tag(/*@unique@*/ char *whitespace_tag, const otr_t *otr, const char *message) {

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
otr_message_contains_tag(const char *message) {
  if (strstr(message, tag_base)) {
    return 1;
  } else {
    return 0;
  }
}

static void
otr_message_to_display_without_tag(otr_t *otr, const char *message, const char *tag_version) {
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
otr_message_to_display_set(otr_t *otr, const char *message) {
  if(otr->message_to_display != NULL) {
      free(otr->message_to_display);
  }
  otr->message_to_display = otrv4_strdup(message);
}

static void
otr_state_set(otr_t *otr, stateFlag target) {
  otr->state = target;
}

static void
otr_running_version_set_from_tag(otr_t *otr, const char *message) {
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
otr_message_is_query(const char *message) {
  if (strstr(message, query)) {
    return 1;
  } else {
    return 0;
  }
}

static void
otr_running_version_set_from_query(otr_t *otr, const char *message) {
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
otr_pre_key_set(otr_t *otr, /*@only@*/ dake_pre_key_t *pre_key) {
  if(otr->pre_key != NULL) {
    free(otr->pre_key);
  }
  otr->pre_key = pre_key;
}

static void
otr_in_message_parse(otr_in_message_t *target, const char *message) {
  if (otr_message_contains_tag(message) != 0) {
    target->type = IN_MSG_TAGGED_PLAINTEXT;
  } else if (otr_message_is_query(message) != 0) {
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
otr_receive_plaintext(otr_t *otr, const otr_in_message_t *message) {
  if (message->raw_text == NULL) {
    return;
  }

  otr_message_to_display_set(otr, message->raw_text);
  if (otr->state != OTR_STATE_START) {
    if(otr->warning != NULL) {
      free(otr->warning);
    }
    otr->warning = otrv4_strdup("The above message was received unencrypted.");
  }
}

static void
otr_receive_tagged_plaintext(otr_t *otr, const otr_in_message_t *message) {
  if (message->raw_text == NULL) {
    return;
  }
  otr_running_version_set_from_tag(otr, message->raw_text);
  otr_state_set(otr, OTR_STATE_AKE_IN_PROGRESS);

  switch (otr->running_version) {
  case V4:
    otr_message_to_display_without_tag(otr, message->raw_text, tag_version_v4);
    otr_pre_key_set(otr, dake_compute_pre_key());
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
otr_receive_query_string(otr_t *otr, otr_in_message_t *message) {
  if (message->raw_text == NULL) {
    return;
  }
  otr_running_version_set_from_query(otr, message->raw_text);
  otr_state_set(otr, OTR_STATE_AKE_IN_PROGRESS);

  switch (otr->running_version) {
  case V4:
    otr_pre_key_set(otr, dake_compute_pre_key());
    break;
  case V3:
    otrv3_receive_message(message->raw_text);
    break;
  default:
      //TODO Do we exit(1)?
    break;
  }
}

static otr_in_message_t *
otr_in_message_new() {
  otr_in_message_t *input = malloc(sizeof(otr_in_message_t));

  if(input == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  input->type = 0;
  input->raw_text = NULL;

  return input;
}

void
otr_receive_message(otr_t *otr, const char *message) {
  otr_in_message_t *input = otr_in_message_new();
  otr_in_message_parse(input, message);

  switch (input->type) {
  case IN_MSG_PLAINTEXT:
    otr_receive_plaintext(otr, input);
    break;

  case IN_MSG_TAGGED_PLAINTEXT:
    otr_receive_tagged_plaintext(otr, input);
    break;

  case IN_MSG_QUERY_STRING:
    otr_receive_query_string(otr, input);
    break;
  }

  free(input->raw_text);
  free(input);
}
