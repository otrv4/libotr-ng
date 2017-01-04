#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mem.h"
#include "otr.h"

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

otr_t *
otr_new(void) {
  otr_t *otr = mem_alloc(sizeof(otr_t));
  otr->running_version = 0;
  otr->pre_key = NULL;

  return otr;
}

void
otr_free(otr_t *otr) {
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
otr_build_query_message(char *query_message, const otr_t *otr, const char *message) {
  const char *query = "?OTRv";

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
otr_build_whitespace_tag(char *whitespace_tag, const otr_t *otr, const char *message) {

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
  char *tag;
  if (strstr(message, tag_base)) {
    return 1;
  } else {
    return 0;
  }
}

static void
otr_message_to_display_without_tag(otr_t *otr, const char *message, const char *tag_version) {
  int msg_length = strlen(message);
  int tag_length = strlen(tag_base) + strlen(tag_version);
  int chars = msg_length - tag_length;
  char m[chars];
  otr->message_to_display = mem_alloc(chars);
  strncpy(otr->message_to_display, message+tag_length, chars + 1);
}

static void
otr_message_to_display_set(otr_t *otr, const char *message) {
  char to_display[strlen(message)];
  otr->message_to_display = to_display;
  strcpy(otr->message_to_display, message);
}

static void
otr_state_set(otr_t *otr, stateFlag target) {
    otr->state = target;
}

static void
otr_running_version_set(otr_t *otr, const char *message) {
    char *tag_v4;
    tag_v4 = strstr(message, tag_version_v4);
    if (tag_v4) {
      otr->running_version = V4;
      return;
    }
    char *tag_v3;
    tag_v3 = strstr(message, tag_version_v3);
    if (tag_v3) {
      otr->running_version = V3;
      return;
    }
}

void
otr_receive_message(otr_t *otr, const char *message) {
  if (otr_message_contains_tag(message)) {
    otr_running_version_set(otr, message);
    otr_state_set(otr, OTR_STATE_AKE_IN_PROGRESS);

    switch (otr->running_version) {
    case V4:
      otr_message_to_display_without_tag(otr, message, tag_version_v4);
      otr->pre_key = dake_compute_pre_key();
      break;
    case V3:
      otr_message_to_display_without_tag(otr, message, tag_version_v3);
      break;
    }

  } else {
    otr_message_to_display_set(otr, message);
    if (otr->state > OTR_STATE_START) {
      otr->warning = "The above message was received unencrypted.";
    }
  }
}
