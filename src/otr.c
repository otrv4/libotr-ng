#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "otr.h"
#include "otr_string.h"

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

static void *
otr_malloc(size_t size) {
  void *p = malloc(size);

  if (p) {
    return p;
  }

  fprintf(stderr, "Failed to allocate memory. Chao!\n");
  exit(EXIT_FAILURE);
}

void
otr_free(otr *otr) {
  free(otr);
}

otr *
otr_new(void) {
  otr *otr = otr_malloc(sizeof(otr));
  otr->supported_versions = otr_malloc(sizeof(int));

  return otr;
}

void
otr_version_support_v3(otr *otr) {
  *otr->supported_versions |= OTR_ALLOW_V3;
}

int
otr_start(otr *otr) {
  otr->state = &OTR_STATE_START;
  *otr->supported_versions = OTR_ALLOW_V4;

  return 0;
}

void
otr_build_query_message(char *query_message, const otr *otr, const char *message) {
  const char *query = "?OTRv";

  strcpy(query_message, query);

  if ((*otr->supported_versions & OTR_ALLOW_V3) > 0) {
    strcat(query_message, "3");
  }

  if ((*otr->supported_versions & OTR_ALLOW_V4) > 0) {
    strcat(query_message, "4");
  }

  strcat(query_message, "? ");
  strcat(query_message, message);
}

//TODO: should this care about UTF8?
//TODO: should this deal with buffer overflows?
int
otr_build_whitespace_tag(char *whitespace_tag, const otr *otr, const char *message) {

  strcpy(whitespace_tag, tag_base);
  
  if ((*otr->supported_versions & OTR_ALLOW_V4) > 0) {
    strcat(whitespace_tag, tag_version_v4);
  }

  if ((*otr->supported_versions & OTR_ALLOW_V3) > 0) {
    strcat(whitespace_tag, tag_version_v3);
  }

  strcat(whitespace_tag, message);

  return 0;
}

void
otr_receive_message(otr *otr, const char *message) {
  char *tag;
  tag = strstr(message, tag_base);

  int msg_lenght = strlen(message);
  if (tag) {
    int tag_lenght = strlen(tag_base) + strlen(tag_version_v4);
    int chars = msg_lenght - tag_lenght;
    otr->message_to_display = otr_malloc(chars);
    otr_string_cpy(otr->message_to_display, message, tag_lenght, chars);

    otr->state = &OTR_STATE_AKE_IN_PROGRESS;
  } else {
    char to_display[msg_lenght];
    otr->message_to_display = to_display;
    strcpy(otr->message_to_display, message);
  }
}
