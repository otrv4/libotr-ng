#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "otr.h"

  const char tag_base[] = {
    '\x20', '\x09', '\x20', '\x20', '\x09', '\x09', '\x09', '\x09',
    '\x20', '\x09', '\x20', '\x09', '\x20', '\x09', '\x20', '\x20',
    '\0'
  };
  const char tag_version_v4[] = {
    '\x20', '\x20', '\x09', '\x09', '\x20', '\x09', '\x20', '\x20',
    '\0'
  };
  const char tag_version_v3[] = {
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

otr *
otr_new(void) {
  otr *otr = otr_malloc(sizeof(otr));
  otr->state = otr_malloc(sizeof(int));
  otr->supported_versions = otr_malloc(sizeof(int));

  return otr;
}

int
otr_start(otr *otr) {
  *otr->state = OTR_STATE_START;
  *otr->supported_versions = OTR_ALLOW_V4;

  return 0;
}

void
otr_version_support_v3(otr *otr) {
  *otr->supported_versions |= OTR_ALLOW_V3;
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
otr_free(otr *otr) {
  free(otr->state);
  free(otr);
}

void
otr_receive_message(otr *otr, const char *message) {
  char *tag;
  tag = strstr(message, tag_base);

  int msg_lenght = strlen(message);
  if (tag) {
    int tag_lenght = strlen(tag_base) + strlen(tag_version_v4);
    int chars = msg_lenght - tag_lenght;
    char to_display[chars];
    int char_at = 0;
    for (int i = tag_lenght; i < msg_lenght; i++) {
      to_display[char_at] = message[i];
      char_at++;
    }
    to_display[char_at] = '\0';
    otr->message_to_display = otr_malloc(sizeof(to_display));
    strcpy(otr->message_to_display, to_display);
  } else {
    char to_display[msg_lenght];
    otr->message_to_display = to_display;
    strcpy(otr->message_to_display, message);
  }
}
