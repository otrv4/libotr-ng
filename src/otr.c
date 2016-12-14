#include <stdlib.h>
#include <stdio.h>

#include "otr.h"

static int OTR_SUPPORTED_VERSIONS[2] = { OTR_V3, OTR_V4 };

otr *
otr_malloc(void) {
  return (otr *) malloc(sizeof(otr));
}

int
otr_start(otr *otr) {
  otr->version = OTR_V4;
  otr->state = OTRSTATE_START;
  otr->supported_versions = OTR_SUPPORTED_VERSIONS;
  
  return 0;
}

void
otr_build_query_message(char *query_message, const otr *otr, const char *message) {
  const char *query ="?OTRv%i? %s";
  sprintf(query_message, query, otr->version, message);
}

void
otr_build_whitespace_tag(char *whitespace_tag, const otr *otr, const char *message) {
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

  if (otr->version == OTR_V4) {
    sprintf(whitespace_tag, "%s%s%s", tag_base, tag_version_v4, message);
  }
  if (otr->version == OTR_V3) {
    sprintf(whitespace_tag, "%s%s%s", tag_base, tag_version_v3, message);
  }
}

void
otr_version_downgrade(otr *otr) {
  otr->version = OTR_V3;
}

void
otr_free(otr *otr) {
  free(otr);
}
