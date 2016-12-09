#include <stdlib.h>
#include <stdio.h>

#include "otr.h"

otr *
otr_malloc(void) {
  return (otr *) malloc(sizeof(otr));
}

int
otr_start(otr *otr) {
  otr->version = OTR_V4;
  otr->state = OTRSTATE_START;
  
  return 1;
}

void
otr_build_query_message(char *query_message, otr *otr, char *message) {
  const char *query ="?OTRv%i? %s";
  sprintf(query_message, query, otr->version, message);
}

void
otr_free(otr *otr) {
  free(otr);
}
