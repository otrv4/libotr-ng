#include <stdlib.h>
#include <stdio.h>

#include "otr.h"

otr *otr_malloc(void) {
  return (otr *) malloc(sizeof(otr));
}

int otr_start(otr *otr) {
  otr->version = OTR_V4;
  otr->state = OTRSTATE_START;
  
  return 1;
}

void otr_free(otr *otr) {
  free(otr);
}
