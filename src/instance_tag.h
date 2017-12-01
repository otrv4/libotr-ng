#ifndef INSTANCE_TAG_H
#define INSTANCE_TAG_H

#include <stdint.h>
#include <stdio.h>

#include "error.h"

typedef struct {
  char *account;
  char *protocol;
  unsigned int value;
} otrv4_instag_t;

otrv4_bool_t otrv4_instag_get(otrv4_instag_t *otrv4_instag, const char *account,
                              const char *protocol, FILE *filename);

void otr4_instag_free(otrv4_instag_t *instag);

#endif
