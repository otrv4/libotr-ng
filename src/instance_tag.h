#ifndef OTRNG_INSTANCE_TAG_H
#define OTRNG_INSTANCE_TAG_H

#include <stdint.h>
#include <stdio.h>

#include "error.h"
#include "shared.h"

#define MIN_VALID_INSTAG 0x00000100

typedef struct {
  char *account;
  char *protocol;
  unsigned int value;
} otrng_instag_t;

API otrng_bool_t otrng_instag_get(otrng_instag_t *otrng_instag,
                                  const char *account, const char *protocol,
                                  FILE *filename);

API void otrng_instag_free(otrng_instag_t *instag);

#ifdef OTRNG_INSTANCE_TAG_PRIVATE
#endif

#endif
