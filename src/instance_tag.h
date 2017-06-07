#ifndef INSTANCE_TAG_H
#define INSTANCE_TAG_H

#include <stdint.h>

typedef struct {
  char *account;
  char *protocol;
  uint32_t value;
} otrv4_instag_t;

otrv4_instag_t *otr4_instag_generate(const char * account, const char *protocol);

void otr4_instag_free(otrv4_instag_t *instag);

#endif
