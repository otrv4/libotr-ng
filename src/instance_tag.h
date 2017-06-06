#ifndef INSTANCE_TAG_H
#define INSTANCE_TAG_H

#include <stdint.h>

typedef struct {
  char *account;
  char *protocol;
  uint32_t value;
} otrv4_instag_t;

int otr4_instag_generate(otrv4_instag_t *instag, char * account, char *protocol);

#endif
