#ifndef FRAGMENT_H
#define FRAGMENT_H

#include "error.h"
#include "str.h"

#define FRAGMENT_HEADER_LEN 37

typedef struct {
  string_t *pieces;
  int total;
} fragment_message_t;

otr4_err_t otr4_fragment_message(int mms, fragment_message_t *fragments,
                                int our_instance, int their_instance,
                                const string_t message);

#endif
