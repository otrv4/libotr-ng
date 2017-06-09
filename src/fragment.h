#ifndef FRAGMENT_H
#define FRAGMENT_H

#include "error.h"
#include "str.h"

#define FRAGMENT_HEADER_LEN 37

typedef struct {
  string_t *pieces;
  int total;
} fragment_message_t;

typedef enum {
  OTR4_FRAGMENT_UNFRAGMENTED,
  OTR4_FRAGMENT_INCOMPLETE,
  OTR4_FRAGMENT_FINISH
} fragment_status;

typedef struct {
  unsigned int K, N;
  string_t fragment;
  size_t fragment_len;
  fragment_status status;
} fragment_context_t;

fragment_context_t *fragment_context_new(void);
void fragment_context_free(fragment_context_t *context);

otr4_err_t otr4_fragment_message(int mms, fragment_message_t *fragments,
                                 int our_instance, int their_instance,
                                 const string_t message);

otr4_err_t otr4_defragment_message(fragment_context_t *context,
                                   const string_t message);

#endif
