#ifndef FRAGMENT_H
#define FRAGMENT_H

#include "error.h"
#include "str.h"

#define FRAGMENT_HEADER_LEN 37

typedef struct {
  string_t *pieces;
  int total;
} otr4_message_to_send_t;

typedef enum {
  OTR4_FRAGMENT_UNFRAGMENTED,
  OTR4_FRAGMENT_INCOMPLETE,
  OTR4_FRAGMENT_COMPLETE
} fragment_status;

typedef struct {
  unsigned int K, N;
  string_t fragment;
  size_t fragment_len;
  fragment_status status;
} fragment_context_t;

otr4_message_to_send_t *otr4_message_new();

void otr4_message_free(otr4_message_to_send_t *message);

fragment_context_t *fragment_context_new(void);

void fragment_context_free(fragment_context_t *context);

otr4_err_t otr4_fragment_message(int mms, otr4_message_to_send_t *fragments,
                                 int our_instance, int their_instance,
                                 const string_t message);

otr4_err_t otr4_unfragment_message(char **unfrag_msg,
                                   fragment_context_t *context,
                                   const string_t message,
                                   const int our_instance_tag);

#endif
