#ifndef OTRV4_FRAGMENT_H
#define OTRV4_FRAGMENT_H

#include "shared.h"
#include "error.h"
#include "str.h"

#define FRAGMENT_HEADER_LEN 37

typedef struct {
  string_t *pieces;
  int total;
} otrv4_message_to_send_t;

typedef enum {
  FRAGMENT_UNFRAGMENTED,
  FRAGMENT_INCOMPLETE,
  FRAGMENT_COMPLETE
} fragment_status;

typedef struct {
  unsigned int K, N;
  string_t fragment;
  size_t fragment_len;
  fragment_status status;
} fragment_context_t;

API otrv4_message_to_send_t *otrv4_message_new(void);

API void otrv4_message_free(otrv4_message_to_send_t *message);

INTERNAL fragment_context_t *otrv4_fragment_context_new(void);

INTERNAL void otrv4_fragment_context_free(fragment_context_t *context);

INTERNAL otrv4_err_t otrv4_fragment_message(int mms, otrv4_message_to_send_t *fragments,
                                  int our_instance, int their_instance,
                                  const string_t message);

INTERNAL otrv4_err_t otrv4_unfragment_message(char **unfrag_msg,
                                    fragment_context_t *context,
                                    const string_t message,
                                    const int our_instance_tag);


#ifdef OTRV4_FRAGMENT_PRIVATE
#endif

#endif
