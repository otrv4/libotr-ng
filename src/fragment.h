#ifndef OTRNG_FRAGMENT_H
#define OTRNG_FRAGMENT_H

#include "error.h"
#include "shared.h"
#include "str.h"

#define FRAGMENT_HEADER_LEN 37

typedef struct {
  string_t *pieces;
  int total;
} otrng_message_to_send_t;

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

API otrng_message_to_send_t *otrng_message_new(void);

API void otrng_message_free(otrng_message_to_send_t *message);

INTERNAL fragment_context_t *otrng_fragment_context_new(void);

INTERNAL void otrng_fragment_context_free(fragment_context_t *context);

INTERNAL otrng_err_t otrng_fragment_message(int mms,
                                            otrng_message_to_send_t *fragments,
                                            int our_instance,
                                            int their_instance,
                                            const string_t message);

INTERNAL otrng_err_t otrng_unfragment_message(char **unfrag_msg,
                                              fragment_context_t *context,
                                              const string_t message,
                                              const int our_instance_tag);

#ifdef OTRNG_FRAGMENT_PRIVATE
#endif

#endif
