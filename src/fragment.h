/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OTRNG_FRAGMENT_H
#define OTRNG_FRAGMENT_H

#include "error.h"
#include "shared.h"
#include "str.h"

/* ?OTR| + fragment_identifier + | + sender_instance_tag + receiver_instance_tag
 */
#define FRAGMENT_HEADER_LEN 46

typedef struct otrng_message_to_send_s {
  string_p *pieces;
  int total;
} otrng_message_to_send_s, otrng_message_to_send_p[1];

typedef enum {
  FRAGMENT_UNFRAGMENTED,
  FRAGMENT_INCOMPLETE,
  FRAGMENT_COMPLETE
} fragment_status;

typedef struct fragment_context_s {
  uint32_t identifier;
  unsigned int K, N;
  string_p fragment;
  size_t fragment_len;
  fragment_status status;
} fragment_context_s, fragment_context_p[1];

API otrng_message_to_send_s *otrng_message_new(void);

API void otrng_message_free(otrng_message_to_send_s *message);

INTERNAL fragment_context_s *otrng_fragment_context_new(void);

INTERNAL void otrng_fragment_context_free(fragment_context_s *context);

INTERNAL otrng_err otrng_fragment_message(int mms,
                                          otrng_message_to_send_s *fragments,
                                          int our_instance, int their_instance,
                                          const string_p message);

INTERNAL otrng_err otrng_unfragment_message(char **unfrag_msg,
                                            fragment_context_s *context,
                                            const string_p message,
                                            const int our_instance_tag);

#ifdef OTRNG_FRAGMENT_PRIVATE
#endif

#endif
