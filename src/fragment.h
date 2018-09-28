/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
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
#include "list.h"
#include "shared.h"
#include "str.h"

/* ?OTR|identifier|sender_instance_tag|receiver_instance_tag,
 * index,total,,*/
#define FRAGMENT_HEADER_LEN 45

typedef struct otrng_message_to_send_s {
  string_p *pieces;
  int total;
} otrng_message_to_send_s;

typedef struct fragment_context_s {
  uint32_t identifier;
  unsigned int total, count;
  size_t total_message_len;
  time_t last_fragment_received_at;
  string_p *fragments;
} fragment_context_s;

INTERNAL void otrng_fragment_context_free(fragment_context_s *context);

INTERNAL otrng_result otrng_fragment_message(int max_size,
                                             otrng_message_to_send_s *fragments,
                                             int our_instance,
                                             int their_instance,
                                             const string_p message);

INTERNAL otrng_result otrng_unfragment_message(char **unfrag_message,
                                               list_element_s **contexts,
                                               const string_p message,
                                               const uint32_t our_instance_tag);

INTERNAL otrng_result otrng_expire_fragments(time_t now,
                                             uint32_t expiration_time,
                                             list_element_s **contexts);

#ifdef OTRNG_FRAGMENT_PRIVATE

otrng_message_to_send_s *otrng_message_new(void);

tstatic void otrng_message_free(otrng_message_to_send_s *message);

/*@null@*/ fragment_context_s *otrng_fragment_context_new(void);

#endif

#endif
