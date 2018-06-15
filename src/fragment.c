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

#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OTRNG_FRAGMENT_PRIVATE

#include "fragment.h"
#include "list.h"

#define FRAGMENT_FORMAT "?OTR|%08x|%08x|%08x,%05hu,%05hu,%s,"
#define UNFRAGMENT_FORMAT "?OTR|%08x|%08x|%08x,%05hu,%05hu,%n%*[^,],%n"

API otrng_message_to_send_s *otrng_message_new() {
  otrng_message_to_send_s *msg = malloc(sizeof(otrng_message_to_send_s));
  if (!msg) {
    return NULL;
  }

  msg->pieces = NULL;
  msg->total = 0;

  return msg;
}

API void otrng_message_free(otrng_message_to_send_s *message) {
  if (!message) {
    return;
  }

  int i;
  for (i = 0; i < message->total; i++) {
    free(message->pieces[i]);
    message->pieces[i] = NULL;
  }

  free(message->pieces);
  message->pieces = NULL;

  message->total = 0;

  free(message);
  message = NULL;
}

tstatic void initialize_fragment_context(fragment_context_s *context) {
  context->identifier = 0;
  context->count = 0;
  context->total = 0;
  context->total_message_len = 0;
  context->status = FRAGMENT_UNFRAGMENTED;
  context->fragments = NULL;
}

tstatic void free_fragments_in_context(fragment_context_s *context) {
  if (!context->fragments) {
    return;
  }

  for (int i = 0; i < context->total; i++) {
    free(context->fragments[i]);
    context->fragments[i] = NULL;
  }
}

INTERNAL /*@null@*/ fragment_context_s *otrng_fragment_context_new(void) {
  fragment_context_s *context = malloc(sizeof(fragment_context_s));
  if (!context) {
    return NULL;
  }

  initialize_fragment_context(context);
  return context;
}

INTERNAL void otrng_fragment_context_free(fragment_context_s *context) {
  free_fragments_in_context(context);
  free(context->fragments);
  context->fragments = NULL;
  free(context);
}

INTERNAL otrng_err otrng_fragment_message(int max_size,
                                          otrng_message_to_send_s *fragments,
                                          int our_instance, int their_instance,
                                          const string_p message) {
  size_t msg_len = strlen(message);
  size_t limit = max_size - FRAGMENT_HEADER_LEN;
  string_p *pieces;
  int piece_len = 0;

  fragments->total = ((msg_len - 1) / limit) + 1;
  if (fragments->total < 1 || fragments->total > 65535) {
    return ERROR;
  }

  size_t pieces_len = fragments->total * sizeof(string_p);
  pieces = malloc(pieces_len);
  if (!pieces) {
    return ERROR;
  }

  for (int i = 0; i < fragments->total; i++) {
    pieces[i] = NULL;
  }

  for (int current = 1; current <= fragments->total; current++) {
    string_p piece = NULL;
    string_p piece_data = NULL;

    piece_len = msg_len < limit ? msg_len : limit;
    piece_data = malloc(piece_len + 1);
    if (!piece_data) {
      for (int i = 0; i < fragments->total; i++) {
        free(pieces[i]);
        pieces[i] = NULL;
      }

      free(pieces);
      return ERROR;
    }

    strncpy(piece_data, message, piece_len);
    piece_data[piece_len] = 0;

    piece = malloc(piece_len + FRAGMENT_HEADER_LEN + 1);
    if (!piece) {
      for (int i = 0; i < fragments->total; i++) {
        free(pieces[i]);
        pieces[i] = NULL;
      }

      free(piece_data);
      piece_data = NULL;
      free(pieces);
      pieces = NULL;

      return ERROR;
    }

    uint32_t *identifier = gcry_random_bytes(32, GCRY_STRONG_RANDOM);

    snprintf(piece, piece_len + FRAGMENT_HEADER_LEN + 1, FRAGMENT_FORMAT,
             *identifier, our_instance, their_instance, (unsigned short)current,
             (unsigned short)fragments->total, piece_data);

    gcry_free(identifier);
    identifier = NULL;

    piece[piece_len + FRAGMENT_HEADER_LEN] = 0;

    pieces[current - 1] = piece;

    free(piece_data);
    piece_data = NULL;
    message += piece_len;
  }

  fragments->pieces = pieces;

  return SUCCESS;
}

tstatic otrng_bool is_fragment(const string_p message) {
  if (message != NULL && strstr(message, "?OTR|") == message) {
    return otrng_true;
  }

  return otrng_false;
}

tstatic otrng_err initialize_fragments(fragment_context_s *context) {
  context->fragments = malloc(sizeof(string_p) * context->total);
  if (!context->fragments) {
    return ERROR;
  }

  for (int i = 0; i < context->total; i++) {
    context->fragments[i] = NULL;
  }

  return SUCCESS;
}

tstatic otrng_err join_fragments(char **unfrag_msg,
                                 fragment_context_s *context) {
  *unfrag_msg = malloc(context->total_message_len + 1);
  if (!*unfrag_msg) {
    return ERROR;
  }

  char *end_msg = *unfrag_msg;
  for (int i = 0; i < context->total; i++) {
    end_msg = otrng_stpcpy(end_msg, context->fragments[i]);
  }

  return SUCCESS;
}

tstatic otrng_err copy_fragment_to_context(fragment_context_s *context,
                                           unsigned short i,
                                           const string_p message,
                                           uint32_t fragment_len) {
  char *fragment = malloc(fragment_len + 1);
  if (!fragment) {
    return ERROR;
  }

  memcpy(fragment, message, fragment_len);
  fragment[fragment_len] = '\0';
  context->fragments[i - 1] = fragment;
  context->total_message_len += fragment_len;
  return SUCCESS;
}

INTERNAL otrng_err otrng_unfragment_message(char **unfrag_msg,
                                            fragment_context_s *context,
                                            const string_p message,
                                            const int our_instance_tag) {
  if (!is_fragment(message)) {
    *unfrag_msg = otrng_strdup(message);
    initialize_fragment_context(context);
    return SUCCESS;
  }

  uint32_t fragment_identifier, sender_tag, receiver_tag, start = 0, end = 0;
  unsigned short i, t;

  sscanf(message, UNFRAGMENT_FORMAT, &fragment_identifier, &sender_tag,
         &receiver_tag, &i, &t, &start, &end);

  if (end <= start) {
    return ERROR;
  }

  if (our_instance_tag != receiver_tag && 0 != receiver_tag) {
    return ERROR;
  }

  if (i == 0 || t == 0 || i > t) {
    initialize_fragment_context(context);
    return SUCCESS;
  }

  if (context->total != 0 && context->total != t) {
    return ERROR;
  }

  context->total = t;
  context->status = FRAGMENT_INCOMPLETE;

  if (context->fragments == NULL) {
    if (!initialize_fragments(context)) {
      return ERROR;
    }
  }

  if (context->fragments[i - 1] != NULL) {
    return ERROR;
  }

  uint32_t fragment_len = end - start - 1;
  if (!copy_fragment_to_context(context, i, message + start, fragment_len)) {
    return ERROR;
  }

  context->count++;

  if (context->count == t) {
    if (join_fragments(unfrag_msg, context)) {
      context->status = FRAGMENT_COMPLETE;
      return SUCCESS;
    }
    return ERROR;
  }

  return SUCCESS;
}
