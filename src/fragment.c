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
  if (!msg)
    return NULL;

  msg->pieces = NULL;
  msg->total = 0;

  return msg;
}

API void otrng_message_free(otrng_message_to_send_s *message) {
  if (!message)
    return;

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

INTERNAL fragment_context_s *otrng_fragment_context_new(void) {
  fragment_context_s *context = malloc(sizeof(fragment_context_s));
  context->identifier = 0;
  context->C = 0;
  context->T = 0;
  context->fragment_len = 0;
  context->status = FRAGMENT_UNFRAGMENTED;
  context->fragment = NULL;
  context->stored_fragments = NULL;

  return context;
}

INTERNAL void otrng_fragment_context_free(fragment_context_s *context) {
  context->identifier = 0;
  context->C = 0;
  context->T = 0;
  context->status = FRAGMENT_UNFRAGMENTED;

  free(context->fragment);
  context->fragment = NULL;

  free(context);
  context = NULL;
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
  if (fragments->total < 1 || fragments->total > 65535)
    return ERROR;

  size_t pieces_len = fragments->total * sizeof(string_p);
  pieces = malloc(pieces_len);
  if (!pieces)
    return ERROR;

  for (int current = 1; current <= fragments->total; current++) {
    string_p piece = NULL;
    string_p piece_data = NULL;

    piece_len = msg_len < limit ? msg_len : limit;
    piece_data = malloc(piece_len + 1);
    if (!piece_data) {
      int i;
      for (i = 0; i < fragments->total; i++) {
        free(pieces[i]);
        pieces[i] = NULL;
      }

      free(pieces);
      pieces = NULL;
      return ERROR;
    }

    strncpy(piece_data, message, piece_len);
    piece_data[piece_len] = 0;

    piece = malloc(piece_len + FRAGMENT_HEADER_LEN + 1);
    if (!piece) {
      int i;
      for (i = 0; i < fragments->total; i++) {
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

    snprintf(piece, piece_len + FRAGMENT_HEADER_LEN, FRAGMENT_FORMAT,
             (uint32_t)*identifier, our_instance, their_instance,
             (unsigned short)current, (unsigned short)fragments->total,
             piece_data);

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

tstatic void initialize_fragment_context(fragment_context_s *context) {
  context->fragment_len = 0;

  context->identifier = 0;
  context->T = 0;
  context->C = 0;
  context->status = FRAGMENT_UNFRAGMENTED;
  context->fragment = NULL;
}

tstatic void join_fragments(list_element_s *node, void *context) {
  fragment_context_s *ctx = (void *)context;
  size_t msg_len = strlen(node->data);

  if (ctx->fragment == NULL) {
    ctx->fragment = malloc(ctx->fragment_len + 1);
    memcpy(ctx->fragment, node->data, msg_len);
  } else {
    ctx->fragment = realloc(ctx->fragment, ctx->fragment_len + msg_len);
    memmove(ctx->fragment + ctx->fragment_len, node->data, msg_len);
  }

  ctx->fragment_len += msg_len;
  ctx->fragment[ctx->fragment_len] = '\0';
}

tstatic otrng_bool is_fragment(const string_p message) {
  if (strstr(message, "?OTR|") != NULL)
    return otrng_true;

  return otrng_false;
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

  int fragment_identifier, sender_tag = 0, receiver_tag = 0, start = 0, end = 0;
  unsigned short i = 0, t = 0;

  sscanf(message, UNFRAGMENT_FORMAT, &fragment_identifier, &sender_tag,
         &receiver_tag, &i, &t, &start, &end);

  context->status = FRAGMENT_INCOMPLETE;

  if (our_instance_tag != receiver_tag && 0 != receiver_tag) {
    context->status = FRAGMENT_COMPLETE;
    return ERROR;
  }

  if (i == 0 || t == 0 || i > t) {
    initialize_fragment_context(context);
    return SUCCESS;
  }

  int msg_len = end - start - 1;
  if (end <= start)
    return ERROR;

  uint8_t *stored_fragment = malloc(msg_len + 1);
  if (!stored_fragment)
    return ERROR;

  memcpy(stored_fragment, message + start, msg_len);
  stored_fragment[msg_len] = '\0';

  context->stored_fragments =
      otrng_list_add(stored_fragment, context->stored_fragments);
  context->T = t;
  context->C++;

  if (context->C == t) {
    otrng_list_foreach(context->stored_fragments, join_fragments, context);
    *unfrag_msg = otrng_strdup(context->fragment);
    context->status = FRAGMENT_COMPLETE;
  }

  return SUCCESS;
}
