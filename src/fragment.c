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
  context->K = 0;
  context->N = 0;
  context->fragment = otrng_strdup("");
  context->fragment_len = 0;
  context->status = FRAGMENT_UNFRAGMENTED;

  return context;
}

INTERNAL void otrng_fragment_context_free(fragment_context_s *context) {
  context->K = 0;
  context->N = 0;
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

// TODO: why?
tstatic void initialize_fragment_context(fragment_context_s *context) {
  free(context->fragment);
  context->fragment = NULL;
  context->fragment = otrng_strdup("");
  context->fragment_len = 0;

  context->N = 0;
  context->K = 0;
  context->status = FRAGMENT_UNFRAGMENTED;
}

tstatic otrng_err add_first_fragment(const char *msg, int msg_len,
                                     fragment_context_s *ctx) {
  char *buff = malloc(msg_len + 1);
  if (!buff)
    return ERROR;

  memmove(buff, msg, msg_len);
  buff[msg_len] = '\0';
  ctx->fragment_len += msg_len;
  free(ctx->fragment);
  ctx->fragment = buff;

  return SUCCESS;
}

tstatic otrng_err append_fragment(const char *msg, int msg_len,
                                  fragment_context_s *ctx) {
  size_t new_buff_len = ctx->fragment_len + msg_len + 1;
  char *buff = realloc(ctx->fragment, new_buff_len);
  if (!buff)
    return ERROR;

  memmove(buff + ctx->fragment_len, msg, msg_len);
  ctx->fragment_len += msg_len;
  buff[ctx->fragment_len] = '\0';
  ctx->fragment = buff;

  return SUCCESS;
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
  unsigned short k = 0, n = 0;

  context->status = FRAGMENT_INCOMPLETE;

  sscanf(message, UNFRAGMENT_FORMAT, &fragment_identifier, &sender_tag,
         &receiver_tag, &k, &n, &start, &end);

  if (our_instance_tag != receiver_tag && 0 != receiver_tag) {
    context->status = FRAGMENT_COMPLETE;
    return ERROR;
  }

  if (k == 0 || n == 0 || k > n) {
    initialize_fragment_context(context);
    return SUCCESS;
  }

  int msg_len = end - start - 1;
  if (end <= start)
    return ERROR;

  otrng_err err;
  if (k == 1) {
    err = add_first_fragment(message + start, msg_len, context);
    if (err != SUCCESS)
      return err;

    context->N = n;
    context->K = k;

  } else {
    if (n == context->N && k == context->K + 1) {
      err = append_fragment(message + start, msg_len, context);
      if (err != SUCCESS)
        return err;

      context->K = k;
    } else
      initialize_fragment_context(context);
  }

  if (context->N == context->K) {
    *unfrag_msg = otrng_strdup(context->fragment);
    free(context->fragment);
    context->fragment = NULL;
    context->status = FRAGMENT_COMPLETE;
  }

  return SUCCESS;
}
