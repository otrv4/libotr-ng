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

#define FRAGMENT_FORMAT "?OTR|%08x|%08x|%08x,%05hu,%05hu,%.*s,"
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

  for (int i = 0; i < message->total; i++) {
    free(message->pieces[i]);
    message->pieces[i] = NULL;
  }

  free(message->pieces);
  message->pieces = NULL;

  free(message);
}

tstatic void initialize_fragment_context(fragment_context_s *context) {
  context->identifier = 0;
  context->count = 0;
  context->total = 0;
  context->total_message_len = 0;
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

tstatic void reset_fragment_context(fragment_context_s *context) {
  free_fragments_in_context(context);
  initialize_fragment_context(context);
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

static otrng_err create_fragment_message(char **dst, const char *piece,
                                         size_t piece_len, uint32_t identifier,
                                         uint32_t our_instance,
                                         uint32_t their_instance,
                                         uint32_t current, uint32_t total) {

  if (strlen(piece) < piece_len) {
    return ERROR;
  }

  *dst = malloc(FRAGMENT_HEADER_LEN + piece_len + 1);
  if (!*dst) {
    return ERROR;
  }

  snprintf(*dst, FRAGMENT_HEADER_LEN + piece_len + 1, FRAGMENT_FORMAT,
           identifier, our_instance, their_instance, current, total,
           (int)piece_len, piece);

  (*dst)[FRAGMENT_HEADER_LEN + piece_len] = 0;

  return SUCCESS;
}

static otrng_err
init_message_to_send_with_total(otrng_message_to_send_s *fragments, int total) {
  if (total < 1 || total > 65535) {
    return ERROR;
  }

  fragments->total = total;

  size_t pieces_len = fragments->total * sizeof(string_p);
  fragments->pieces = malloc(pieces_len);
  if (!fragments->pieces) {
    return ERROR;
  }

  for (int i = 0; i < fragments->total; i++) {
    fragments->pieces[i] = NULL;
  }

  return SUCCESS;
}

INTERNAL otrng_err otrng_fragment_message(int max_size,
                                          otrng_message_to_send_s *fragments,
                                          int our_instance, int their_instance,
                                          const string_p message) {
  size_t msg_len = strlen(message);
  size_t limit = max_size - FRAGMENT_HEADER_LEN;
  int total = ((msg_len - 1) / limit) + 1;

  if (!init_message_to_send_with_total(fragments, total)) {
    return ERROR;
  }

  uint32_t *identifier = gcry_random_bytes(4, GCRY_STRONG_RANDOM);

  for (int i = 0; i < fragments->total; i++) {
    int piece_len = msg_len < limit ? msg_len : limit;
    char **dst = fragments->pieces + i;

    if (!create_fragment_message(dst, message, piece_len, *identifier,
                                 our_instance, their_instance, i + 1,
                                 fragments->total)) {
      otrng_message_free(fragments);
      return ERROR;
    }

    message += piece_len;
    msg_len -= piece_len;
  }

  gcry_free(identifier);

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
                                            list_element_s **contexts,
                                            const string_p message,
                                            const int our_instance_tag) {
  *unfrag_msg = NULL;

  if (!contexts) {
    return ERROR;
  }

  if (!is_fragment(message)) {
    *unfrag_msg = otrng_strdup(message);
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

  fragment_context_s *context = NULL;
  for (list_element_s *current = *contexts; current; current = current->next) {
    if (!current->data) {
      continue;
    }

    fragment_context_s *ctx = current->data;
    if (ctx->identifier == fragment_identifier) {
      context = ctx;
      break;
    }
  }

  if (!context) {
    context = otrng_fragment_context_new();
    context->identifier = fragment_identifier;
    *contexts = otrng_list_add(context, *contexts);
  }

  if (i == 0 || t == 0 || i > t) {
    reset_fragment_context(context);
    return SUCCESS;
  }

  if (context->total != 0 && context->total != t) {
    return ERROR;
  }

  context->total = t;

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
      list_element_s *to_remove = otrng_list_get_by_value(context, *contexts);
      *contexts = otrng_list_remove_element(to_remove, *contexts);
      otrng_fragment_context_free(context);
      otrng_list_free_nodes(to_remove);
      return SUCCESS;
    }
    return ERROR;
  }

  return SUCCESS;
}
