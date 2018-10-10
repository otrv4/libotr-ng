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

#ifndef S_SPLINT_S
#include <gcrypt.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OTRNG_FRAGMENT_PRIVATE

#include "alloc.h"
#include "fragment.h"
#include "list.h"

/* Example:
   ?OTR|00000000|00000001|00000002,00001,00002,one , */
#define FRAGMENT_FORMAT "?OTR|%08x|%08x|%08x,%05hu,%05hu,%.*s,"
#define UNFRAGMENT_FORMAT "?OTR|%08x|%08x|%08x,%05hu,%05hu,%n%*[^,],%n"

otrng_message_to_send_s *otrng_message_new(void) {
  otrng_message_to_send_s *msg =
      otrng_xmalloc_z(sizeof(otrng_message_to_send_s));

  return msg;
}

tstatic void otrng_message_free(otrng_message_to_send_s *msg) {
  int i;

  if (!msg) {
    return;
  }

  for (i = 0; i < msg->total; i++) {
    free(msg->pieces[i]);
  }

  free(msg->pieces);
  free(msg);
}

tstatic void initialize_fragment_context(fragment_context_s *context) {
  context->identifier = 0;
  context->count = 0;
  context->total = 0;
  context->last_fragment_received_at = 0;
  context->total_message_len = 0;
  context->fragments = NULL;
}

tstatic void free_fragments_in_context(fragment_context_s *context) {
  unsigned int i;

  if (!context->fragments) {
    return;
  }

  for (i = 0; i < context->total; i++) {
    free(context->fragments[i]);
    context->fragments[i] = NULL;
  }
}

tstatic void reset_fragment_context(fragment_context_s *context) {
  free_fragments_in_context(context);
  initialize_fragment_context(context);
}

tstatic /*@null@*/ fragment_context_s *otrng_fragment_context_new(void) {
  fragment_context_s *context = otrng_xmalloc_z(sizeof(fragment_context_s));
  initialize_fragment_context(context);
  return context;
}

INTERNAL void otrng_fragment_context_free(fragment_context_s *context) {
  free_fragments_in_context(context);
  free(context->fragments);
  free(context);
}

static otrng_result create_fragment_message(char **dst, const char *piece,
                                            size_t piece_len,
                                            uint32_t identifier,
                                            uint32_t our_instance,
                                            uint32_t their_instance,
                                            uint16_t current, uint16_t total) {
  int res;

  if (strlen(piece) < piece_len) {
    return OTRNG_ERROR;
  }

  *dst = otrng_xmalloc_z(FRAGMENT_HEADER_LEN + piece_len + 1);

  res = snprintf(*dst, FRAGMENT_HEADER_LEN + piece_len + 1, FRAGMENT_FORMAT,
                 identifier, our_instance, their_instance, current, total,
                 (int)piece_len, piece);
  if (res < 0) {
    return OTRNG_ERROR;
  }

  (*dst)[FRAGMENT_HEADER_LEN + piece_len] = 0;

  return OTRNG_SUCCESS;
}

static otrng_result
init_message_to_send_with_total(otrng_message_to_send_s *fragments, int total) {
  size_t pieces_len;

  if (total < 1 || total > 65535) {
    return OTRNG_ERROR;
  }

  fragments->total = total;

  pieces_len = fragments->total * sizeof(string_p);
  fragments->pieces = otrng_xmalloc_z(pieces_len);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_fragment_message(int max_size,
                                             otrng_message_to_send_s *fragments,
                                             int our_instance,
                                             int their_instance,
                                             const string_p msg) {
  size_t msg_len = strlen(msg);
  size_t limit = max_size - FRAGMENT_HEADER_LEN;
  int total = ((msg_len - 1) / limit) + 1;
  uint32_t *identifier;
  int i;

  if (otrng_failed(init_message_to_send_with_total(fragments, total))) {
    return OTRNG_ERROR;
  }

  identifier = gcry_random_bytes(4, GCRY_STRONG_RANDOM);
  if (!identifier) {
    return OTRNG_ERROR;
  }

  for (i = 0; i < fragments->total; i++) {
    int piece_len = msg_len < limit ? msg_len : limit;
    char **dst = fragments->pieces + i;

    if (otrng_failed(create_fragment_message(dst, msg, piece_len, *identifier,
                                             our_instance, their_instance,
                                             i + 1, fragments->total))) {
      otrng_message_free(fragments);
      return OTRNG_ERROR;
    }

    msg += piece_len;
    msg_len -= piece_len;
  }

  gcry_free(identifier);

  return OTRNG_SUCCESS;
}

tstatic otrng_bool is_fragment(const string_p msg) {
  if (msg != NULL && strstr(msg, "?OTR|") == msg) {
    return otrng_true;
  }

  return otrng_false;
}

tstatic otrng_result initialize_fragments(fragment_context_s *context) {
  context->fragments = otrng_xmalloc_z(sizeof(string_p) * context->total);

  return OTRNG_SUCCESS;
}

tstatic otrng_result join_fragments(char **unfrag_msg,
                                    fragment_context_s *context) {
  char *end_msg;
  unsigned int i;

  *unfrag_msg = otrng_xmalloc_z(context->total_message_len + 1);

  end_msg = *unfrag_msg;
  for (i = 0; i < context->total; i++) {
    end_msg = otrng_stpcpy(end_msg, context->fragments[i]);
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result copy_fragment_to_context(fragment_context_s *context,
                                              unsigned short i,
                                              const string_p msg,
                                              uint32_t fragment_len) {
  char *fragment = otrng_xmalloc(fragment_len + 1);

  memcpy(fragment, msg, fragment_len);
  fragment[fragment_len] = '\0';
  context->fragments[i - 1] = fragment;
  context->total_message_len += fragment_len;
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_unfragment_message(char **unfrag_msg, list_element_s **contexts,
                         const string_p msg, const uint32_t our_instance_tag) {
  int start = 0, end = 0;
  uint32_t fragment_identifier, sender_tag, receiver_tag;
  uint16_t i, t;
  fragment_context_s *context = NULL;
  list_element_s *current;
  fragment_context_s *ctx;
  uint32_t fragment_len;

  *unfrag_msg = NULL;

  if (!contexts) {
    return OTRNG_ERROR;
  }

  if (!is_fragment(msg)) {
    *unfrag_msg = otrng_xstrdup(msg);

    return OTRNG_SUCCESS;
  }

  if (sscanf(msg, UNFRAGMENT_FORMAT, &fragment_identifier, &sender_tag,
             &receiver_tag, &i, &t, &start, &end) == EOF) {
    return OTRNG_ERROR;
  }

  if (our_instance_tag != receiver_tag && 0 != receiver_tag) {
    return OTRNG_SUCCESS;
  }

  if (end <= start) {
    return OTRNG_ERROR;
  }

  for (current = *contexts; current; current = current->next) {
    if (!current->data) {
      continue;
    }

    ctx = current->data;
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
    return OTRNG_SUCCESS;
  }

  if (context->total != 0 && context->total != t) {
    return OTRNG_ERROR;
  }

  context->total = t;

  if (context->fragments == NULL) {
    if (otrng_failed(initialize_fragments(context))) {
      return OTRNG_ERROR;
    }
  }

  if (context->fragments[i - 1] != NULL) {
    return OTRNG_ERROR;
  }

  fragment_len = end - start - 1;
  if (otrng_failed(
          copy_fragment_to_context(context, i, msg + start, fragment_len))) {
    return OTRNG_ERROR;
  }

  context->count++;
  context->last_fragment_received_at = time(NULL);

  if (context->count == t) {
    if (otrng_succeeded(join_fragments(unfrag_msg, context))) {
      list_element_s *to_remove = otrng_list_get_by_value(context, *contexts);
      *contexts = otrng_list_remove_element(to_remove, *contexts);
      otrng_fragment_context_free(context);
      otrng_list_free_nodes(to_remove);
      return OTRNG_SUCCESS;
    }
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_expire_fragments(time_t now,
                                             uint32_t expiration_time,
                                             list_element_s **contexts) {
  list_element_s *current = *contexts;

  while (current) {
    fragment_context_s *ctx = current->data;

    list_element_s *to_free = NULL;
    if ((ctx != NULL) &&
        (difftime(now, ctx->last_fragment_received_at) < expiration_time)) {
      *contexts = otrng_list_remove_element(current, *contexts);
      otrng_fragment_context_free(ctx);
      to_free = current;
    }

    current = current->next;
    otrng_list_free_nodes(to_free);
  }

  return OTRNG_SUCCESS;
}
