#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OTRV4_FRAGMENT_PRIVATE

#include "fragment.h"


#define FRAGMENT_FORMAT "?OTR|%08x|%08x,%05x,%05x,%s,"

API otrv4_message_to_send_t *otrv4_message_new() {
  otrv4_message_to_send_t *msg = malloc(sizeof(otrv4_message_to_send_t));
  if (!msg)
    return NULL;

  msg->pieces = NULL;
  msg->total = 0;

  return msg;
}

API void otrv4_message_free(otrv4_message_to_send_t *message) {
  if (!message)
    return;

  int i;
  for (i = 0; i < message->total; i++)
    free(message->pieces[i]);

  free(message->pieces);
  message->pieces = NULL;

  message->total = 0;

  free(message);
  message = NULL;
}

INTERNAL fragment_context_t *otrv4_fragment_context_new(void) {
  fragment_context_t *context = malloc(sizeof(fragment_context_t));
  context->N = 0;
  context->K = 0;
  context->fragment = otrv4_strdup("");
  context->fragment_len = 0;
  context->status = FRAGMENT_UNFRAGMENTED;

  return context;
}

INTERNAL void otrv4_fragment_context_free(fragment_context_t *context) {
  context->N = 0;
  context->K = 0;
  context->status = FRAGMENT_UNFRAGMENTED;
  free(context->fragment);
  context->fragment = NULL;
  free(context);
  context = NULL;
}

INTERNAL otrv4_err_t otrv4_fragment_message(int max_size,
                                  otrv4_message_to_send_t *fragments,
                                  int our_instance, int their_instance,
                                  const string_t message) {
  size_t msg_len = strlen(message);
  size_t limit_piece = max_size - FRAGMENT_HEADER_LEN;
  string_t *pieces;
  int piece_len = 0;

  fragments->total = ((msg_len - 1) / (max_size - FRAGMENT_HEADER_LEN)) + 1;
  if (fragments->total > 65535)
    return ERROR;

  size_t pieces_len = fragments->total * sizeof(string_t);
  pieces = malloc(pieces_len);
  if (!pieces)
    return ERROR;

  int current_frag;
  for (current_frag = 1; current_frag <= fragments->total; current_frag++) {
    int index_len = 0;
    string_t piece = NULL;
    string_t piece_data = NULL;

    if (msg_len - index_len < limit_piece)
      piece_len = msg_len - index_len;
    else
      piece_len = limit_piece;

    piece_data = malloc(piece_len + 1);
    if (!piece_data) {
      int i;
      for (i = 0; i < fragments->total; i++) {
        free(pieces[i]);
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
      }

      free(piece_data);
      piece_data = NULL;
      free(pieces);
      pieces = NULL;

      return ERROR;
    }

    snprintf(piece, piece_len + FRAGMENT_HEADER_LEN, FRAGMENT_FORMAT,
             our_instance, their_instance, current_frag, fragments->total,
             piece_data);
    piece[piece_len + FRAGMENT_HEADER_LEN] = 0;

    pieces[current_frag - 1] = piece;

    free(piece_data);
    piece_data = NULL;
    index_len += piece_len;
    message += piece_len;
  }

  fragments->pieces = pieces;

  return SUCCESS;
}

tstatic void initialize_fragment_context(fragment_context_t *context) {
  free(context->fragment);
  context->fragment = NULL;
  context->fragment = otrv4_strdup("");
  context->fragment_len = 0;

  context->N = 0;
  context->K = 0;
  context->status = FRAGMENT_UNFRAGMENTED;
}

tstatic otrv4_err_t add_first_fragment(const char *msg, int msg_len,
                                      fragment_context_t *ctx) {
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

tstatic otrv4_err_t append_fragment(const char *msg, int msg_len,
                                   fragment_context_t *ctx) {
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

tstatic otrv4_bool_t is_fragment(const string_t message) {
  if (strstr(message, "?OTR|") != NULL)
    return otrv4_true;

  return otrv4_false;
}

INTERNAL otrv4_err_t otrv4_unfragment_message(char **unfrag_msg,
                                    fragment_context_t *context,
                                    const string_t message,
                                    const int our_instance_tag) {
  if (is_fragment(message)) {
    *unfrag_msg = otrv4_strdup(message);
    initialize_fragment_context(context);
    return SUCCESS;
  }

  int sender_tag = 0, receiver_tag = 0, start = 0, end = 0;
  int k = 0, n = 0;
  context->status = FRAGMENT_INCOMPLETE;

  // TODO: check this format
  sscanf(message, "?OTR|%08x|%08x,%05x,%05x,%n%*[^,],%n", &sender_tag,
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

  otrv4_err_t err;
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
    *unfrag_msg = otrv4_strdup(context->fragment);
    free(context->fragment);
    context->fragment = NULL;
    context->status = FRAGMENT_COMPLETE;
  }

  return SUCCESS;
}
