#include "fragment.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_FORMAT "?OTR|%08x|%08x,%05x,%05x,%s,"

otr4_message_to_send_t *otr4_message_new() {
  otr4_message_to_send_t *msg = malloc(sizeof(otr4_message_to_send_t));
  if (!msg)
    return NULL;

  msg->pieces = NULL;
  msg->total = 0;

  return msg;
}

void otr4_message_free(otr4_message_to_send_t *message) {
  if (!message)
    return;

  int i;
  for (i = 0; i < message->total; i++)
    free(message->pieces[i]);

  free(message->pieces);
  message->pieces = NULL;

  message->total = 0;

  free(message);
}

fragment_context_t *fragment_context_new(void) {
  fragment_context_t *context = malloc(sizeof(fragment_context_t));
  context->N = 0;
  context->K = 0;
  context->fragment = otrv4_strdup("");
  context->fragment_len = 0;
  context->status = OTR4_FRAGMENT_UNFRAGMENTED;

  return context;
}

void fragment_context_free(fragment_context_t *context) {
  context->N = 0;
  context->K = 0;
  context->status = OTR4_FRAGMENT_UNFRAGMENTED;
  free(context->fragment);
  context->fragment = NULL;
  free(context);
}

otr4_err_t otr4_fragment_message(int max_size,
                                 otr4_message_to_send_t *fragments,
                                 int our_instance, int their_instance,
                                 const string_t message) {
  size_t msg_len = strlen(message);
  size_t limit_piece = max_size - FRAGMENT_HEADER_LEN;
  string_t *pieces;
  int piece_len = 0;

  fragments->total = ((msg_len - 1) / (max_size - FRAGMENT_HEADER_LEN)) + 1;
  if (fragments->total > 65535)
    return OTR4_ERROR;

  size_t pieces_len = fragments->total * sizeof(string_t);
  pieces = malloc(pieces_len);
  if (!pieces)
    return OTR4_ERROR;

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
      return OTR4_ERROR;
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
      free(pieces);
      pieces = NULL;

      return OTR4_ERROR;
    }

    snprintf(piece, piece_len + FRAGMENT_HEADER_LEN, FRAGMENT_FORMAT,
             our_instance, their_instance, current_frag, fragments->total,
             piece_data);
    piece[piece_len + FRAGMENT_HEADER_LEN] = 0;

    pieces[current_frag - 1] = piece;

    free(piece_data);
    index_len += piece_len;
    message += piece_len;
  }

  fragments->pieces = pieces;

  return OTR4_SUCCESS;
}

static void initialize_fragment_context(fragment_context_t *context) {
  free(context->fragment);
  context->fragment = otrv4_strdup("");
  context->fragment_len = 0;

  context->N = 0;
  context->K = 0;
  context->status = OTR4_FRAGMENT_UNFRAGMENTED;
}

static otr4_err_t add_first_fragment(const char *msg, int msg_len,
                                     fragment_context_t *ctx) {
  char *buff = malloc(msg_len + 1);
  if (!buff)
    return OTR4_ERROR;

  memmove(buff, msg, msg_len);
  buff[msg_len] = '\0';
  ctx->fragment_len += msg_len;
  free(ctx->fragment);
  ctx->fragment = buff;

  return OTR4_SUCCESS;
}

static otr4_err_t append_fragment(const char *msg, int msg_len,
                                  fragment_context_t *ctx) {
  size_t new_buff_len = ctx->fragment_len + msg_len + 1;
  char *buff = realloc(ctx->fragment, new_buff_len);
  if (!buff)
    return OTR4_ERROR;

  memmove(buff + ctx->fragment_len, msg, msg_len);
  ctx->fragment_len += msg_len;
  buff[ctx->fragment_len] = '\0';
  ctx->fragment = buff;

  return OTR4_SUCCESS;
}

static otrv4_bool_t is_fragment(const string_t message) {
  if (strstr(message, "?OTR|") != NULL)
    return otrv4_true;

  return otrv4_false;
}

otr4_err_t otr4_unfragment_message(char **unfrag_msg,
                                   fragment_context_t *context,
                                   const string_t message,
                                   const int our_instance_tag) {
  if (is_fragment(message)) {
    *unfrag_msg = otrv4_strdup(message);
    initialize_fragment_context(context);
    return OTR4_SUCCESS;
  }

  int sender_tag = 0, receiver_tag = 0, start = 0, end = 0;
  int k = 0, n = 0;
  context->status = OTR4_FRAGMENT_INCOMPLETE;

  // TODO: check this format
  const string_t format = "?OTR|%08x|%08x,%05x,%05x,%n%*[^,],%n";
  sscanf(message, format, &sender_tag, &receiver_tag, &k, &n, &start, &end);

  if (our_instance_tag != receiver_tag && 0 != receiver_tag) {
    context->status = OTR4_FRAGMENT_COMPLETE;
    return OTR4_ERROR;
  }

  if (k == 0 || n == 0 || k > n) {
    initialize_fragment_context(context);
    return OTR4_SUCCESS;
  }

  int msg_len = end - start - 1;
  if (end <= start)
    return OTR4_ERROR;

  otr4_err_t err;
  if (k == 1) {
    err = add_first_fragment(message + start, msg_len, context);
    if (err != OTR4_SUCCESS)
      return err;

    context->N = n;
    context->K = k;

  } else {
    if (n == context->N && k == context->K + 1) {
      err = append_fragment(message + start, msg_len, context);
      if (err != OTR4_SUCCESS)
        return err;

      context->K = k;
    } else
      initialize_fragment_context(context);
  }

  if (context->N == context->K) {
    *unfrag_msg = otrv4_strdup(context->fragment);
    free(context->fragment);
    context->fragment = NULL;
    context->status = OTR4_FRAGMENT_COMPLETE;
  }

  return OTR4_SUCCESS;
}
