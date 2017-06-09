#include "fragment.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define FRAGMENT_FORMAT "?OTR|%08x|%08x,%05x,%05x,%s,"

fragment_context_t * fragment_context_new(void) {
  fragment_context_t *context = malloc(sizeof(fragment_context_t));
  context->N = 0;
  context->K = 0;
  context->fragment = NULL;
  context->fragment_len = 0;
  context->status = OTR4_FRAGMENT_UNFRAGMENTED;

  return context;
}

void fragment_context_free(fragment_context_t *context){
  context->N = 0;
  context->K = 0;
  free(context->fragment);
  context->fragment = NULL;
  free(context);
}

otr4_err_t otr4_fragment_message(int mms, fragment_message_t *fragments,
                                int our_instance, int their_instance,
                                const string_t message)
{
  size_t msglen = strlen(message);
  size_t limit_piece = mms - FRAGMENT_HEADER_LEN;
  string_t *pieces;
  int piece_len = 0;

  fragments->total = ((msglen-1) / (mms - FRAGMENT_HEADER_LEN)) + 1;
  if (fragments->total > 65535)
    return OTR4_ERROR;

  pieces = malloc(fragments->total * sizeof(string_t));
  if (!pieces)
    return OTR4_ERROR;


  for(int curfrag = 1; curfrag <= fragments->total; curfrag++) {
    int index_len = 0;
    string_t piece = NULL;
    string_t piece_data = NULL;

    if (msglen - index_len < limit_piece)
        piece_len = msglen - index_len;
    else
        piece_len = limit_piece;

    piece_data = malloc(piece_len + 1);
    if(!piece_data) {
        free(pieces);
        return OTR4_ERROR;
    }

    strncpy(piece_data, message, piece_len);
    piece_data[piece_len] = 0;

    piece = malloc(piece_len + FRAGMENT_HEADER_LEN + 1);
    if(!piece) {
        free(piece);
        free(piece_data);
        return OTR4_ERROR;
    }

    snprintf(piece, piece_len + FRAGMENT_HEADER_LEN,
            FRAGMENT_FORMAT, our_instance, their_instance, curfrag,
            fragments->total, piece_data);
    piece[piece_len + FRAGMENT_HEADER_LEN] = 0;

    pieces[curfrag - 1] = piece;

    free(piece_data);
    index_len += piece_len;
    message += piece_len;
  }

  fragments->pieces = pieces;
  return OTR4_SUCCESS;
}

static bool is_fragment(const string_t message) {
  //TODO: should test if ends with , ?
  return strstr(message, "?OTR|") != NULL;
}

otr4_err_t otr4_defragment_message(fragment_context_t *context, const string_t message)
{
  if (!is_fragment(message)) {
    context->fragment = malloc(strlen(message));
    if (!context->fragment)
      return OTR4_ERROR;

    strcpy(context->fragment, message);
    return OTR4_SUCCESS;
  }

  int sender_tag = 0, receiver_tag = 0, start = 0, end = 0;
  context->status = OTR4_FRAGMENT_INCOMPLETE;

  const string_t format = "?OTR|%08x|%08x,%05x,%05x,%n%*[^,],%n";
  sscanf(message, format, &sender_tag, &receiver_tag, &context->K,
        &context->N, &start, &end);

  if (context->K == 1) {
    int frag_len = end - start - 1;
    if (frag_len >= 1)
      context->fragment = malloc(frag_len +1);

    if (!context->fragment)
      return OTR4_ERROR;

    memmove(context->fragment, message + start, frag_len);
    context->fragment[frag_len] = '\0';
    context->fragment_len = frag_len;
  }

  return OTR4_SUCCESS;
}
