#include "fragment.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

otr4_err_t otr4_fragment_message(int mms, fragment_message_t *fragments,
                                int our_instance, int their_instance,
                                const string_t message)
{
  size_t msglen = strlen(message);
  size_t limit_piece = mms - FRAGMENT_HEADER_LEN;
  string_t *pieces;
  int piece_len = 0;

  fragments->total = ((msglen-1) / (mms - FRAGMENT_HEADER_LEN)) + 1;

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
        "?OTR|%08x|%08x,%05x,%05x,%s,",
        our_instance, their_instance, curfrag, fragments->total, piece_data);
    piece[piece_len + FRAGMENT_HEADER_LEN] = 0;

    pieces[curfrag - 1] = piece;

    free(piece_data);
    index_len += piece_len;
    message += piece_len;
  }

  fragments->pieces = pieces;
  return OTR4_SUCCESS;
}
