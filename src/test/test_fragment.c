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

#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "../fragment.h"

void test_create_fragments(void) {
  int max_size = 48;
  char *message = "one two tree";
  char frag_without_identifier[35];

  otrng_message_to_send_s *frag_message =
      malloc(sizeof(otrng_message_to_send_s));

  otrng_assert_is_success(
      otrng_fragment_message(max_size, frag_message, 1, 2, message));

  strncpy(frag_without_identifier, frag_message->pieces[0] + 14, 35);
  g_assert_cmpstr(frag_without_identifier, ==,
                  "00000001|00000002,00001,00004,one,");
  strncpy(frag_without_identifier, frag_message->pieces[1] + 14, 35);
  g_assert_cmpstr(frag_without_identifier, ==,
                  "00000001|00000002,00002,00004, tw,");
  strncpy(frag_without_identifier, frag_message->pieces[2] + 14, 35);
  g_assert_cmpstr(frag_without_identifier, ==,
                  "00000001|00000002,00003,00004,o t,");
  strncpy(frag_without_identifier, frag_message->pieces[3] + 14, 35);
  g_assert_cmpstr(frag_without_identifier, ==,
                  "00000001|00000002,00004,00004,ree,");

  g_assert_cmpint(frag_message->total, ==, 4);

  otrng_message_free(frag_message);
}

void test_defragment_valid_message(void) {
  string_p fragments[2];
  fragments[0] = "?OTR|00000000|00000001|00000002,00001,00002,one ,";
  fragments[1] = "?OTR|00000000|00000001|00000002,00002,00002,more,";

  fragment_context_s *context;
  context = otrng_fragment_context_new();

  char *unfrag = NULL;
  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, context, fragments[0], 2));

  g_assert_cmpint(context->total, ==, 2);
  g_assert_cmpint(context->count, ==, 1);
  otrng_assert(!unfrag);
  otrng_assert(context->status == FRAGMENT_INCOMPLETE);

  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, context, fragments[1], 2));

  g_assert_cmpint(context->total, ==, 2);
  g_assert_cmpint(context->count, ==, 2);
  g_assert_cmpint(context->total_message_len, ==, 8);
  g_assert_cmpstr(unfrag, ==, "one more");
  otrng_assert(context->status == FRAGMENT_COMPLETE);

  free(unfrag);
  unfrag = NULL;
  otrng_fragment_context_free(context);
}

void test_defragment_single_fragment(void) {
  string_p msg = "?OTR|00000000|00000001|00000002,00001,00001,small lol,";

  fragment_context_s *context;
  context = otrng_fragment_context_new();

  char *unfrag = NULL;
  otrng_assert_is_success(otrng_unfragment_message(&unfrag, context, msg, 2));

  g_assert_cmpint(context->total, ==, 1);
  g_assert_cmpint(context->count, ==, 1);
  g_assert_cmpint(context->total_message_len, ==, 9);
  g_assert_cmpstr(unfrag, ==, "small lol");
  otrng_assert(context->status == FRAGMENT_COMPLETE);

  free(unfrag);
  unfrag = NULL;
  otrng_fragment_context_free(context);
}

void test_defragment_without_comma_fails(void) {
  string_p msg = "?OTR|00000000|00000001|00000002,00001,00001,blergh";

  fragment_context_s *context;
  context = otrng_fragment_context_new();

  char *unfrag = NULL;
  otrng_assert_is_error(otrng_unfragment_message(&unfrag, context, msg, 2));
  g_assert_cmpint(context->total, ==, 0);
  g_assert_cmpint(context->count, ==, 0);
  g_assert_cmpint(context->total_message_len, ==, 0);
  g_assert_cmpstr(unfrag, ==, NULL);

  free(unfrag);
  unfrag = NULL;
  otrng_fragment_context_free(context);
}

void test_defragment_with_different_total_fails(void) {
  string_p fragments[2];
  fragments[0] = "?OTR|00000000|00000001|00000002,00001,00003,mess with,";
  fragments[1] = "?OTR|00000000|00000001|00000002,00002,00002,total,";

  fragment_context_s *context;
  context = otrng_fragment_context_new();

  char *unfrag = NULL;
  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, context, fragments[0], 2));
  otrng_assert(context->status == FRAGMENT_INCOMPLETE);
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 3);
  g_assert_cmpint(context->count, ==, 1);

  otrng_assert_is_error(
      otrng_unfragment_message(&unfrag, context, fragments[1], 2));
  otrng_assert(context->status == FRAGMENT_INCOMPLETE);
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 3);
  g_assert_cmpint(context->count, ==, 1);

  otrng_fragment_context_free(context);
}

void test_defragment_fragment_twice_fails(void) {
  string_p fragments[2];
  fragments[0] = "?OTR|00000000|00000001|00000002,00001,00002,same twice,";
  fragments[1] = "?OTR|00000000|00000001|00000002,00001,00002,same twice,";

  fragment_context_s *context;
  context = otrng_fragment_context_new();

  char *unfrag = NULL;
  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, context, fragments[0], 2));
  otrng_assert(context->status == FRAGMENT_INCOMPLETE);
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 2);
  g_assert_cmpint(context->count, ==, 1);

  otrng_assert_is_error(
      otrng_unfragment_message(&unfrag, context, fragments[1], 2));
  otrng_assert(context->status == FRAGMENT_INCOMPLETE);
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 2);
  g_assert_cmpint(context->count, ==, 1);

  otrng_fragment_context_free(context);
}

void test_defragment_out_of_order_message(void) {
  string_p fragments[3];
  fragments[0] = "?OTR|00000000|00000001|00000002,00003,00003,send,";
  fragments[1] = "?OTR|00000000|00000001|00000002,00002,00003,fragment ,";
  fragments[2] = "?OTR|00000000|00000001|00000002,00001,00003,one more ,";

  fragment_context_s *context;
  context = otrng_fragment_context_new();

  char *unfrag = NULL;
  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, context, fragments[0], 2));
  otrng_assert(context->status == FRAGMENT_INCOMPLETE);
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 3);
  g_assert_cmpint(context->count, ==, 1);

  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, context, fragments[1], 2));
  otrng_assert(context->status == FRAGMENT_INCOMPLETE);
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 3);
  g_assert_cmpint(context->count, ==, 2);

  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, context, fragments[2], 2));
  otrng_assert(context->status == FRAGMENT_COMPLETE);
  g_assert_cmpstr(unfrag, ==, "one more fragment send");
  g_assert_cmpint(context->total, ==, 3);
  g_assert_cmpint(context->count, ==, 3);
  g_assert_cmpint(context->total_message_len, ==, 22);

  free(unfrag);
  unfrag = NULL;
  otrng_fragment_context_free(context);
}

void test_defragment_fails_for_invalid_tag(void) {
  string_p msg = "?OTR|00000000|00000001|00000002,00001,00001,small lol,";

  fragment_context_s *context;
  context = otrng_fragment_context_new();

  char *unfrag = NULL;
  otrng_assert_is_error(otrng_unfragment_message(&unfrag, context, msg, 1));

  g_assert_cmpint(context->total, ==, 0);
  g_assert_cmpint(context->count, ==, 0);
  g_assert_cmpint(context->total_message_len, ==, 0);
  g_assert_cmpstr(unfrag, ==, NULL);
  otrng_assert(context->status == FRAGMENT_COMPLETE);

  free(unfrag);
  unfrag = NULL;
  otrng_fragment_context_free(context);
}

void test_defragment_regular_otr_message(void) {
  string_p msg = "?OTR:not a fragmented message.";

  fragment_context_s *context;
  context = otrng_fragment_context_new();

  char *unfrag = NULL;
  otrng_assert_is_success(otrng_unfragment_message(&unfrag, context, msg, 1));

  g_assert_cmpint(context->total, ==, 0);
  g_assert_cmpint(context->count, ==, 0);
  g_assert_cmpint(context->total_message_len, ==, 0);
  g_assert_cmpstr(unfrag, ==, msg);
  otrng_assert(context->status == FRAGMENT_UNFRAGMENTED);

  free(unfrag);
  unfrag = NULL;
  otrng_fragment_context_free(context);
}
