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
  const char *message = "one two tree";

  otrng_message_to_send_s *frag_message =
      malloc(sizeof(otrng_message_to_send_s));

  otrng_assert_is_success(
      otrng_fragment_message(max_size, frag_message, 1, 2, message));

  g_assert_cmpstr(frag_message->pieces[0] + 14, ==,
                  "00000001|00000002,00001,00004,one,");
  g_assert_cmpstr(frag_message->pieces[1] + 14, ==,
                  "00000001|00000002,00002,00004, tw,");
  g_assert_cmpstr(frag_message->pieces[2] + 14, ==,
                  "00000001|00000002,00003,00004,o t,");
  g_assert_cmpstr(frag_message->pieces[3] + 14, ==,
                  "00000001|00000002,00004,00004,ree,");

  g_assert_cmpint(frag_message->total, ==, 4);

  otrng_message_free(frag_message);
}

void test_create_fragments_smaller_than_max_size(void) {
  int max_size = 50;
  const char *message = "one two";

  otrng_message_to_send_s *frag_message =
      malloc(sizeof(otrng_message_to_send_s));

  otrng_assert_is_success(
      otrng_fragment_message(max_size, frag_message, 1, 2, message));

  g_assert_cmpstr(frag_message->pieces[0] + 14, ==,
                  "00000001|00000002,00001,00002,one t,");
  g_assert_cmpstr(frag_message->pieces[1] + 14, ==,
                  "00000001|00000002,00002,00002,wo,");

  g_assert_cmpint(frag_message->total, ==, 2);
  otrng_message_free(frag_message);
}

void test_defragment_valid_message(void) {
  const string_p fragments[2];
  fragments[0] = "?OTR|00000000|00000001|00000002,00001,00002,one ,";
  fragments[1] = "?OTR|00000000|00000001|00000002,00002,00002,more,";

  fragment_context_s *context = NULL;
  list_element_s *list = NULL;

  char *unfrag = NULL;
  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, fragments[0], 2));

  context = list->data;
  g_assert_cmpint(context->total, ==, 2);
  g_assert_cmpint(context->count, ==, 1);
  otrng_assert(!unfrag);

  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, fragments[1], 2));

  otrng_assert(otrng_list_len(list) == 0);
  g_assert_cmpstr(unfrag, ==, "one more");

  free(unfrag);
  otrng_list_free_nodes(list);
}

void test_defragment_single_fragment(void) {
  const string_p msg = "?OTR|00000000|00000001|00000002,00001,00001,small lol,";

  list_element_s *list = NULL;
  char *unfrag = NULL;

  otrng_assert_is_success(otrng_unfragment_message(&unfrag, &list, msg, 2));

  otrng_assert(otrng_list_len(list) == 0);
  g_assert_cmpstr(unfrag, ==, "small lol");

  free(unfrag);
  otrng_list_free_nodes(list);
}

void test_defragment_without_comma_fails(void) {
  const string_p msg = "?OTR|00000000|00000001|00000002,00001,00001,blergh";

  list_element_s *list = NULL;

  char *unfrag = NULL;
  otrng_assert_is_error(otrng_unfragment_message(&unfrag, &list, msg, 2));

  otrng_assert(list == NULL);
  g_assert_cmpstr(unfrag, ==, NULL);

  free(unfrag);
  otrng_list_free_nodes(list);
}

void test_defragment_with_different_total_fails(void) {
  const string_p fragments[2];
  fragments[0] = "?OTR|00000000|00000001|00000002,00001,00003,mess with,";
  fragments[1] = "?OTR|00000000|00000001|00000002,00002,00002,total,";

  fragment_context_s *context = NULL;
  list_element_s *list = NULL;

  char *unfrag = NULL;
  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, fragments[0], 2));
  otrng_assert(!unfrag);

  context = list->data;
  g_assert_cmpint(context->total, ==, 3);
  g_assert_cmpint(context->count, ==, 1);

  otrng_assert_is_error(
      otrng_unfragment_message(&unfrag, &list, fragments[1], 2));

  context = list->data;
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 3);
  g_assert_cmpint(context->count, ==, 1);

  otrng_fragment_context_free(context);
  otrng_list_free_nodes(list);
}

void test_defragment_fragment_twice_fails(void) {
  const string_p fragments[2];
  fragments[0] = "?OTR|00000000|00000001|00000002,00001,00002,same twice,";
  fragments[1] = "?OTR|00000000|00000001|00000002,00001,00002,same twice,";

  fragment_context_s *context = NULL;
  list_element_s *list = NULL;

  char *unfrag = NULL;
  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, fragments[0], 2));

  context = list->data;
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 2);
  g_assert_cmpint(context->count, ==, 1);

  otrng_assert_is_error(
      otrng_unfragment_message(&unfrag, &list, fragments[1], 2));

  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 2);
  g_assert_cmpint(context->count, ==, 1);

  otrng_fragment_context_free(context);
  otrng_list_free_nodes(list);
}

void test_defragment_out_of_order_message(void) {
  const string_p fragments[3];
  fragments[0] = "?OTR|00000000|00000001|00000002,00003,00003,send,";
  fragments[1] = "?OTR|00000000|00000001|00000002,00002,00003,fragment ,";
  fragments[2] = "?OTR|00000000|00000001|00000002,00001,00003,one more ,";

  fragment_context_s *context = NULL;
  list_element_s *list = NULL;

  char *unfrag = NULL;
  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, fragments[0], 2));

  context = list->data;
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 3);
  g_assert_cmpint(context->count, ==, 1);

  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, fragments[1], 2));
  otrng_assert(!unfrag);
  g_assert_cmpint(context->total, ==, 3);
  g_assert_cmpint(context->count, ==, 2);

  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, fragments[2], 2));
  g_assert_cmpstr(unfrag, ==, "one more fragment send");

  otrng_assert(otrng_list_len(list) == 0);

  free(unfrag);
  otrng_list_free_nodes(list);
}

void test_defragment_fails_for_another_instance(void) {
  const string_p msg = "?OTR|00000000|00000001|00000002,00001,00001,small lol,";

  list_element_s *list = NULL;
  char *unfrag = NULL;

  otrng_assert_is_success(otrng_unfragment_message(&unfrag, &list, msg, 1));

  otrng_assert(list == NULL);
  g_assert_cmpstr(unfrag, ==, NULL);

  otrng_list_free_nodes(list);
}

void test_defragment_regular_otr_message(void) {
  const string_p msg = "?OTR:not a fragmented message.";

  list_element_s *list = NULL;
  char *unfrag = NULL;

  otrng_assert_is_success(otrng_unfragment_message(&unfrag, &list, msg, 1));

  otrng_assert(list == NULL);
  g_assert_cmpstr(unfrag, ==, msg);

  free(unfrag);
  otrng_list_free_nodes(list);
}

void test_defragment_two_messages(void) {
  const string_p msg1_fragments[2];
  const string_p msg2_fragments[2];
  msg1_fragments[0] = "?OTR|00000001|00000001|00000002,00001,00002,first ,";
  msg1_fragments[1] = "?OTR|00000001|00000001|00000002,00002,00002,message,";
  msg2_fragments[0] = "?OTR|00000002|00000001|00000002,00001,00002,second ,";
  msg2_fragments[1] = "?OTR|00000002|00000001|00000002,00002,00002,message,";

  list_element_s *list = NULL;

  char *unfrag = NULL;
  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, msg1_fragments[0], 2));

  otrng_assert(!unfrag);
  otrng_assert(otrng_list_len(list) == 1);

  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, msg2_fragments[0], 2));
  otrng_assert(!unfrag);
  otrng_assert(otrng_list_len(list) == 2);

  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, msg2_fragments[1], 2));
  g_assert_cmpstr(unfrag, ==, "second message");
  otrng_assert(otrng_list_len(list) == 1);

  free(unfrag);
  unfrag = NULL;

  otrng_assert_is_success(
      otrng_unfragment_message(&unfrag, &list, msg1_fragments[1], 2));
  g_assert_cmpstr(unfrag, ==, "first message");
  otrng_assert(otrng_list_len(list) == 0);

  free(unfrag);
  otrng_list_free_nodes(list);
}

void test_expiration_of_fragments(void) {
  time_t HOUR_IN_SEC = 3600;
  list_element_s *list = NULL;
  fragment_context_s *ctx1 = otrng_fragment_context_new();
  fragment_context_s *ctx2 = otrng_fragment_context_new();

  ctx1->last_fragment_received_at = HOUR_IN_SEC;
  ctx2->last_fragment_received_at = HOUR_IN_SEC + 2;

  list = otrng_list_add(ctx1, list);
  list = otrng_list_add(ctx2, list);

  time_t now = HOUR_IN_SEC + 1;
  otrng_assert_is_success(otrng_expire_fragments(now, 5, &list));
  otrng_assert(otrng_list_len(list) == 1);

  now = HOUR_IN_SEC + 3;
  otrng_assert_is_success(otrng_expire_fragments(now, 5, &list));
  otrng_assert(otrng_list_len(list) == 0);
}
