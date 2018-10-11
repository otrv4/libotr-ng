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

#include <glib.h>

#include "test_helpers.h"

#include "list.h"

static void test_otrng_list_add() {
  int one = 1, two = 2;
  list_element_s *list = NULL;
  list = otrng_list_add(&one, list);

  otrng_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));

  list = otrng_list_add(&two, list);
  otrng_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));
  otrng_assert(list->next);
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  otrng_list_free_nodes(list);
}

static void test_otrng_list_copy() {
  int one = 1, two = 2, three = 3;
  list_element_s *list = NULL;

  otrng_assert(!otrng_list_copy(list));

  list = otrng_list_add(&one, list);

  otrng_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));

  list = otrng_list_add(&two, list);
  otrng_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));
  otrng_assert(list->next);
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  list = otrng_list_add(&three, list);
  otrng_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));
  otrng_assert(list->next);
  g_assert_cmpint(two, ==, *((int *)list->next->data));
  otrng_assert(list->next->next);
  g_assert_cmpint(three, ==, *((int *)list->next->next->data));

  list_element_s *cpy_list = otrng_list_copy(list);
  g_assert_cmpint(one, ==, *((int *)cpy_list->data));
  g_assert_cmpint(two, ==, *((int *)cpy_list->next->data));
  g_assert_cmpint(three, ==, *((int *)cpy_list->next->next->data));

  otrng_list_free_nodes(list);
  otrng_list_free_nodes(cpy_list);
}

static void test_otrng_list_insert_at_n() {
  int one = 1, two = 2;
  list_element_s *list = NULL;

  list_element_s *result = otrng_list_insert_at_position_n(&two, 0, list);

  otrng_assert(result);
  otrng_assert(!result->next);
  g_assert_cmpint(two, ==, *((int *)result->data));
  free(result);

  list = otrng_list_add(&one, list);

  otrng_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));

  list = otrng_list_add(&two, list);
  otrng_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));
  otrng_assert(list->next);
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  int three = 3;
  list = otrng_list_insert_at_position_n(&three, 2, list);
  g_assert_cmpint(one, ==, *((int *)list->data));
  otrng_assert(list->next);
  g_assert_cmpint(two, ==, *((int *)list->next->data));
  otrng_assert(list->next->next);
  g_assert_cmpint(three, ==, *((int *)list->next->next->data));

  otrng_list_free_nodes(list);

  list_element_s *list_2 = list_new();

  int four = 4, five = 5, six = 6;
  list_2 = otrng_list_insert_at_position_n(&four, 0, list_2);
  g_assert_cmpint(four, ==, *((int *)list_2->data));
  list_2 = otrng_list_insert_at_position_n(&six, 2, list_2);
  g_assert_cmpint(six, ==, *((int *)list_2->next->next->data));
  list_2 = otrng_list_insert_at_position_n(&five, 1, list_2);
  g_assert_cmpint(five, ==, *((int *)list_2->next->data));

  otrng_list_free_nodes(list_2);
}

static void test_otrng_list_get_last() {
  int one = 1, two = 2;
  list_element_s *list = NULL;
  list = otrng_list_add(&one, list);
  list = otrng_list_add(&two, list);

  otrng_assert(list);
  // Adds two after one
  g_assert_cmpint(one, ==, *((int *)list->data));
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  // Gets two and keeps one in the head
  list_element_s *last = otrng_list_get_last(list);
  g_assert_cmpint(two, ==, *((int *)last->data));
  otrng_assert(!last->next);
  g_assert_cmpint(one, ==, *((int *)list->data));
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  // Removes two and one is the new last element
  list = otrng_list_remove_element(last, list);
  g_assert_cmpint(two, ==, *((int *)last->data));
  otrng_list_free_nodes(last);

  last = otrng_list_get_last(list);
  g_assert_cmpint(one, ==, *((int *)last->data));

  last->data = NULL;

  otrng_list_free_nodes(last->next);
  otrng_list_free_nodes(list);
}

static void test_otrng_list_get_by_value() {
  int one = 1, two = 2;
  list_element_s *list = NULL;
  list = otrng_list_add(&one, list);

  otrng_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));

  list = otrng_list_add(&two, list);
  otrng_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));
  otrng_assert(list->next);
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  list_element_s *elem = otrng_list_get_by_value(&one, list);
  otrng_assert(elem);
  g_assert_cmpint(one, ==, *((int *)elem->data));

  otrng_list_free_nodes(list);
}

static void test_otrng_list_len() {
  int one = 1, two = 2;
  list_element_s *list = NULL;
  list = otrng_list_add(&one, list);
  list = otrng_list_add(&two, list);

  otrng_assert(list);
  g_assert_cmpint(otrng_list_len(list), ==, 2);

  list_element_s *last = otrng_list_get_last(list);
  list = otrng_list_remove_element(last, list);
  otrng_list_free_nodes(last);

  last = otrng_list_get_last(list);
  list = otrng_list_remove_element(last, list);
  otrng_list_free_nodes(last);

  g_assert_cmpint(otrng_list_len(list), ==, 0);

  otrng_list_free_nodes(list);
}

static void test_list_empty_size() {
  list_element_s *empty = list_new();
  g_assert_cmpint(otrng_list_len(empty), ==, 0);
  otrng_list_free_nodes(empty);
}

void units_list_add_tests(void) {
  g_test_add_func("/list/add", test_otrng_list_add);
  g_test_add_func("/list/copy", test_otrng_list_copy);
  g_test_add_func("/list/insert_at_n", test_otrng_list_insert_at_n);
  g_test_add_func("/list/get", test_otrng_list_get_last);
  g_test_add_func("/list/get_by_value", test_otrng_list_get_by_value);
  g_test_add_func("/list/length", test_otrng_list_len);
  g_test_add_func("/list/empty_size", test_list_empty_size);
}
