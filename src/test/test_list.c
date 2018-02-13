#include "../list.h"

void test_otrv4_list_add() {
  int one = 1, two = 2;
  list_element_t *list = NULL;
  list = otrv4_list_add(&one, list);

  otrv4_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));

  list = otrv4_list_add(&two, list);
  otrv4_assert(list);
  g_assert_cmpint(one, ==, *((int *)list->data));
  otrv4_assert(list->next);
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  otrv4_list_free_nodes(list);
}

void test_otrv4_list_get_last() {
  int one = 1, two = 2;
  list_element_t *list = NULL;
  list = otrv4_list_add(&one, list);
  list = otrv4_list_add(&two, list);

  otrv4_assert(list);
  // Adds two after one
  g_assert_cmpint(one, ==, *((int *)list->data));
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  // Gets two and keeps one in the head
  list_element_t *last = otrv4_list_get_last(list);
  g_assert_cmpint(two, ==, *((int *)last->data));
  otrv4_assert(!last->next);
  g_assert_cmpint(one, ==, *((int *)list->data));
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  // Removes two and one is the new last element
  list = otrv4_list_remove_element(last, list);
  g_assert_cmpint(two, ==, *((int *)last->data));
  otrv4_list_free_nodes(last);

  last = otrv4_list_get_last(list);
  g_assert_cmpint(one, ==, *((int *)last->data));

  last->data = NULL;

  otrv4_list_free_nodes(last->next);
  otrv4_list_free_nodes(list);
}

void test_otrv4_list_len() {
  int one = 1, two = 2;
  list_element_t *list = NULL;
  list = otrv4_list_add(&one, list);
  list = otrv4_list_add(&two, list);

  otrv4_assert(list);
  g_assert_cmpint(otrv4_list_len(list), ==, 2);

  list_element_t *last = otrv4_list_get_last(list);
  list = otrv4_list_remove_element(last, list);
  otrv4_list_free_nodes(last);

  last = otrv4_list_get_last(list);
  list = otrv4_list_remove_element(last, list);
  otrv4_list_free_nodes(last);

  g_assert_cmpint(otrv4_list_len(list), ==, 0);

  otrv4_list_free_nodes(list);
}

void test_list_empty_size() {
  list_element_t *empty = list_new();
  g_assert_cmpint(otrv4_list_len(empty), ==, 0);
  otrv4_list_free_nodes(empty);
}
