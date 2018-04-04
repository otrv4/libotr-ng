#include "../list.h"

void test_otrng_list_add() {
  int one = 1, two = 2;
  list_element_t *list = NULL;
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

void test_otrng_list_get_last() {
  int one = 1, two = 2;
  list_element_t *list = NULL;
  list = otrng_list_add(&one, list);
  list = otrng_list_add(&two, list);

  otrng_assert(list);
  // Adds two after one
  g_assert_cmpint(one, ==, *((int *)list->data));
  g_assert_cmpint(two, ==, *((int *)list->next->data));

  // Gets two and keeps one in the head
  list_element_t *last = otrng_list_get_last(list);
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

void test_otrng_list_len() {
  int one = 1, two = 2;
  list_element_t *list = NULL;
  list = otrng_list_add(&one, list);
  list = otrng_list_add(&two, list);

  otrng_assert(list);
  g_assert_cmpint(otrng_list_len(list), ==, 2);

  list_element_t *last = otrng_list_get_last(list);
  list = otrng_list_remove_element(last, list);
  otrng_list_free_nodes(last);

  last = otrng_list_get_last(list);
  list = otrng_list_remove_element(last, list);
  otrng_list_free_nodes(last);

  g_assert_cmpint(otrng_list_len(list), ==, 0);

  otrng_list_free_nodes(list);
}

void test_list_empty_size() {
  list_element_t *empty = list_new();
  g_assert_cmpint(otrng_list_len(empty), ==, 0);
  otrng_list_free_nodes(empty);
}
