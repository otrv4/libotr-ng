#include "../list.h"

void test_list_add()
{
	int one = 1, two = 2;
	list_element_t *list = NULL;
	list = list_add(&one, list);

	otrv4_assert(list);
	g_assert_cmpint(one, ==, *((int *)list->data));

	list = list_add(&two, list);
	otrv4_assert(list);
	g_assert_cmpint(one, ==, *((int *)list->data));
	otrv4_assert(list->next);
	g_assert_cmpint(two, ==, *((int *)list->next->data));

	list_free_all(list);
}

void test_list_get_last()
{
	int one = 1, two = 2;
	list_element_t *list = NULL;
	list = list_add(&one, list);
	list = list_add(&two, list);

	otrv4_assert(list);
	// Adds two after one
	g_assert_cmpint(one, ==, *((int *)list->data));
	g_assert_cmpint(two, ==, *((int *)list->next->data));

	// Gets two and keeps one in the head
	list_element_t *last = list_get_last(list);
	g_assert_cmpint(two, ==, *((int *) last->data));
	otrv4_assert(!last->next);
	g_assert_cmpint(one, ==, *((int *)list->data));
	g_assert_cmpint(two, ==, *((int *)list->next->data));

	// Removes two and one is the new last element
	list = list_remove_element(last, list);
	g_assert_cmpint(two, ==, *((int *) last->data));
	last = list_get_last(list);
	g_assert_cmpint(one, ==, *((int *)last->data));

	last->data = NULL;
	free(last->data);

	list_free_all(last->next);
	list_free_all(list);
}

void test_list_len()
{
	int one = 1, two = 2;
	list_element_t *list = NULL;
	list = list_add(&one, list);
	list = list_add(&two, list);

	otrv4_assert(list);
	g_assert_cmpint(list_len(list), ==, 2);

	list_element_t *last = list_get_last(list);
	list = list_remove_element(last, list);
        list_free_all(last);

	last = list_get_last(list);
	list = list_remove_element(last, list);
        list_free_all(last);

	g_assert_cmpint(list_len(list), ==, 0);

	list_free_all(list);
}

void test_list_empty_size()
{
        list_element_t *empty = list_new();
        g_assert_cmpint(list_len(empty), ==, 0);
	list_free_all(empty);
}
