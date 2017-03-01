#include "../list.h"

void
test_list_add() {
    int one = 1, two = 2;
    list_element_t *list = NULL;
    list = list_add(&one, list);

    otrv4_assert(list);
    g_assert_cmpint(one, ==, *((int*)list->data));

    list = list_add(&two, list);
    otrv4_assert(list);
    g_assert_cmpint(one, ==, *((int*)list->data));
    otrv4_assert(list->next);
    g_assert_cmpint(two, ==, *((int*)list->next->data));
}
