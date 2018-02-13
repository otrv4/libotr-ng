#include <stdlib.h>

#define OTRV4_LIST_PRIVATE

#include "list.h"

tstatic list_element_t *list_new() {
  list_element_t *n = malloc(sizeof(list_element_t));
  if (!n)
    return n;

  n->data = NULL;
  n->next = NULL;

  return n;
}

INTERNAL void otrv4_list_foreach(list_element_t *head,
                                 void (*fn)(list_element_t *node,
                                            void *context),
                                 void *context) {
  list_element_t *current = head;
  while (current) {
    list_element_t *next = current->next;

    if (fn)
      fn(current, context);

    current = next;
  }
}

tstatic void call_and_free_node(list_element_t *node, void *context) {
  void (*fn)(void *data) = context;

  if (fn)
    fn(node->data);

  node->data = NULL;
  free(node);
}

INTERNAL void otrv4_list_free(list_element_t *head, void (*fn)(void *data)) {
  otrv4_list_foreach(head, call_and_free_node, fn);
}

INTERNAL void otrv4_list_free_full(list_element_t *head) {
  otrv4_list_free(head, free);
}

INTERNAL void otrv4_list_free_nodes(list_element_t *head) {
  otrv4_list_free(head, NULL);
}

INTERNAL list_element_t *otrv4_list_add(void *data, list_element_t *head) {
  list_element_t *n = list_new();
  if (!n)
    return NULL;

  n->data = data;

  list_element_t *last = otrv4_list_get_last(head);
  if (!last)
    return n;

  last->next = n;
  return head;
}

INTERNAL list_element_t *otrv4_list_get_last(list_element_t *head) {
  if (!head)
    return NULL;

  list_element_t *cursor = head;
  while (cursor->next)
    cursor = cursor->next;

  return cursor;
}

INTERNAL list_element_t *
otrv4_list_get(const void *wanted, list_element_t *head,
               int (*fn)(const void *current, const void *wanted)) {
  list_element_t *cursor = head;

  while (cursor) {
    if (fn && fn(cursor->data, wanted))
      return cursor;

    cursor = cursor->next;
  }

  return NULL;
}

tstatic int compare_data(const void *current, const void *wanted) {
  return current == wanted;
}

INTERNAL list_element_t *otrv4_list_get_by_value(const void *wanted,
                                                 list_element_t *head) {
  return otrv4_list_get(wanted, head, compare_data);
}

INTERNAL list_element_t *otrv4_list_remove_element(const list_element_t *wanted,
                                                   list_element_t *head) {
  list_element_t *cursor = head;

  if (head == wanted) {
    cursor = head->next;
    head->next = NULL;
    return cursor;
  }

  while (cursor->next) {
    if (cursor->next == wanted) {
      list_element_t *found = cursor->next;
      cursor->next = wanted->next;
      found->next =
          NULL; /* the element found should not point to anything in the list */
      break;
    }

    cursor = cursor->next;
  }

  return head;
}

INTERNAL size_t otrv4_list_len(list_element_t *head) {
  list_element_t *cursor = head;
  size_t size = 0;

  while (cursor) {
    if (cursor->data) {
      size++;
    }
    cursor = cursor->next;
  }

  return size;
}
