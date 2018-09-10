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

#include <stdlib.h>

#define OTRNG_LIST_PRIVATE

#include "list.h"

tstatic list_element_s *list_new() {
  list_element_s *n = malloc(sizeof(list_element_s));
  if (!n) {
    return NULL;
  }

  n->data = NULL;
  n->next = NULL;

  return n;
}

INTERNAL void otrng_list_foreach(list_element_s *head,
                                 void (*fn)(list_element_s *node,
                                            void *context),
                                 void *context) {
  list_element_s *current = head;
  while (current) {
    list_element_s *next = current->next;

    if (fn) {
      fn(current, context);
    }

    current = next;
  }
}

INTERNAL void otrng_list_free(list_element_s *head,
                              void (*free_data)(void *data)) {
  list_element_s *current = head;
  while (current) {
    list_element_s *next = current->next;

    if (free_data) {
      free_data(current->data);
      current->data = NULL;
    }

    free(current);
    current = next;
  }
}

INTERNAL void otrng_list_free_full(list_element_s *head) {
  otrng_list_free(head, free);
}

INTERNAL /*@null@*/ void otrng_list_free_nodes(list_element_s *head) {
  otrng_list_free(head, NULL);
}

INTERNAL list_element_s *otrng_list_copy(list_element_s *head) {
  if (otrng_list_len(head) == 0) {
    return NULL;
  }

  list_element_s *cursor = head;
  list_element_s *copy = list_new();
  if (!copy) {
    return NULL;
  }
  copy->data = cursor->data;
  copy->next = NULL;

  list_element_s *ret = copy;

  cursor = cursor->next;
  while (cursor) {
    copy = copy->next = list_new();
    copy->data = cursor->data;
    copy->next = NULL;

    cursor = cursor->next;
  }

  return ret;
}

INTERNAL list_element_s *otrng_list_add(void *data, list_element_s *head) {
  list_element_s *n = list_new();
  if (!n) {
    return NULL;
  }

  n->data = data;

  list_element_s *last = otrng_list_get_last(head);
  if (!last) {
    return n;
  }

  last->next = n;
  return head;
}

INTERNAL list_element_s *otrng_list_insert_at_position_n(void *data, size_t pos,
                                                         list_element_s *head) {
  list_element_s *n = list_new();
  if (!n) {
    return NULL;
  }

  n->data = data;
  n->next = NULL;

  if (!head) {
    return n;
  }

  int i;
  list_element_s *tmp = head;

  if (pos == 0) {
    n->next = tmp;
    head = n;

    return head;
  }

  for (i = 0; i < pos - 1; i++) {
    tmp = tmp->next;
  }

  n->next = tmp->next;
  tmp->next = n;

  return head;
}

INTERNAL list_element_s *otrng_list_get_last(list_element_s *head) {
  if (!head) {
    return NULL;
  }

  list_element_s *cursor = head;
  while (cursor->next) {
    cursor = cursor->next;
  }

  return cursor;
}

INTERNAL list_element_s *
otrng_list_get(const void *wanted, list_element_s *head,
               int (*fn)(const void *current, const void *wanted)) {
  list_element_s *cursor = head;

  while (cursor) {
    if (fn && fn(cursor->data, wanted)) {
      return cursor;
    }

    cursor = cursor->next;
  }

  return NULL;
}

tstatic int compare_data(const void *current, const void *wanted) {
  return current == wanted;
}

INTERNAL list_element_s *otrng_list_get_by_value(const void *wanted,
                                                 list_element_s *head) {
  return otrng_list_get(wanted, head, compare_data);
}

INTERNAL list_element_s *otrng_list_remove_element(const list_element_s *wanted,
                                                   list_element_s *head) {
  list_element_s *cursor = head;

  if (head == wanted) {
    cursor = head->next;
    head->next = NULL;
    return cursor;
  }

  while (cursor->next) {
    if (cursor->next == wanted) {
      list_element_s *found = cursor->next;
      cursor->next = wanted->next;
      found->next =
          NULL; /* the element found should not point to anything in the list
                 */
      break;
    }

    cursor = cursor->next;
  }

  return head;
}

INTERNAL size_t otrng_list_len(list_element_s *head) {
  list_element_s *cursor = head;
  size_t size = 0;

  while (cursor) {
    if (cursor->data) {
      size++;
    }
    cursor = cursor->next;
  }

  return size;
}
