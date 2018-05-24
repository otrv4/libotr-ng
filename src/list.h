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

#ifndef OTRNG_LIST_H
#define OTRNG_LIST_H

#include <stdlib.h>

#include "shared.h"

typedef struct list_element_s {
  void *data;
  struct list_element_s *next;
} list_element_s, list_element_p[1];

INTERNAL void otrng_list_foreach(list_element_s *head,
                                 void (*fn)(list_element_s *node,
                                            void *context),
                                 void *context);

// Free list and invoke fn to free the nodes' data
INTERNAL void otrng_list_free(list_element_s *head, void (*fn)(void *data));

// Free list and invoke "free()" to free the nodes' data
INTERNAL void otrng_list_free_full(list_element_s *head);

// Free list but does not free the nodes' data
INTERNAL void otrng_list_free_nodes(list_element_s *head);

INTERNAL list_element_s *otrng_list_add(void *data, list_element_s *head);

INTERNAL list_element_s *
otrng_list_insert_at_position_n(void *data, int position, list_element_s *head);

INTERNAL list_element_s *otrng_list_get_last(list_element_s *head);

INTERNAL list_element_s *
otrng_list_get(const void *wanted, list_element_s *head,
               int (*fn)(const void *current, const void *wanted));

INTERNAL list_element_s *otrng_list_get_by_value(const void *wanted,
                                                 list_element_s *head);

INTERNAL list_element_s *otrng_list_remove_element(const list_element_s *wanted,
                                                   list_element_s *head);

INTERNAL size_t otrng_list_len(list_element_s *head);

#ifdef OTRNG_LIST_PRIVATE

tstatic list_element_s *list_new(void);

#endif

#endif
