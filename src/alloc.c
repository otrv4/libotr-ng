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

#define OTRNG_ALLOC_PRIVATE

#include "alloc.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void (*oom_handler)(void) = NULL;

API void otrng_register_out_of_memory_handler(
    /*@null@*/ void (*handler)(void)) /*@modifies oom_handler@*/ {
  oom_handler = handler;
}

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_xmalloc(size_t size) {
  void *result = malloc(size);
  if (result == NULL) {
    if (oom_handler != NULL) {
      oom_handler();
    }
    fprintf(stderr, "fatal: memory exhausted (xmalloc of %zu bytes).\n", size);
    exit(EXIT_FAILURE);
  }

  return result;
}

INTERNAL /*@only@*/ /*@notnull@*/ void *
otrng_xrealloc(/*@only@*/ /*@null@*/ void *ptr, size_t size) {
  void *result = realloc(ptr, size);
  if (result == NULL) {
    if (oom_handler != NULL) {
      oom_handler();
    }
    fprintf(stderr, "fatal: memory exhausted (xrealloc of %zu bytes).\n", size);
    exit(EXIT_FAILURE);
  }

  return result;
}

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_secure_alloc(size_t size) {
  // TODO: this should be implemented
  // more properly
  void *result = otrng_xmalloc(size);
  memset(result, 0, size);
  return result;
}

INTERNAL void otrng_secure_wipe(/*@null@*/ /*@out@*/ /*@only@*/ void *p,
                                size_t size) /*@modifies p@*/ {
  sodium_memzero(p, size);
}
