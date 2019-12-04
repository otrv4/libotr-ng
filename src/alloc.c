/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

static void (*oom_handler)(void);

API void otrng_register_out_of_memory_handler(
    /*@null@*/ void (*handler)(void)) /*@modifies internalState @*/ {
  oom_handler = handler;
}

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_xmalloc(size_t size) {
  void *result = malloc(size);
  if (result == NULL) {
    if (oom_handler != NULL) {
      oom_handler();
    }
    fprintf(stderr, "fatal: memory exhausted (xmalloc of %lu bytes).\n", size);
    exit(EXIT_FAILURE);
  }

  return result;
}

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_xmalloc_z(size_t size) {
  void *result = otrng_xmalloc(size);
  memset(result, 0, size);
  return result;
}

INTERNAL /*@only@*/ /*@notnull@*/ void *
otrng_xrealloc(/*@only@*/ /*@null@*/ void *ptr, size_t size) {
  void *result = realloc(ptr, size);
  if (result == NULL) {
    if (oom_handler != NULL) {
      oom_handler();
    }
    fprintf(stderr, "fatal: memory exhausted (xrealloc of %lu bytes).\n", size);
    exit(EXIT_FAILURE);
  }

  return result;
}

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_secure_alloc(size_t size) {
  void *result = sodium_malloc(size);
  memset(result, 0, size);
  return result;
}

INTERNAL /*@only@*/ /*@notnull@*/ void *otrng_secure_alloc_array(size_t count,
                                                                 size_t size) {
  return sodium_allocarray(count, size);
}

INTERNAL void otrng_free(/*@notnull@*/ /*@only@*/ void *p) /*@modifies p@*/ {
  free(p);
}

INTERNAL void
otrng_secure_free(/*@notnull@*/ /*@only@*/ void *p) /*@modifies p@*/ {
  sodium_free(p);
}

INTERNAL void otrng_secure_wipe(/*@notnull@*/ /*@only@*/ void *p,
                                size_t size) /*@modifies p@*/ {
  sodium_memzero(p, size);
}
