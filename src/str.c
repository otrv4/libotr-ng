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
#include <string.h>

#define OTRNG_STR_PRIVATE

#include "alloc.h"
#include "str.h"

INTERNAL /*@null@*/ char *otrng_xstrndup(const char *s, size_t s_len) {
  void *new;
  char *ret;

  if (!s) {
    return NULL;
  }

  if (strlen(s) < s_len) {
    s_len = strlen(s);
  }

  new = otrng_xmalloc(s_len + 1);
  ret = memcpy(new, s, s_len + 1);
  ret[s_len] = 0;

  return ret;
}

INTERNAL /*@null@*/ char *otrng_xstrdup(const char *s) {
  return otrng_xstrndup(s, strlen(s));
}

INTERNAL /*@null@*/ void *otrng_xmemdup(const void *s, const size_t len) {
  void *d;

  if (!s || len == 0) {
    return NULL;
  }

  d = otrng_xmalloc(len);
  return memcpy(d, s, len);
}

INTERNAL /*@null@*/ char *otrng_stpcpy(char *dest, const char *src) {
  return otrng_stpncpy(dest, src, strlen(src) + 1);
}

INTERNAL /*@null@*/ char *otrng_stpncpy(char *dest, const char *src, size_t n) {
  size_t l, w;
  char *t;

  if (!src) {
    return NULL;
  }

  l = strlen(src);
  w = l < n ? l : n;
  memmove(dest, src, w);

  for (t = dest + w; t < dest + n; t++) {
    *t = 0;
  }

  return dest + w;
}

INTERNAL size_t otrng_strnlen(/*@nonnull@*/ const char *s, size_t maxlen) {
  size_t l = 0;
  while (s[l] && l < maxlen) {
    l++;
  }

  return l;
}
