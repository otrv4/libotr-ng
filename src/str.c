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

INTERNAL /*@notnull@*/ /*@only@*/ char *
otrng_xstrndup(/*@notnull@*/ const char *s, size_t s_len) {
  void *new;
  char *ret;

  if (strlen(s) < s_len) {
    s_len = strlen(s);
  }

  new = otrng_xmalloc(s_len + 1);
  ret = memcpy(new, s, s_len + 1);
  ret[s_len] = '\0';

  return ret;
}

INTERNAL /*@notnull@*/ /*@only@*/ char *
otrng_xstrdup(/*@notnull@*/ const char *s) {
  return otrng_xstrndup(s, strlen(s));
}

INTERNAL /*@notnull@*/ /*@only@*/ void *
otrng_xmemdup(/*@notnull@*/ const void *s, const size_t len) {
  void *d;

  d = otrng_xmalloc(len);
  return memcpy(d, s, len);
}

INTERNAL /*@notnull@*/ /*@only@*/ char *
otrng_stpcpy(/*@notnull@*/ char *dst,
             /*@notnull@*/ const char *src) /*@modifies dst@*/ {
  return otrng_stpncpy(dst, src, strlen(src) + 1);
}

INTERNAL /*@notnull@*/ /*@only@*/ char *
otrng_stpncpy(/*@notnull@*/ char *dst, /*@notnull@*/ const char *src,
              const size_t n) /*@modifies dst@*/ {
  size_t l, w;
  char *t;

  l = strlen(src);
  w = l < n ? l : n;
  memmove(dst, src, w);

  for (t = dst + w; t < dst + n; t++) {
    *t = '\0';
  }

  return dst + w;
}

INTERNAL size_t otrng_strnlen(/*@notnull@*/ const char *s,
                              const size_t maxlen) {
  size_t l = 0;
  while ((s[l] != '\0') && l < maxlen) {
    l++;
  }

  return l;
}

INTERNAL size_t otrng_strlen_ns(/*@null@*/ const char *s) {
  if (s == NULL) {
    return 0;
  }
  return strlen(s);
}
