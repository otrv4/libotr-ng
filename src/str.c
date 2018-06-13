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

#include <stdlib.h>
#include <string.h>

#define OTRNG_STR_PRIVATE

#include "str.h"

INTERNAL /*@null@*/ char *otrng_strndup(const char *s, size_t s_len) {
  if (!s) {
    return NULL;
  }

  if (strlen(s) < s_len) {
    s_len = strlen(s);
  }

  void *new = malloc(s_len + 1);
  if (!new) {
    return NULL;
  }

  char *ret = memcpy(new, s, s_len + 1);
  ret[s_len] = 0;

  return ret;
}

INTERNAL /*@null@*/ char *otrng_strdup(const char *s) {
  return otrng_strndup(s, strlen(s));
}

INTERNAL /*@null@*/ uint8_t *otrng_memdup(const uint8_t *s, const size_t len) {
  if (!s || len == 0) {
    return NULL;
  }

  uint8_t *d = malloc(len);
  if (!d) {
    return NULL;
  }

  return memcpy(d, s, len);
}

INTERNAL /*@null@*/ char *otrng_stpcpy(char *dest, const char *src) {
  return otrng_stpncpy(dest, src, strlen(src) + 1);
}

INTERNAL /*@null@*/ char *otrng_stpncpy(char *dest, const char *src, size_t n) {
  if (!src) {
    return NULL;
  }

  size_t l = strlen(src);
  size_t w = l < n ? l : n;
  memmove(dest, src, w);

  for (char *t = dest + w; t < dest + n; t++) {
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
