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
  if (s == NULL)
    return NULL;

  if (strlen(s) < s_len)
    s_len = strlen(s);

  void *new = malloc(s_len + 1);
  if (new == NULL)
    return NULL;

  char *ret = memcpy(new, s, s_len + 1);
  ret[s_len] = 0;

  return ret;
}

INTERNAL /*@null@*/ char *otrng_strdup(const char *s) {
  if (!s)
    return NULL;

  return otrng_strndup(s, strlen(s));
}
