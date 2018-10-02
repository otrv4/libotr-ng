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

#define OTRNG_DEBUG_PRIVATE

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"

INTERNAL /*@null@*/ char *_otrng_memdump(const uint8_t *src, size_t len) {
  size_t s = len * 6 + len / 8 + 2;
  char *buff, *cursor;
  unsigned int i;

  if (src == NULL) {
    return otrng_xstrndup("(NULL)", 6);
  }
  /* each char is represented by "0x00, " */
  buff = otrng_xmalloc(s);

  cursor = buff;

  for (i = 0; i < len; i++) {
    if (i % 8 == 0) {
      cursor += snprintf(cursor, s, "\n");
    }
    cursor += snprintf(cursor, s, "0x%02x, ", src[i]);
  }

  return buff;
}

static int debug_printing_enabled = 0;

API void otrng_debug_init(void) {
  const char *set = getenv("OTRNG_DEBUG");
  if (set != NULL && strcmp("true", set) == 0) {
    otrng_debug_enable();
  } else {
    otrng_debug_disable();
  }
}

API void otrng_debug_enable(void) {
  debug_printing_enabled = 1;
  otrng_debug_fprintf(stderr, "OTRNG debug printing enabled\n");
}

API void otrng_debug_disable(void) { debug_printing_enabled = 0; }

static int debug_indent = 0;

API void otrng_debug_enter(const char *name) {
  otrng_debug_fprintf(stderr, "-> %s()\n", name);
  debug_indent++;
}

API void otrng_debug_exit(const char *name) {
  debug_indent--;

  assert(debug_indent >= 0);

  otrng_debug_fprintf(stderr, "<- %s()\n", name);
}

API void otrng_debug_fprintf(FILE *f, const char *fmt, ...) {
  int ix;
  va_list args;
  if (debug_printing_enabled) {
    for (ix = 0; ix < debug_indent; ix++) {
      fprintf(f, "  ");
    }

    va_start(args, fmt);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    (void)vfprintf(f, fmt, args);
#pragma clang diagnostic pop
    va_end(args);
  }
}
