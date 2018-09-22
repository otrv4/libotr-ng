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

// This file doesn't have the standard header file guard - the reason for that
// has to do with weird interactions with static inline and so on.
// It's a bit horrible, but let's keep it this way for now.

#include <stdint.h>
#include <stdio.h>

#include "alloc.h"
#include "shared.h"
#include "str.h"

static inline /*@null@*/ char *_otrng_memdump(const uint8_t *src, size_t len) {
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

#ifdef DEBUG_API
#define debug_api_print fprintf
struct otrng_client_id_s;
API void otrng_client_id_debug_print(FILE *, const struct otrng_client_id_s);
API void otrng_add_debug_print_ignore(const char *);
API void otrng_clear_debug_print_ignores();
API otrng_bool otrng_debug_print_should_ignore(const char *);

static inline void otrng_print_indent(FILE *f, int indent) {
  int i;
  for (i = 0; i < indent; i++) {
    fputc(' ', f);
  }
}

static inline void otrng_debug_print_pointer(FILE *f, const void *p) {
  if (p == NULL) {
    debug_api_print(f, "NULL");
  } else {
    debug_api_print(f, "%p", p);
  }
}

static inline void otrng_debug_print_data(FILE *f, const uint8_t *p,
                                          size_t len) {
  int i;
  if (p == NULL) {
    debug_api_print(f, "NULL");
  } else {
    debug_api_print(f, "0x");
    for (i = 0; i < len; i++) {
      debug_api_print(f, "%02X", p[i]);
    }
  }
}
#endif

#define debug_print printf
#ifdef DEBUG
static inline void otrng_memdump(const uint8_t *src, size_t len) {
  debug_print("%s\n", _otrng_memdump(src, len));
}

#else
static inline void otrng_memdump(const uint8_t *src, size_t len) {
  (void)src;
  (void)len;
}
#endif
