// This file doesn't have the standard header file guard - the reason for that
// has to do with weird interactions with static inline and so on.
// It's a bit horrible, but let's keep it this way for now.

#include <stdint.h>
#include <stdio.h>

#include "shared.h"
#include "str.h"

static inline char *_otrv4_memdump(const uint8_t *src, size_t len) {
  if (src == NULL) {
    return otrv4_strndup("(NULL)", 6);
  }
  /* each char is represented by "0x00, " */
  size_t s = len * 6 + len / 8 + 2;
  char *buff = malloc(s);
  char *cursor = buff;
  unsigned int i = 0;

  for (i = 0; i < len; i++) {
    if (i % 8 == 0) {
      cursor += sprintf(cursor, "\n");
    }
    cursor += sprintf(cursor, "0x%02x, ", src[i]);
  }

  return buff;
}

#ifdef DEBUG
static inline void otrv4_memdump(const uint8_t *src, size_t len) {
  printf("%s\n", _otrv4_memdump(src, len));
}

#else
// TODO: is this used?
static inline void otrv4_memdump(const uint8_t *src, size_t len) {}
#endif
