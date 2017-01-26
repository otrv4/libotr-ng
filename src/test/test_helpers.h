#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libdecaf/decaf.h>

#include "../ed448.h"

static char*
otrv4_memdump(const uint8_t *src, size_t len) {
  //each char is represented by 0x00,
  char *buff = malloc(len*6+1 + len/8);
  char *cursor = buff;
  int i = 0;

  for (i = 0; i < len; i++) {
    if (i % 8 == 0) { cursor += sprintf(cursor, "\n"); }
    cursor += sprintf(cursor, "0x%02x, ", src[i]);
  }

  return buff;
}

#define otrv4_assert_cmpmem(s1, s2, len) do { \
        char *__s1 = otrv4_memdump((const uint8_t*) s1, len); \
        char *__s2 = otrv4_memdump((const uint8_t*) s2, len); \
        char *__msg = g_strdup_printf("assertion failed: (%s)\nEXPECTED (%p): %s\nACTUAL (%p): %s\n", \
            #s1 " ==  " #s2, s1, __s1, s2, __s2); \
        if (memcmp(s1, s2, len) == 0); else \
        g_assertion_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, __msg); \
        free(__s1); \
        free(__s2); \
        g_free(__msg); \
        } while (0)

#define otrv4_assert(expr)  do { if G_LIKELY (expr) ; else \
                        g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
                        #expr); } while (0)


static inline void
otrv4_assert_point_equals(const ec_point_t expected, const ec_point_t actual) {
  g_assert_cmpint(decaf_448_point_eq(expected, actual), !=, 0);
}

