#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libdecaf/decaf.h>

#include "../str.h"
#include "../ed448.h"

#define WITH_FIXTURE(_p, _c, _t, _f) \
  do { g_test_add(_p, _t, NULL, _f##_setup, _c, _f##_teardown); } while(0);

static char*
otrv4_memdump(const uint8_t *src, size_t len) {
  if (src == NULL) {
    return otrv4_strdup("(NULL)");
  }

  //each char is represented by "0x00, "
  size_t s = len*6 + len/8 + 2;
  char *buff = malloc(s);
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

#define otrv4_assert_cs_public_key_equals(pk1, pk2) do { \
  otrv4_assert_point_equals(pk1->c, pk2->c); \
  otrv4_assert_point_equals(pk1->d, pk2->d); \
  otrv4_assert_point_equals(pk1->h, pk2->h); \
} while (0)

#define otrv4_assert_mpi_eq(m1, m2) do { \
  g_assert_cmpuint(m1->len, ==, m2->len); \
  otrv4_assert_cmpmem(m1->data, m2->data, m1->len); \
} while (0)

#define otrv4_assert_user_profile_eq(p1, p2) do { \
  otrv4_assert_cs_public_key_equals(p1->pub_key, p2->pub_key); \
  otrv4_assert_cmpmem(p1->versions, p2->versions, strlen(p1->versions)+1); \
  g_assert_cmpuint(p1->expires, ==, p2->expires); \
  otrv4_assert_cmpmem(p1->signature, p2->signature, EC_SIGNATURE_BYTES); \
  otrv4_assert_mpi_eq(p1->transitional_signature, p2->transitional_signature); \
} while (0)

#define otrv4_assert_ec_public_key_eq(pk1, pk2) do { \
  otrv4_assert_cmpmem(pk1, pk2, sizeof(ec_public_key_t)); \
} while (0)

#define otrv4_assert_dh_public_key_eq(pk1, pk2) do { \
  g_assert_cmpint(dh_mpi_cmp(pk1, pk2), ==, 0); \
} while (0)

static inline void
otrv4_assert_point_equals(const ec_point_t expected, const ec_point_t actual) {
  g_assert_cmpint(decaf_448_point_eq(expected, actual), !=, 0);
}

