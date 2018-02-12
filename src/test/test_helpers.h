#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../client.h"
#include "../str.h"

#include "../debug.h"

#define ALICE_IDENTITY "alice@otr.example"
#define BOB_IDENTITY "bob@otr.example"
#define CHARLIE_IDENTITY "charlie@otr.example"
#define PHI "alice@otr.jabber.net"
#define FORCE_CREATE_CONVO true

#define WITH_FIXTURE(_p, _c, _t, _f)                                           \
  do {                                                                         \
    g_test_add(_p, _t, NULL, _f##_setup, _c, _f##_teardown);                   \
  } while (0);


// TODO: for structs like scalars and points, use: decaf_memeq
// for the rest use our own implementation of mem_cmp
#define otrv4_assert_cmpmem(s1, s2, len)                                       \
  do {                                                                         \
    char *__s1 = _otrv4_memdump((const uint8_t *)s1, len);                     \
    char *__s2 = _otrv4_memdump((const uint8_t *)s2, len);                     \
    char *__msg = g_strdup_printf(                                             \
        "assertion failed: (%s)\nEXPECTED (%p): %s\nACTUAL (%p): %s\n",        \
        #s1 " ==  " #s2, s1, __s1, s2, __s2);                                  \
    if (memcmp(s1, s2, len) == 0)                                              \
      ;                                                                        \
    else                                                                       \
      g_assertion_message(G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, __msg); \
    free(__s1);                                                                \
    free(__s2);                                                                \
    g_free(__msg);                                                             \
  } while (0)

#define otrv4_assert(expr)                                                     \
  do {                                                                         \
    if                                                                         \
      G_LIKELY(expr);                                                          \
    else                                                                       \
      g_assertion_message_expr(G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC,    \
                               #expr);                                         \
  } while (0)

#define otrv4_assert_mpi_eq(m1, m2)                                            \
  do {                                                                         \
    g_assert_cmpuint(m1->len, ==, m2->len);                                    \
    otrv4_assert_cmpmem(m1->data, m2->data, m1->len);                          \
  } while (0)

#define otrv4_assert_user_profile_eq(p1, p2)                                   \
  do {                                                                         \
    otrv4_assert_point_equals(p1->pub_key, p2->pub_key);                       \
    otrv4_assert_cmpmem(p1->versions, p2->versions, strlen(p1->versions) + 1); \
    g_assert_cmpuint(p1->expires, ==, p2->expires);                            \
    otrv4_assert_cmpmem(p1->signature, p2->signature, ED448_SIGNATURE_BYTES);  \
    otrv4_assert_mpi_eq(p1->transitional_signature,                            \
                        p2->transitional_signature);                           \
  } while (0)

#define otrv4_assert_not_zero(s, len)                                          \
  do {                                                                         \
    char *__s = _otrv4_memdump((const uint8_t *)s, len);                       \
    char zero_value[len];                                                      \
    memset(zero_value, 0, sizeof zero_value);                                  \
    char *__msg = g_strdup_printf("assertion failed: (%s)\nRESULT (%p): %s\n", \
                                  #s " is zero", s, __s);                      \
    if (decaf_memeq(s, zero_value, len) == 0)                                  \
      ;                                                                        \
    else                                                                       \
      g_assertion_message(G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, __msg); \
    free(__s);                                                                 \
    g_free(__msg);                                                             \
  } while (0)

#define otrv4_assert_zero(s, len)                                              \
  do {                                                                         \
    char zero_value[len];                                                      \
    memset(zero_value, 0, sizeof zero_value);                                  \
    otrv4_assert_cmpmem(zero_value, s, len);                                   \
  } while (0)

#define otrv4_assert_ec_public_key_eq(pk1, pk2)                                \
  do {                                                                         \
    otrv4_assert_cmpmem(pk1, pk2, sizeof(ec_public_key_t));                    \
  } while (0)

#define otrv4_assert_dh_public_key_eq(pk1, pk2)                                \
  do {                                                                         \
    g_assert_cmpint(dh_mpi_cmp(pk1, pk2), ==, 0);                              \
  } while (0)

#define otrv4_assert_root_key_eq(rk1, rk2)                                     \
  do {                                                                         \
    otrv4_assert_cmpmem(rk1, rk2, sizeof(root_key_t));                         \
  } while (0)

#define otrv4_assert_chain_key_eq(ck1, ck2)                                    \
  do {                                                                         \
    otrv4_assert_cmpmem(ck1, ck2, sizeof(chain_key_t));                        \
  } while (0)

// TODO: here actually use the designated initializers as I was planning to
// do for the future nonetheless
#define fn_apply(fn, ...)                                                      \
  {                                                                            \
    void *stopper = (int[]){0};                                                \
    void **list = (void *[]){__VA_ARGS__, stopper};                            \
    for (int i = 0; list[i] != stopper; i++)                                   \
      fn(list[i]);                                                             \
  }

#define otrv4_free_all(...) fn_apply(otrv4_free, __VA_ARGS__);

#define otrv4_response_free_all(...) fn_apply(otrv4_response_free, __VA_ARGS__);

#define otrv4_userstate_free_all(...)                                          \
  fn_apply(otrl_userstate_free, __VA_ARGS__);

#define otrv4_client_state_free_all(...)                                       \
  fn_apply(otr4_client_state_free, __VA_ARGS__);

#define otrv4_client_free_all(...) fn_apply(otrv4_client_free, __VA_ARGS__);

static inline void otrv4_assert_point_equals(const ec_point_t expected,
                                             const ec_point_t actual) {
  g_assert_cmpint(ec_point_eq(expected, actual), !=, otrv4_false);
}
