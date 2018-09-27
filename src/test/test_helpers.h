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

#ifndef __TEST_HELPERS_H__
#define __TEST_HELPERS_H__

#define OTRNG_AUTH_PRIVATE
#define OTRNG_DAKE_PRIVATE
#define OTRNG_DH_PRIVATE
#define OTRNG_ED448_PRIVATE
#define OTRNG_FRAGMENT_PRIVATE
#define OTRNG_KEY_MANAGEMENT_PRIVATE
#define OTRNG_LIST_PRIVATE
#define OTRNG_OTRNG_PRIVATE
#define OTRNG_PERSISTENCE_PRIVATE
#define OTRNG_PREKEY_CLIENT_PRIVATE
#define OTRNG_PROTOCOL_PRIVATE
#define OTRNG_SMP_PRIVATE
#define OTRNG_SMP_PROTOCOL_PRIVATE
#define OTRNG_TLV_PRIVATE
#define OTRNG_USER_PROFILE_PRIVATE
#define OTRNG_MESSAGING_PRIVATE

#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"
#include "client_profile.h"
#include "debug.h"
#include "str.h"

#define ALICE_ACCOUNT "alice@otr.example"
#define BOB_ACCOUNT "bob@otr.example"
#define CHARLIE_ACCOUNT "charlie@otr.example"
#define ALICE_IDENTITY create_client_id("otr", ALICE_ACCOUNT)
#define BOB_IDENTITY create_client_id("otr", BOB_ACCOUNT)
#define CHARLIE_IDENTITY create_client_id("otr", CHARLIE_ACCOUNT)
#define FORCE_CREATE_CONV 1
#define NOT_FORCE_CREATE_CONV 0

#define WITH_FIXTURE(_p, _c, _t, _f)                                           \
  do {                                                                         \
    g_test_add((_p), _t, NULL, _f##_setup, (_c), _f##_teardown);               \
  } while (0)

#define WITH_DAKE_FIXTURE(_p, _c)                                              \
  WITH_FIXTURE(_p, _c, dake_fixture_s, dake_fixture)

// TODO: @refactoring for structs like scalars and points, use: goldilocks_memeq
// for the rest use our own implementation of mem_cmp
#define otrng_assert_cmpmem(s1, s2, len)                                       \
  do {                                                                         \
    const uint8_t *_s1_evaled = (uint8_t *)(s1);                               \
    const uint8_t *_s2_evaled = (uint8_t *)(s2);                               \
    const size_t _len_evaled = (len);                                          \
    char *__s1 = _otrng_memdump(_s1_evaled, _len_evaled);                      \
    char *__s2 = _otrng_memdump(_s2_evaled, _len_evaled);                      \
    char *__msg = g_strdup_printf(                                             \
        "assertion failed: (%s)\n\n%s (%p): %s\n\n%s (%p): %s\n",              \
        #s1 " ==  " #s2, #s1, (void *)_s1_evaled, __s1, #s2,                   \
        (void *)_s2_evaled, __s2);                                             \
    if ((_s1_evaled == NULL && _s2_evaled == NULL) ||                          \
        memcmp(_s1_evaled, _s2_evaled, _len_evaled) == 0)                      \
      ;                                                                        \
    else                                                                       \
      g_assertion_message(G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, __msg); \
    free(__s1);                                                                \
    free(__s2);                                                                \
    g_free(__msg);                                                             \
  } while (0)

#define otrng_assert(expr)                                                     \
  do {                                                                         \
    if                                                                         \
      G_LIKELY(expr);                                                          \
    else                                                                       \
      g_assertion_message_expr(G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC,    \
                               #expr);                                         \
  } while (0)

#define otrng_assert_is_success(otrng_result)                                  \
  do {                                                                         \
    otrng_assert(otrng_result == OTRNG_SUCCESS);                               \
  } while (0)

#define otrng_assert_is_error(otrng_result)                                    \
  do {                                                                         \
    otrng_assert(otrng_result == OTRNG_ERROR);                                 \
  } while (0)

#define otrng_assert_mpi_eq(m1, m2)                                            \
  do {                                                                         \
    const otrng_mpi_p _m1 = {(m1)[0]};                                         \
    const otrng_mpi_p _m2 = {(m2)[0]};                                         \
    g_assert_cmpuint(_m1->len, ==, _m2->len);                                  \
    otrng_assert_cmpmem(_m1->data, _m2->data, _m1->len);                       \
  } while (0)

#define otrng_assert_prekey_profile_eq(p1, p2)                                 \
  do {                                                                         \
    const otrng_prekey_profile_s *_p1 = (p1);                                  \
    const otrng_prekey_profile_s *_p2 = (p2);                                  \
    g_assert_cmpuint(_p1->instance_tag, ==, _p2->instance_tag);                \
    otrng_assert_point_equals(_p1->shared_prekey, _p2->shared_prekey);         \
    otrng_assert_cmpmem(_p1->signature, _p2->signature,                        \
                        sizeof(eddsa_signature_p));                            \
  } while (0)

#define otrng_assert_client_profile_eq(p1, p2)                                 \
  do {                                                                         \
    const client_profile_s *_p1 = (p1);                                        \
    const client_profile_s *_p2 = (p2);                                        \
    g_assert_cmpuint(_p1->sender_instance_tag, ==, _p2->sender_instance_tag);  \
    otrng_assert_point_equals(_p1->long_term_pub_key, _p2->long_term_pub_key); \
    otrng_assert_cmpmem(_p1->versions, _p2->versions,                          \
                        strlen(_p1->versions) + 1);                            \
    g_assert_cmpuint(_p1->expires, ==, _p2->expires);                          \
    otrng_assert_cmpmem(_p1->signature, _p2->signature,                        \
                        ED448_SIGNATURE_BYTES);                                \
    otrng_assert_cmpmem(_p1->transitional_signature,                           \
                        _p2->transitional_signature, OTRv3_DSA_SIG_BYTES);     \
  } while (0)

// TODO: this is using variable-length array
#define otrng_assert_not_zero(s, len)                                          \
  do {                                                                         \
    const uint8_t *_s = (uint8_t *)(s);                                        \
    const size_t _len = (len);                                                 \
    char *__s = _otrng_memdump(_s, _len);                                      \
    char zero_value[_len];                                                     \
    memset(zero_value, 0, sizeof zero_value);                                  \
    char *__msg = g_strdup_printf("assertion failed: (%s)\nRESULT (%p): %s\n", \
                                  #s " is zero", (void *)_s, __s);             \
    if (goldilocks_memeq(_s, zero_value, _len) == 0)                           \
      ;                                                                        \
    else                                                                       \
      g_assertion_message(G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, __msg); \
    free(__s);                                                                 \
    g_free(__msg);                                                             \
  } while (0)

// TODO: this is using variable-length array
#define otrng_assert_zero(s, len)                                              \
  do {                                                                         \
    const uint8_t *_s = (uint8_t *)(s);                                        \
    const size_t _len = (len);                                                 \
    char zero_value[_len];                                                     \
    memset(zero_value, 0, sizeof zero_value);                                  \
    otrng_assert_cmpmem(zero_value, _s, _len);                                 \
  } while (0)

#define otrng_assert_ec_public_key_eq(pk1, pk2)                                \
  do {                                                                         \
    otrng_assert_cmpmem((pk1), (pk2), sizeof(ec_point_p));                     \
  } while (0)

#define otrng_assert_dh_public_key_eq(pk1, pk2)                                \
  do {                                                                         \
    g_assert_cmpint(dh_mpi_cmp((pk1), (pk2)), ==, 0);                          \
  } while (0)

#define otrng_assert_root_key_eq(rk1, rk2)                                     \
  do {                                                                         \
    otrng_assert_cmpmem((rk1), (rk2), sizeof(root_key_p));                     \
  } while (0)

#define otrng_assert_chain_key_eq(ck1, ck2)                                    \
  do {                                                                         \
    otrng_assert_cmpmem((ck1), (ck2), sizeof(chain_key_p));                    \
  } while (0)

#define fn_apply(fn, ...)                                                      \
  {                                                                            \
    void *stopper = (int[]){0};                                                \
    void **list = (void *[]){__VA_ARGS__, stopper};                            \
    for (int i = 0; list[i] != stopper; i++)                                   \
      fn(list[i]);                                                             \
  }

#define otrng_free_all(...) fn_apply(otrng_free, __VA_ARGS__);

#define otrng_response_free_all(...) fn_apply(otrng_response_free, __VA_ARGS__);

#define otrng_user_state_free_all(...)                                         \
  fn_apply(otrl_userstate_free, __VA_ARGS__);

#define otrng_client_state_free_all(...)                                       \
  fn_apply(otrng_client_state_free, __VA_ARGS__);

#define otrng_client_free_all(...) fn_apply(otrng_client_free, __VA_ARGS__);

#define assert_msg_sent(result, to_send)                                       \
  do {                                                                         \
    const otrng_result _result = (result);                                     \
    const char *_to_send = (to_send);                                          \
    otrng_assert_is_success(_result);                                          \
    otrng_assert(_to_send);                                                    \
    otrng_assert_cmpmem("?OTR:AAQD", _to_send, 9);                             \
  } while (0)

#define assert_msg_rec(result, message, response)                              \
  do {                                                                         \
    const otrng_result _result = (result);                                     \
    const char *_message = (message);                                          \
    const otrng_response_s *_response = (response);                            \
    otrng_assert_is_success(_result);                                          \
    otrng_assert_cmpmem(_message, _response->to_display,                       \
                        strlen(_message) + 1);                                 \
    otrng_assert(_response->to_send == NULL);                                  \
  } while (0)

#define assert_rec_msg_in_state(result, respond_to, sender, otr_state,         \
                                send_response)                                 \
  do {                                                                         \
    const otrng_result _result = (result);                                     \
    const otrng_response_s *_respond_to = (respond_to);                        \
    const otrng_s *_sender = (sender);                                         \
    const otrng_state_e _otr_state = (otr_state);                              \
    const otrng_bool _send_response = (send_response);                         \
    otrng_assert_is_success(_result);                                          \
    otrng_assert(!_respond_to->to_display);                                    \
    otrng_assert(_sender->state == _otr_state);                                \
    if (_send_response) {                                                      \
      otrng_assert(_respond_to->to_send);                                      \
    } else {                                                                   \
      otrng_assert(!_respond_to->to_send);                                     \
    }                                                                          \
  } while (0)

static inline void otrng_assert_point_equals(const ec_point_p expected,
                                             const ec_point_p actual) {
  g_assert_cmpint(otrng_ec_point_eq(expected, actual), !=, otrng_false);
}

#endif // __TEST_HELPERS_H__
