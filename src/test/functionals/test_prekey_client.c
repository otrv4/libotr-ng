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

#include <glib.h>

#include "test_helpers.h"

#include "test_fixtures.h"

#include "deserialize.h"
#include "random.h"

static const char *domain_for_account_cb_fixed(otrng_client_s *client,
                                               void *ctx) {
  (void)client;
  (void)ctx;
  return "jabber.localhost";
}

static void test_send_dake_1_message(void) {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_fingerprint fpr = {1};

  set_up_client(alice, 1);
  otrng_assert(!alice->conversations);

  otrng_prekey_ensure_manager(alice, "alice@localhost");
  alice->prekey_manager->callbacks->domain_for_account =
      domain_for_account_cb_fixed;

  otrng_prekey_provide_server_identity_for(alice, "jabber.localhost",
                                           "prekey@localhost", fpr);

  char *dake_1 = NULL;
  otrng_assert_is_success(otrng_prekey_publish(&dake_1, alice, NULL));

  otrng_assert(dake_1);
  otrng_free(dake_1);

  otrng_global_state_free(alice->global_state);
}

static void test_send_dake_3_message_with_storage_info_request(void) {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_fingerprint fpr = {1};
  uint8_t sym[ED448_PRIVATE_BYTES] = {0};

  random_bytes(sym, ED448_PRIVATE_BYTES);

  set_up_client(alice, 1);
  otrng_assert(!alice->conversations);

  otrng_prekey_ensure_manager(alice, "alice@localhost");
  alice->prekey_manager->callbacks->domain_for_account =
      domain_for_account_cb_fixed;

  otrng_prekey_provide_server_identity_for(alice, "jabber.localhost",
                                           "prekey@localhost", fpr);

  alice->prekey_manager->request_for_account = create_prekey_request(
      otrng_prekey_get_server_identity_for(alice, "jabber.localhost"), NULL);
  alice->prekey_manager->request_for_account->after_dake =
      storage_request_after_dake;

  otrng_assert_is_success(otrng_ecdh_keypair_generate(
      alice->prekey_manager->request_for_account->ephemeral_ecdh, sym));

  otrng_prekey_dake2_message_s message;
  otrng_prekey_dake2_message_init(&message);

  size_t read = 0;
  uint8_t ser_server_public_key[ED448_PUBKEY_BYTES] = {
      0x0,  0x10, 0xac, 0x2f, 0x26, 0x98, 0xfc, 0xf1, 0x52, 0x84, 0x80, 0x78,
      0x50, 0x5b, 0x4,  0x17, 0x91, 0xe3, 0x42, 0x49, 0xfb, 0x2,  0x9a, 0xd7,
      0x71, 0xf7, 0xf7, 0x6c, 0xc9, 0x31, 0xcc, 0xb5, 0x2d, 0xdb, 0x7,  0x1,
      0x8a, 0x96, 0xb1, 0x28, 0xce, 0x9b, 0x41, 0xed, 0x8a, 0x97, 0xa2, 0x36,
      0xd6, 0xf4, 0xea, 0xf4, 0xe6, 0xb5, 0x2d, 0x1e, 0xa,  0xe4, 0x80,
  };

  uint8_t ser_S[ED448_POINT_BYTES] = {
      0xc0, 0x3d, 0xc6, 0x1f, 0x8b, 0x2e, 0xae, 0x34, 0x6e, 0x5,  0xa8, 0x42,
      0xa2, 0x73, 0xfc, 0x25, 0x3c, 0x9f, 0xcb, 0x49, 0xf1, 0x80, 0x12, 0xc5,
      0xaa, 0x76, 0x57, 0x58, 0x3f, 0xd2, 0xa9, 0x5b, 0x5d, 0x5e, 0x2c, 0xb2,
      0xc6, 0x84, 0xff, 0x9c, 0x3a, 0x5f, 0x53, 0xb,  0x9d, 0x26, 0x2f, 0xc5,
      0x4f, 0x16, 0x95, 0x6,  0xba, 0xa1, 0x54, 0xc4, 0x0,
  };

  otrng_assert_is_success(otrng_deserialize_public_key(
      message.server_pub_key, ser_server_public_key, ED448_PUBKEY_BYTES,
      &read));
  otrng_assert_is_success(
      otrng_deserialize_ec_point(message.S, ser_S, ED448_POINT_BYTES));

  uint8_t composite_identity[86] = {
      0x0,  0x0,  0x0,  0x17, 0x70, 0x72, 0x65, 0x6b, 0x65, 0x79, 0x73,
      0x2e, 0x74, 0x68, 0x61, 0x74, 0x73, 0x6e, 0x6f, 0x74, 0x6d, 0x79,
      0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x0,  0x10, 0x57, 0xd5, 0x5a, 0x70,
      0x2b, 0xc9, 0xcb, 0x5f, 0x43, 0x42, 0xc0, 0x1b, 0x7b, 0x60, 0x22,
      0x27, 0x7c, 0x99, 0xf3, 0x3a, 0x6e, 0xd5, 0x1,  0x5f, 0x4c, 0xb,
      0x10, 0xa,  0x46, 0xc7, 0xc6, 0xc0, 0x97, 0x9d, 0xb9, 0x2f, 0x9f,
      0x35, 0xa5, 0x1c, 0x77, 0x2b, 0x77, 0xa0, 0x90, 0x76, 0x2d, 0xaf,
      0xf3, 0x90, 0x46, 0x21, 0xfb, 0x2c, 0xb8, 0x94, 0x0,
  };
  message.composite_identity_len = 86;
  message.composite_identity = otrng_xmalloc_z(message.composite_identity_len);
  memcpy(message.composite_identity, composite_identity,
         message.composite_identity_len);

  char *dake_3 =
      send_dake3(alice, alice->prekey_manager->request_for_account, &message);

  otrng_assert(dake_3);

  otrng_free(dake_3);

  otrng_global_state_free(alice->global_state);
  otrng_prekey_dake2_message_destroy(&message);
}

static void notify_error_cb(struct otrng_client_s *client, int error,
                            void *ctx) {
  (void)ctx;
  (void)error;
  (void)client;
}

static void test_receive_prekey_server_messages(void) {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_fingerprint fpr = {1};

  set_up_client(alice, 1);
  otrng_assert(!alice->conversations);

  otrng_prekey_ensure_manager(alice, "alice@localhost");
  alice->prekey_manager->callbacks->domain_for_account =
      domain_for_account_cb_fixed;
  alice->prekey_manager->callbacks->notify_error = notify_error_cb;

  otrng_prekey_provide_server_identity_for(alice, "jabber.localhost",
                                           "prekey@localhost", fpr);

  char *dake_2 = otrng_xstrndup(
      "AAQ2bQJzmAAAABFwcmVrZXlzLmxvY2FsaG9zdAAQrC8mmPzxUoSAeFBbBBeR40JJ+"
      "wKa13H392zJMcy1LdsHAYqWsSjOm0HtipeiNtb06vTmtS0eCuSAFOnQ3NGhoDG0o+"
      "LAdCMHrcz9TUACdMkMK4ikUa49KYexpGDrsVRLNiH8ts8P/"
      "hC2NxqMjLdk472AqUco6fGEmR2xAHQt7zgfYs1vHJYgFjGYvvdDtqhvOHl5ZT7BSz2F2KU97"
      "piYkyt5mKGQkhLgwTmHdvDtblcPVydZIvmhsNxMNQh/"
      "1wNoR6VwRppufi1rD56gI2ZQPs13PJaRM6FfF4Ds6ymTAPsDI02wiyqNtdHYjZEEtJ+"
      "LxvBXHexnLvTZ1XIvgwAhZD/7ecLmDqBoqHB/p/"
      "9TdiQ8vJy8XqUwfvIQYQtJYrje6iB6rT+"
      "bGf0lW0wIMLIRPvy5SWVnsFNuZILllsxDesb5wKuS9LgSyhiS04YQ/"
      "OTzyjnjDV3JNh2uCEjGWmZSmu04GaxcNwapbELZTyCWlmDhMWqJ96UNbPsHiCVD86uuPlNw5"
      "Cxb9O09MWwGEo664TMwzFc+"
      "vYjSTFISps6lIicYbx4qQt6wii5gwqgZssouuxMD6Ubv7GzLVixS5evkfuA0.",
      642);

  char *to_send = NULL;
  otrng_assert_is_success(
      otrng_prekey_receive(&to_send, alice, "prekey@localhost", dake_2));

  otrng_assert(!to_send); /* wrong instance tag */

  otrng_free(dake_2);

  char *success =
      otrng_xstrndup("AAQGbQJzmIlxG+O+"
                     "2z7bcBMm5pWSQ2FqVbIrXLiJTaDsgfETk59Dnxa5US0avH"
                     "pUD6qTyooaIh2Mqg6PXojQOmWKnj3LqBM=.",
                     98);

  otrng_assert_is_success(
      otrng_prekey_receive(&to_send, alice, "prekey@localhost", success));

  otrng_assert(!to_send); /* wrong instance tag */

  otrng_free(success);

  otrng_global_state_free(alice->global_state);
}

static void test_receive_prekey_ensemble_retrieval_message(void) {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  otrng_fingerprint fpr = {1};

  set_up_client(alice, 1);
  otrng_assert(!alice->conversations);

  otrng_prekey_ensure_manager(alice, "alice@localhost");
  alice->prekey_manager->callbacks->domain_for_account =
      domain_for_account_cb_fixed;
  alice->prekey_manager->callbacks->notify_error = notify_error_cb;

  otrng_prekey_provide_server_identity_for(alice, "jabber.localhost",
                                           "prekey@localhost", fpr);

  char *retrieval_message = otrng_xstrdup(
      "AAQTbQJzmAAAABNwcmVrZXkxLmV4YW1wbGUub3JnAQAAAAUAAduhT/EAAgAQQYoXXP+Mvpf/"
      "MUDNvvd23qYcgX8gBHi1eT1Sl6yrcwH2vesBIPMEQywNGO5M++"
      "Mjkdw3ePORPcUAAAMAEgebJMiBUef9JotlGN8A2ChTm/"
      "eRckQu+xZFPLKX5VMnA7vkOoUiqXUz4er/ZP1c9WiYxeJ43Rl4gAAEAAAAAjM0AAUAAAAAW/"
      "XnONvwscrL09jJYOQ1PmPr6234uoY9t+"
      "qbzWM01peglMQ2mGWLwMejxcmLFpFkV28ZcXwJnXCatVgoACRuaaUgaaJfDorrUz+"
      "Nf9GfiXAUFuhIDs2MEEgoxp9oCWPzMeJ9rMUVMREKl0kzCfHaf5a+IjocANuhT/"
      "EAAAAAXAxZCAARQBBjPpjGvCnnd6zHMA2oXUU04mM4ldGZ/"
      "5N9j59PVarfnwkoaSXpkywUuwURk00gpunDSLBvi/8A5muF3Aa/"
      "b8Ce8WY8xjInht4TvAZFdiB6HAPil9wuh+"
      "qfgnpXTH9vjtKVWggB7m72dU1OlZMQi9WANmkux0TZ/"
      "yywGE36CEVi8HvbBsLd7EEqQpblwNg/mODTbvs07YrVeb/"
      "R96Q8KQOagr0sRoqLDywAAAQPA/iHytuhT/"
      "E+"
      "zno9S7yhfgwhj1wjfOPcMwY6exg7yolPifSKcvc7KQWPDeSphzScHRH9V0vTm2SoFiMnIaMt"
      "4gAAAAGAe2fFRpyDqabFyZ3KvkGOkh/"
      "K45wcPYqb5ay2ToIEuODQyDW+"
      "FMZCIDgBBo5lnUJc7XK7pbj67xndgdWcQBAN4jHahUdm72m+"
      "LvJq4BeNreKtduTNBANCryiFauO9j4lH8WOV/"
      "dxOgJ1sSmXQ9FzkDIqWSactc4NhYsTSOWBXGlgEBd5xiDhj2eQSs6qTetrGDLRCsnT92s+"
      "TchkTLmlGgLva5Uwznka0TfKXF+Mr4SSQQWT1H+/"
      "xuezgSHi1fp0Rx5EP6FVJKErVqCb8Z6opAUW0lx3uy3IHKfaoghMHbAutEw9kmJhONbMfLxY"
      "GyKRHmYLJWfdfgYfMMXFNSWmRjLqPYg0L47l2eCT2ViUEiIB7A8wz/"
      "JzQxbFT9I2KNvuBu2mP4cADU9i6yjWTUr8aOrl+V0urvoyQEfBWubI7+Dyy4/"
      "2jjUeNQqr01/BigZ+B/FQlYSYj46/"
      "QbHeVV7hC1fOWZxat52gb9Bs5YaopZz3xUzzx64X3IKQZ5tmhyVoF.");

  char *to_send = NULL;
  otrng_assert_is_success(otrng_prekey_receive(
      &to_send, alice, "prekey@localhost", retrieval_message));

  otrng_assert(!to_send); /* wrong instance tag */

  otrng_free(retrieval_message);

  otrng_global_state_free(alice->global_state);
}

void functionals_prekey_client_add_tests(void) {
  g_test_add_func("/prekey_server_client/send_dake_1_message",
                  test_send_dake_1_message);
  g_test_add_func(
      "/prekey_server_client/send_dake_3_message_with_storage_info_request",
      test_send_dake_3_message_with_storage_info_request);
  g_test_add_func("/prekey_server_client/receive_prekey_server_messages",
                  test_receive_prekey_server_messages);
  g_test_add_func(
      "/prekey_server_client/receive_prekey_ensemble_retrieval_message",
      test_receive_prekey_ensemble_retrieval_message);
}
