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

#include "client_orchestration.h"
#include "messaging.h"

static otrng_client_s *temp_client;

static int load_privkey_v4__called = 0;
static otrng_client_id_s load_privkey_v4__called_with;
static otrng_keypair_s *load_privkey_v4__assign = NULL;

static int create_privkey_v4__called = 0;
static otrng_client_id_s create_privkey_v4__called_with;
static otrng_keypair_s *create_privkey_v4__assign = NULL;

static int store_privkey_v4__called = 0;
static otrng_client_s *store_privkey_v4__called_with;

static void load_privkey_v4(const otrng_client_id_s cid) {
  load_privkey_v4__called++;
  load_privkey_v4__called_with = cid;

  temp_client->keypair = load_privkey_v4__assign;
}

static void create_privkey_v4(const otrng_client_id_s cid) {
  create_privkey_v4__called++;
  create_privkey_v4__called_with = cid;

  temp_client->keypair = create_privkey_v4__assign;
}

static void store_privkey_v4(otrng_client_s *client) {
  store_privkey_v4__called++;
  store_privkey_v4__called_with = client;
}

static void load_client_profile(const otrng_client_id_s cid) { (void)cid; }

static void load_prekey_profile(const otrng_client_id_s cid) { (void)cid; }

static void store_client_profile(otrng_client_s *client,
                                 const otrng_client_id_s cid) {
  (void)client;
  (void)cid;
}

static void store_prekey_profile(otrng_client_s *client,
                                 const otrng_client_id_s cid) {
  (void)client;
  (void)cid;
}
static void load_prekey_messages(otrng_client_s *client) { (void)client; }
static void store_prekey_messages(otrng_client_s *client) { (void)client; }
static void load_forging_key(otrng_client_s *client) { (void)client; }
static void store_forging_key(otrng_client_s *client) { (void)client; }
static void create_forging_key(const otrng_client_id_s cid) { (void)cid; }
static void create_client_profile(otrng_client_s *client,
                                  const otrng_client_id_s cid) {
  (void)client;
  (void)cid;
}
static void store_expired_client_profile(otrng_client_s *client) {
  (void)client;
}
static void load_expired_client_profile(otrng_client_s *client) {
  (void)client;
}
static void store_expired_prekey_profile(otrng_client_s *client) {
  (void)client;
}
static void load_expired_prekey_profile(otrng_client_s *client) {
  (void)client;
}
static void create_prekey_profile(otrng_client_s *client,
                                  const otrng_client_id_s cid) {
  (void)client;
  (void)cid;
}

static void
test__otrng_client_ensure_correct_state__creates_new_long_term_key(void) {
  otrng_client_callbacks_s callbacks;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1};
  uint8_t sym2[ED448_PRIVATE_BYTES] = {2};
  otrng_keypair_s forging_key;
  otrng_global_state_s gs = {
      .clients = NULL,
      .callbacks = &callbacks,
      .user_state_v3 = NULL,
  };
  otrng_client_id_s cid = {
      .protocol = "test-otr",
      .account = "sita@otr.im",
  };
  otrng_client_s *client = otrng_client_new(cid);
  client->global_state = &gs;
  gs.clients = otrng_list_add(client, gs.clients);
  callbacks.load_privkey_v4 = load_privkey_v4;
  callbacks.store_privkey_v4 = store_privkey_v4;
  callbacks.create_privkey_v4 = create_privkey_v4;
  callbacks.load_client_profile = load_client_profile;
  callbacks.load_prekey_profile = load_prekey_profile;
  callbacks.store_client_profile = store_client_profile;
  callbacks.store_prekey_profile = store_prekey_profile;
  callbacks.load_prekey_messages = load_prekey_messages;
  callbacks.store_prekey_messages = store_prekey_messages;
  callbacks.load_forging_key = load_forging_key;
  callbacks.store_forging_key = store_forging_key;
  callbacks.create_forging_key = create_forging_key;
  callbacks.create_client_profile = create_client_profile;
  callbacks.store_expired_client_profile = store_expired_client_profile;
  callbacks.load_expired_client_profile = load_expired_client_profile;
  callbacks.store_expired_prekey_profile = store_expired_prekey_profile;
  callbacks.load_expired_prekey_profile = load_expired_prekey_profile;
  callbacks.create_prekey_profile = create_prekey_profile;

  temp_client = client;

  load_privkey_v4__called = 0;
  store_privkey_v4__called = 0;
  create_privkey_v4__called = 0;

  load_privkey_v4__assign = NULL;

  create_privkey_v4__assign = otrng_keypair_new();
  otrng_keypair_generate(create_privkey_v4__assign, sym1);
  otrng_keypair_generate(&forging_key, sym2);

  client->client_profile = otrng_client_profile_build(
      1234, "4", create_privkey_v4__assign, forging_key.pub, time(NULL) + 420);
  client->prekey_profile =
      otrng_prekey_profile_build(1234, create_privkey_v4__assign);

  otrng_client_ensure_correct_state(client);

  g_assert_cmpint(load_privkey_v4__called, ==, 1);
  g_assert_cmpstr(load_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(load_privkey_v4__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(create_privkey_v4__called, ==, 1);
  g_assert_cmpstr(create_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(create_privkey_v4__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(store_privkey_v4__called, ==, 1);
  g_assert(store_privkey_v4__called_with == client);

  g_assert(client->client_profile == NULL);
  g_assert(client->prekey_profile == NULL);

  store_privkey_v4__called_with = NULL;
  create_privkey_v4__assign = NULL;
  otrng_client_free(client);
  temp_client = NULL;
}

static void
test__otrng_client_ensure_correct_state__fails_creating_long_term_key(void) {
  otrng_client_callbacks_s callbacks;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1};
  uint8_t sym2[ED448_PRIVATE_BYTES] = {2};
  otrng_keypair_s forging_key, long_term;
  otrng_client_profile_s *client_profile;
  otrng_prekey_profile_s *prekey_profile;
  otrng_global_state_s gs = {
      .clients = NULL,
      .callbacks = &callbacks,
      .user_state_v3 = NULL,
  };
  otrng_client_id_s cid = {
      .protocol = "test-otr",
      .account = "sita@otr.im",
  };
  otrng_client_s *client = otrng_client_new(cid);
  client->global_state = &gs;
  gs.clients = otrng_list_add(client, gs.clients);
  callbacks.load_privkey_v4 = load_privkey_v4;
  callbacks.store_privkey_v4 = store_privkey_v4;
  callbacks.create_privkey_v4 = create_privkey_v4;
  callbacks.load_client_profile = load_client_profile;
  callbacks.load_prekey_profile = load_prekey_profile;
  callbacks.store_client_profile = store_client_profile;
  callbacks.store_prekey_profile = store_prekey_profile;
  callbacks.load_prekey_messages = load_prekey_messages;
  callbacks.store_prekey_messages = store_prekey_messages;
  callbacks.load_forging_key = load_forging_key;
  callbacks.store_forging_key = store_forging_key;
  callbacks.create_forging_key = create_forging_key;
  callbacks.create_client_profile = create_client_profile;
  callbacks.store_expired_client_profile = store_expired_client_profile;
  callbacks.load_expired_client_profile = load_expired_client_profile;
  callbacks.store_expired_prekey_profile = store_expired_prekey_profile;
  callbacks.load_expired_prekey_profile = load_expired_prekey_profile;
  callbacks.create_prekey_profile = create_prekey_profile;

  temp_client = client;

  load_privkey_v4__called = 0;
  store_privkey_v4__called = 0;
  create_privkey_v4__called = 0;

  load_privkey_v4__assign = NULL;
  create_privkey_v4__assign = NULL;

  otrng_keypair_generate(&long_term, sym1);
  otrng_keypair_generate(&forging_key, sym2);
  client_profile = otrng_client_profile_build(
      1234, "4", &long_term, forging_key.pub, time(NULL) + 420);
  prekey_profile = otrng_prekey_profile_build(1234, &long_term);
  client->client_profile = client_profile;
  client->prekey_profile = prekey_profile;

  otrng_client_ensure_correct_state(client);

  g_assert_cmpint(load_privkey_v4__called, ==, 1);
  g_assert_cmpstr(load_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(load_privkey_v4__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(create_privkey_v4__called, ==, 1);
  g_assert_cmpstr(create_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(create_privkey_v4__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(store_privkey_v4__called, ==, 0);

  g_assert(client->keypair == NULL);

  g_assert(client->client_profile == client_profile);
  g_assert(client->prekey_profile == prekey_profile);

  store_privkey_v4__called_with = NULL;
  create_privkey_v4__assign = NULL;
  otrng_client_free(client);
}

static void test__otrng_client_ensure_correct_state__loads_long_term_key(void) {
  otrng_client_callbacks_s callbacks;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1};
  otrng_global_state_s gs = {
      .clients = NULL,
      .callbacks = &callbacks,
      .user_state_v3 = NULL,
  };
  otrng_client_id_s cid = {
      .protocol = "test-otr",
      .account = "sita2@otr.im",
  };
  otrng_client_s *client = otrng_client_new(cid);
  client->global_state = &gs;
  gs.clients = otrng_list_add(client, gs.clients);
  callbacks.load_privkey_v4 = load_privkey_v4;
  callbacks.store_privkey_v4 = store_privkey_v4;
  callbacks.create_privkey_v4 = create_privkey_v4;
  callbacks.load_client_profile = load_client_profile;
  callbacks.load_prekey_profile = load_prekey_profile;
  callbacks.store_client_profile = store_client_profile;
  callbacks.store_prekey_profile = store_prekey_profile;
  callbacks.load_prekey_messages = load_prekey_messages;
  callbacks.store_prekey_messages = store_prekey_messages;
  callbacks.load_forging_key = load_forging_key;
  callbacks.store_forging_key = store_forging_key;
  callbacks.create_forging_key = create_forging_key;
  callbacks.create_client_profile = create_client_profile;
  callbacks.store_expired_client_profile = store_expired_client_profile;
  callbacks.load_expired_client_profile = load_expired_client_profile;
  callbacks.store_expired_prekey_profile = store_expired_prekey_profile;
  callbacks.load_expired_prekey_profile = load_expired_prekey_profile;
  callbacks.create_prekey_profile = create_prekey_profile;

  temp_client = client;

  load_privkey_v4__called = 0;
  store_privkey_v4__called = 0;
  create_privkey_v4__called = 0;

  create_privkey_v4__assign = NULL;

  load_privkey_v4__assign = otrng_keypair_new();
  otrng_keypair_generate(load_privkey_v4__assign, sym1);

  otrng_client_ensure_correct_state(client);

  g_assert_cmpint(load_privkey_v4__called, ==, 1);
  g_assert_cmpstr(load_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(load_privkey_v4__called_with.account, ==, "sita2@otr.im");

  g_assert_cmpint(create_privkey_v4__called, ==, 0);
  g_assert_cmpint(store_privkey_v4__called, ==, 0);

  store_privkey_v4__called_with = NULL;
  load_privkey_v4__assign = NULL;
  otrng_client_free(client);
}

static void
test__otrng_client_ensure_correct_state__doesnt_load_long_term_key_if_already_exists(
    void) {
  otrng_client_callbacks_s callbacks;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1};
  otrng_global_state_s gs = {
      .clients = NULL,
      .callbacks = &callbacks,
      .user_state_v3 = NULL,
  };
  otrng_client_id_s cid = {
      .protocol = "test-otr",
      .account = "sita2@otr.im",
  };
  otrng_client_s *client = otrng_client_new(cid);
  client->global_state = &gs;
  gs.clients = otrng_list_add(client, gs.clients);
  callbacks.load_privkey_v4 = load_privkey_v4;
  callbacks.store_privkey_v4 = store_privkey_v4;
  callbacks.create_privkey_v4 = create_privkey_v4;
  callbacks.load_client_profile = load_client_profile;
  callbacks.load_prekey_profile = load_prekey_profile;
  callbacks.store_client_profile = store_client_profile;
  callbacks.store_prekey_profile = store_prekey_profile;
  callbacks.load_prekey_messages = load_prekey_messages;
  callbacks.store_prekey_messages = store_prekey_messages;
  callbacks.load_forging_key = load_forging_key;
  callbacks.store_forging_key = store_forging_key;
  callbacks.create_forging_key = create_forging_key;
  callbacks.create_client_profile = create_client_profile;
  callbacks.store_expired_client_profile = store_expired_client_profile;
  callbacks.load_expired_client_profile = load_expired_client_profile;
  callbacks.store_expired_prekey_profile = store_expired_prekey_profile;
  callbacks.load_expired_prekey_profile = load_expired_prekey_profile;
  callbacks.create_prekey_profile = create_prekey_profile;

  temp_client = client;

  load_privkey_v4__called = 0;
  store_privkey_v4__called = 0;
  create_privkey_v4__called = 0;

  client->keypair = otrng_keypair_new();
  otrng_keypair_generate(client->keypair, sym1);

  otrng_client_ensure_correct_state(client);

  g_assert_cmpint(load_privkey_v4__called, ==, 0);
  g_assert_cmpint(create_privkey_v4__called, ==, 0);
  g_assert_cmpint(store_privkey_v4__called, ==, 0);

  otrng_client_free(client);
}

void units_orchestration_add_tests(void) {
  g_test_add_func(
      "/orchestration/ensure_correct_state/long_term_key/creates",
      test__otrng_client_ensure_correct_state__creates_new_long_term_key);
  g_test_add_func("/orchestration/ensure_correct_state/long_term_key/loads",
                  test__otrng_client_ensure_correct_state__loads_long_term_key);
  g_test_add_func(
      "/orchestration/ensure_correct_state/long_term_key/ensures",
      test__otrng_client_ensure_correct_state__doesnt_load_long_term_key_if_already_exists);
  g_test_add_func(
      "/orchestration/ensure_correct_state/long_term_key/fails",
      test__otrng_client_ensure_correct_state__fails_creating_long_term_key);
}
