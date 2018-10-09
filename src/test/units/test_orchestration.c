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
static void load_privkey_v4(const otrng_client_id_s cid) {
  load_privkey_v4__called++;
  load_privkey_v4__called_with = cid;

  temp_client->keypair = load_privkey_v4__assign;
}

static int create_privkey_v4__called = 0;
static otrng_client_id_s create_privkey_v4__called_with;
static otrng_keypair_s *create_privkey_v4__assign = NULL;
static void create_privkey_v4(const otrng_client_id_s cid) {
  create_privkey_v4__called++;
  create_privkey_v4__called_with = cid;

  temp_client->keypair = create_privkey_v4__assign;
}

static int store_privkey_v4__called = 0;
static otrng_client_s *store_privkey_v4__called_with;
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

static int load_forging_key__called = 0;
static otrng_client_s *load_forging_key__called_with;
static otrng_public_key *load_forging_key__assign = NULL;
static void load_forging_key(otrng_client_s *client) {
  load_forging_key__called++;
  load_forging_key__called_with = client;

  temp_client->forging_key = load_forging_key__assign;
}

static int store_forging_key__called = 0;
static otrng_client_s *store_forging_key__called_with;
static void store_forging_key(otrng_client_s *client) {
  store_forging_key__called++;
  store_forging_key__called_with = client;
}

static int create_forging_key__called = 0;
static otrng_client_id_s create_forging_key__called_with;
static otrng_public_key *create_forging_key__assign = NULL;
static void create_forging_key(const otrng_client_id_s cid) {
  create_forging_key__called++;
  create_forging_key__called_with = cid;

  temp_client->forging_key = create_forging_key__assign;
}

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

typedef struct orchestration_fixture_s {
  otrng_client_callbacks_s *callbacks;
  otrng_keypair_s *long_term_key;
  otrng_keypair_s *forging_key;
  otrng_global_state_s *gs;
  otrng_client_id_s client_id;
  otrng_client_s *client;
  otrng_client_profile_s *client_profile;
  otrng_prekey_profile_s *prekey_profile;
} orchestration_fixture_s;

static void orchestration_fixture_setup(orchestration_fixture_s *f,
                                        gconstpointer user_data) {
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1};
  uint8_t sym2[ED448_PRIVATE_BYTES] = {2};

  (void)user_data;

  f->callbacks = otrng_xmalloc_z(sizeof(otrng_client_callbacks_s));
  f->gs = otrng_xmalloc_z(sizeof(otrng_global_state_s));
  f->gs->callbacks = f->callbacks;
  f->client_id.protocol = "test-otr";
  f->client_id.account = "sita@otr.im";

  f->client = otrng_client_new(f->client_id);
  f->client->global_state = f->gs;
  f->gs->clients = otrng_list_add(f->client, f->gs->clients);

  f->callbacks->load_privkey_v4 = load_privkey_v4;
  f->callbacks->store_privkey_v4 = store_privkey_v4;
  f->callbacks->create_privkey_v4 = create_privkey_v4;
  f->callbacks->load_client_profile = load_client_profile;
  f->callbacks->load_prekey_profile = load_prekey_profile;
  f->callbacks->store_client_profile = store_client_profile;
  f->callbacks->store_prekey_profile = store_prekey_profile;
  f->callbacks->load_prekey_messages = load_prekey_messages;
  f->callbacks->store_prekey_messages = store_prekey_messages;
  f->callbacks->load_forging_key = load_forging_key;
  f->callbacks->store_forging_key = store_forging_key;
  f->callbacks->create_forging_key = create_forging_key;
  f->callbacks->create_client_profile = create_client_profile;
  f->callbacks->store_expired_client_profile = store_expired_client_profile;
  f->callbacks->load_expired_client_profile = load_expired_client_profile;
  f->callbacks->store_expired_prekey_profile = store_expired_prekey_profile;
  f->callbacks->load_expired_prekey_profile = load_expired_prekey_profile;
  f->callbacks->create_prekey_profile = create_prekey_profile;

  f->long_term_key = otrng_keypair_new();
  otrng_keypair_generate(f->long_term_key, sym1);

  f->forging_key = otrng_keypair_new();
  otrng_keypair_generate(f->forging_key, sym2);

  f->client_profile = otrng_client_profile_build(
      1234, "4", f->long_term_key, f->forging_key->pub, time(NULL) + 420);
  f->prekey_profile = otrng_prekey_profile_build(1234, f->long_term_key);

  temp_client = f->client;

  load_privkey_v4__called = 0;
  load_privkey_v4__assign = NULL;
  load_privkey_v4__called_with.protocol = NULL;
  load_privkey_v4__called_with.account = NULL;

  store_privkey_v4__called = 0;
  store_privkey_v4__called_with = NULL;

  create_privkey_v4__called = 0;
  create_privkey_v4__assign = NULL;
  create_privkey_v4__called_with.protocol = NULL;
  create_privkey_v4__called_with.account = NULL;

  load_forging_key__called = 0;
  load_forging_key__assign = NULL;
  load_forging_key__called_with = NULL;

  store_forging_key__called = 0;
  store_forging_key__called_with = NULL;

  create_forging_key__called = 0;
  create_forging_key__assign = NULL;
  create_forging_key__called_with.protocol = NULL;
  create_forging_key__called_with.account = NULL;
}

static void orchestration_fixture_teardown(orchestration_fixture_s *f,
                                           gconstpointer user_data) {
  (void)user_data;

  free(f->callbacks);
  otrng_client_free(f->client);
  otrng_list_free_nodes(f->gs->clients);
  free(f->gs);
  free(f->long_term_key);
  free(f->forging_key);
  otrng_client_profile_free(f->client_profile);
  otrng_prekey_profile_free(f->prekey_profile);
}

static otrng_client_profile_s *
create_client_profile_copy_from(const otrng_client_profile_s *src) {
  otrng_client_profile_s *result =
      otrng_xmalloc_z(sizeof(otrng_client_profile_s));
  otrng_client_profile_copy(result, src);
  return result;
}

static otrng_prekey_profile_s *
create_prekey_profile_copy_from(const otrng_prekey_profile_s *src) {
  otrng_prekey_profile_s *result =
      otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));
  otrng_prekey_profile_copy(result, src);
  return result;
}

static void test__otrng_client_ensure_correct_state__creates_new_long_term_key(
    orchestration_fixture_s *f, gconstpointer data) {
  (void)data;

  create_privkey_v4__assign = f->long_term_key;
  f->client->client_profile =
      create_client_profile_copy_from(f->client_profile);
  f->client->prekey_profile =
      create_prekey_profile_copy_from(f->prekey_profile);

  otrng_client_ensure_correct_state(f->client);

  g_assert_cmpint(load_privkey_v4__called, ==, 1);
  g_assert_cmpstr(load_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(load_privkey_v4__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(create_privkey_v4__called, ==, 1);
  g_assert_cmpstr(create_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(create_privkey_v4__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(store_privkey_v4__called, ==, 1);
  g_assert(store_privkey_v4__called_with == f->client);

  g_assert(f->client->client_profile == NULL);
  g_assert(f->client->prekey_profile == NULL);

  f->client->keypair = NULL;
}

static void
test__otrng_client_ensure_correct_state__fails_creating_long_term_key(
    orchestration_fixture_s *f, gconstpointer data) {
  otrng_client_profile_s *copy_cp =
      create_client_profile_copy_from(f->client_profile);
  otrng_prekey_profile_s *copy_pp =
      create_prekey_profile_copy_from(f->prekey_profile);

  (void)data;

  f->client->client_profile = copy_cp;
  f->client->prekey_profile = copy_pp;

  otrng_client_ensure_correct_state(f->client);

  g_assert_cmpint(load_privkey_v4__called, ==, 1);
  g_assert_cmpstr(load_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(load_privkey_v4__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(create_privkey_v4__called, ==, 1);
  g_assert_cmpstr(create_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(create_privkey_v4__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(store_privkey_v4__called, ==, 0);

  g_assert(f->client->keypair == NULL);

  g_assert(f->client->client_profile == copy_cp);
  g_assert(f->client->prekey_profile == copy_pp);
}

static void test__otrng_client_ensure_correct_state__loads_long_term_key(
    orchestration_fixture_s *f, gconstpointer data) {
  (void)data;

  load_privkey_v4__assign = f->long_term_key;

  otrng_client_ensure_correct_state(f->client);

  g_assert_cmpint(load_privkey_v4__called, ==, 1);
  g_assert_cmpstr(load_privkey_v4__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(load_privkey_v4__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(create_privkey_v4__called, ==, 0);
  g_assert_cmpint(store_privkey_v4__called, ==, 0);

  f->client->keypair = NULL;
}

static void
test__otrng_client_ensure_correct_state__doesnt_load_long_term_key_if_already_exists(
    orchestration_fixture_s *f, gconstpointer data) {
  (void)data;
  f->client->keypair = f->long_term_key;

  otrng_client_ensure_correct_state(f->client);

  g_assert_cmpint(load_privkey_v4__called, ==, 0);
  g_assert_cmpint(create_privkey_v4__called, ==, 0);
  g_assert_cmpint(store_privkey_v4__called, ==, 0);

  f->client->keypair = NULL;
}

static void test__otrng_client_ensure_correct_state__forging_key__ensures(
    orchestration_fixture_s *f, gconstpointer data) {
  (void)data;
  f->client->keypair = f->long_term_key;
  f->client->forging_key = &f->forging_key->pub;

  otrng_client_ensure_correct_state(f->client);

  g_assert_cmpint(load_forging_key__called, ==, 0);
  g_assert_cmpint(create_forging_key__called, ==, 0);
  g_assert_cmpint(store_forging_key__called, ==, 0);

  f->client->keypair = NULL;
  f->client->forging_key = NULL;
}

static void test__otrng_client_ensure_correct_state__forging_key__loads(
    orchestration_fixture_s *f, gconstpointer data) {
  (void)data;
  f->client->keypair = f->long_term_key;
  load_forging_key__assign = &f->forging_key->pub;

  otrng_client_ensure_correct_state(f->client);

  g_assert_cmpint(load_forging_key__called, ==, 1);
  g_assert(load_forging_key__called_with == f->client);

  g_assert_cmpint(create_forging_key__called, ==, 0);
  g_assert_cmpint(store_forging_key__called, ==, 0);

  g_assert(f->client->forging_key == &f->forging_key->pub);

  f->client->forging_key = NULL;
  f->client->keypair = NULL;
}

static void test__otrng_client_ensure_correct_state__forging_key__creates(
    orchestration_fixture_s *f, gconstpointer data) {
  (void)data;
  f->client->keypair = f->long_term_key;
  create_forging_key__assign = &f->forging_key->pub;
  f->client->client_profile =
      create_client_profile_copy_from(f->client_profile);

  otrng_client_ensure_correct_state(f->client);

  g_assert_cmpint(load_forging_key__called, ==, 1);
  g_assert(load_forging_key__called_with == f->client);

  g_assert_cmpint(create_forging_key__called, ==, 1);
  g_assert_cmpstr(create_forging_key__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(create_forging_key__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(store_forging_key__called, ==, 1);
  g_assert(store_forging_key__called_with == f->client);

  g_assert(f->client->forging_key == &f->forging_key->pub);

  g_assert(f->client->client_profile == NULL);

  f->client->forging_key = NULL;
  f->client->keypair = NULL;
}

static void test__otrng_client_ensure_correct_state__forging_key__fails(
    orchestration_fixture_s *f, gconstpointer data) {
  (void)data;
  f->client->keypair = f->long_term_key;
  f->client->client_profile = f->client_profile;

  otrng_client_ensure_correct_state(f->client);

  g_assert_cmpint(load_forging_key__called, ==, 1);
  g_assert(load_forging_key__called_with == f->client);

  g_assert_cmpint(create_forging_key__called, ==, 1);
  g_assert_cmpstr(create_forging_key__called_with.protocol, ==, "test-otr");
  g_assert_cmpstr(create_forging_key__called_with.account, ==, "sita@otr.im");

  g_assert_cmpint(store_forging_key__called, ==, 0);

  g_assert(f->client->forging_key == NULL);

  g_assert(f->client->client_profile == f->client_profile);

  f->client->client_profile = NULL;
  f->client->forging_key = NULL;
  f->client->keypair = NULL;
}

#define WITH_O_FIXTURE(_p, _c)                                                 \
  WITH_FIXTURE(_p, _c, orchestration_fixture_s, orchestration_fixture)

void units_orchestration_add_tests(void) {
  WITH_O_FIXTURE(
      "/orchestration/ensure_correct_state/long_term_key/creates",
      test__otrng_client_ensure_correct_state__creates_new_long_term_key);
  WITH_O_FIXTURE("/orchestration/ensure_correct_state/long_term_key/loads",
                 test__otrng_client_ensure_correct_state__loads_long_term_key);
  WITH_O_FIXTURE(
      "/orchestration/ensure_correct_state/long_term_key/ensures",
      test__otrng_client_ensure_correct_state__doesnt_load_long_term_key_if_already_exists);
  WITH_O_FIXTURE(
      "/orchestration/ensure_correct_state/long_term_key/fails",
      test__otrng_client_ensure_correct_state__fails_creating_long_term_key);

  WITH_O_FIXTURE("/orchestration/ensure_correct_state/forging_key/ensures",
                 test__otrng_client_ensure_correct_state__forging_key__ensures);
  WITH_O_FIXTURE("/orchestration/ensure_correct_state/forging_key/loads",
                 test__otrng_client_ensure_correct_state__forging_key__loads);
  WITH_O_FIXTURE("/orchestration/ensure_correct_state/forging_key/creates",
                 test__otrng_client_ensure_correct_state__forging_key__creates);
  WITH_O_FIXTURE("/orchestration/ensure_correct_state/forging_key/fails",
                 test__otrng_client_ensure_correct_state__forging_key__fails);
}
