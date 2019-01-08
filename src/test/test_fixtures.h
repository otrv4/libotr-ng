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

#ifndef __TEST_FIXTURES_H__
#define __TEST_FIXTURES_H__

#ifndef S_SPLINT_S
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/privkey.h>
#pragma clang diagnostic pop
#endif

#include "test_helpers.h"

#include "alloc.h"
#include "messaging.h"
#include "persistence.h"

typedef struct otrng_fixture_s {
  otrng_s *otr;
  otrng_s *v3;
  otrng_s *v34;
  otrng_client_s *client;
  otrng_global_state_s *gs;
} otrng_fixture_s, otrng_fixture_p[1];

typedef struct dake_fixture_s {
  otrng_keypair_s *keypair;
  otrng_shared_prekey_pair_s *shared_prekey;
  otrng_client_profile_s *profile;
} dake_fixture_s, dake_fixture_p[1];

int dh_mpi_cmp(const dh_mpi m1, const dh_mpi m2);

otrng_client_id_s create_client_id(const char *protocol, const char *account);

otrng_shared_session_state_s get_shared_session_state_cb(const otrng_s *conv);

void create_client_profile_cb(struct otrng_client_s *client);

void create_prekey_profile_cb(struct otrng_client_s *client);
otrng_public_key *
create_forging_key_from(const uint8_t sym[ED448_PRIVATE_BYTES]);

void otrng_fixture_set_up(otrng_fixture_s *otrng_fixture, gconstpointer data);

void otrng_fixture_teardown(otrng_fixture_s *otrng_fixture, gconstpointer data);

void dake_fixture_setup(dake_fixture_s *f, gconstpointer user_data);

void dake_fixture_teardown(dake_fixture_s *f, gconstpointer user_data);

otrng_bool test_should_not_heartbeat(int last_sent);

void set_up_client(otrng_client_s *client, int byte);

otrng_s *set_up(struct otrng_client_s *client, int byte);

void do_dake_fixture(otrng_s *alice, otrng_s *bob);

void free_message_and_response(otrng_response_s *response, string_p *message);

otrng_result
get_account_and_protocol_cb_empty(char **account, char **protocol,
                                  const struct otrng_client_id_s client_id);

void create_privkey_v3_cb_empty(otrng_client_s *client);

void create_privkey_v4_cb_empty(otrng_client_s *client);

void create_forging_key_cb_empty(otrng_client_s *client);

void create_client_profile_cb_empty(struct otrng_client_s *client);

void write_expired_client_profile_cb_empty(struct otrng_client_s *client);

void create_prekey_profile_cb_empty(struct otrng_client_s *client);

void write_expired_prekey_profile_cb_empty(struct otrng_client_s *client);

void create_shared_prekey_cb_empty(struct otrng_client_s *client);

void display_error_message_cb_empty(const otrng_error_event event,
                                    string_p *to_display,
                                    const struct otrng_s *otr);
otrng_shared_session_state_s
get_shared_session_state_cb_empty(const struct otrng_s *conv);

void load_privkey_v4_cb_empty(struct otrng_client_s *client);

void load_client_profile_cb_empty(struct otrng_client_s *client);

void load_prekey_profile_cb_empty(struct otrng_client_s *client);

void store_fingerprints_v4_cb_empty(struct otrng_client_s *client);
void store_fingerprints_v3_cb_empty(struct otrng_client_s *client);
void load_fingerprints_v4_cb_empty(struct otrng_client_s *client);
void load_fingerprints_v3_cb_empty(struct otrng_client_s *client);

extern otrng_client_callbacks_s test_callbacks[];

#endif // __TEST_FIXTURES_H__
