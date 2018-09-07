/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
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

#ifndef OTRNG_CLIENT_STATE_H
#define OTRNG_CLIENT_STATE_H

#include <gcrypt.h>
#include <libotr/userstate.h>

#include "client_callbacks.h"
#include "client_profile.h"
#include "keys.h"
#include "list.h"
#include "prekey_profile.h"
#include "shared.h"

typedef struct {
  uint32_t id;
  uint32_t sender_instance_tag;
  ecdh_keypair_p our_ecdh;
  dh_keypair_p our_dh;
} otrng_stored_prekeys_s, otrng_stored_prekeys_p[1];

typedef struct otrng_client_state_s {
  /* Data in the messaging application context that represents a client and
   * should map directly to it. For example, in libpurple-based apps (like
   * Pidgin) this could be a PurpleAccount */
  const void *client_id;

  const otrng_client_callbacks_s *callbacks;

  // TODO: @client We could point it directly to the user state and have access
  // to the callback and v3 user state
  OtrlUserState user_state;
  otrng_keypair_s *keypair;

  // TODO: @client One or many?
  client_profile_s *client_profile;
  otrng_prekey_profile_s *prekey_profile;
  list_element_s *our_prekeys; // otrng_stored_prekeys_s

  /* @secret: this should be deleted once the prekey profile expires */
  otrng_shared_prekey_pair_s *shared_prekey_pair;

  unsigned int max_stored_msg_keys;
  unsigned int max_published_prekey_msg;
  unsigned int minimum_stored_prekey_msg;
  otrng_bool (*should_heartbeat)(int last_sent);
  size_t padding;

  // OtrlPrivKey *privkeyv3; // ???
  // otrng_instag_s *instag; // TODO: @client Store the instance tag here rather
  // than use v3 User State as a store for instance tags
} otrng_client_state_s, otrng_client_state_p[1];

// TODO: move
static inline void otrng_stored_prekeys_free(otrng_stored_prekeys_s *s) {
  if (!s) {
    return;
  }

  otrng_ecdh_keypair_destroy(s->our_ecdh);
  otrng_dh_keypair_destroy(s->our_dh);

  free(s);
}

static inline void stored_prekeys_free_from_list(void *p) {
  otrng_stored_prekeys_free((otrng_stored_prekeys_s *)p);
}

INTERNAL otrng_result otrng_client_state_get_account_and_protocol(
    char **account, char **protocol, const otrng_client_state_s *client_state);

INTERNAL void store_my_prekey_message(uint32_t id, uint32_t instance_tag,
                                      const ecdh_keypair_p ecdh_pair,
                                      const dh_keypair_p dh_pair,
                                      otrng_client_state_s *client_state);

INTERNAL void
delete_my_prekey_message_by_id(uint32_t id, otrng_client_state_s *client_state);

INTERNAL const otrng_stored_prekeys_s *
get_my_prekeys_by_id(uint32_t id, const otrng_client_state_s *client_state);

INTERNAL unsigned int
otrng_client_state_get_instance_tag(const otrng_client_state_s *client_state);

INTERNAL otrng_result otrng_client_state_add_instance_tag(
    otrng_client_state_s *client_state, unsigned int instag);

// TODO: @client @refactoring remove
INTERNAL otrng_result otrng_client_state_add_shared_prekey_v4(
    otrng_client_state_s *client_state, const uint8_t sym[ED448_PRIVATE_BYTES]);

API client_profile_s *otrng_client_state_build_default_client_profile(
    otrng_client_state_s *client_state);

API otrng_prekey_profile_s *otrng_client_state_build_default_prekey_profile(
    otrng_client_state_s *client_state);

API const client_profile_s *
otrng_client_state_get_client_profile(otrng_client_state_s *client_state);

API otrng_result otrng_client_state_add_client_profile(
    otrng_client_state_s *client_state, const client_profile_s *profile);

API const otrng_prekey_profile_s *
otrng_client_state_get_prekey_profile(otrng_client_state_s *client_state);

API otrng_result otrng_client_state_add_prekey_profile(
    otrng_client_state_s *client_state, const otrng_prekey_profile_s *profile);

// TODO: @client Read/Write prekey_profiles from/to a file.

INTERNAL OtrlPrivKey *
otrng_client_state_get_private_key_v3(const otrng_client_state_s *client_state);

INTERNAL otrng_keypair_s *
otrng_client_state_get_keypair_v4(otrng_client_state_s *client_state);

INTERNAL otrng_result otrng_client_state_add_private_key_v4(
    otrng_client_state_s *client_state, const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL otrng_result otrng_client_state_shared_prekey_write_FILEp(
    const otrng_client_state_s *state, FILE *shared_prekey_f);

INTERNAL void otrng_client_state_free(otrng_client_state_s *client_state);

INTERNAL otrng_client_state_s *otrng_client_state_new(const void *client_id);

API void otrng_client_state_set_padding(size_t granularity,
                                        otrng_client_state_s *client_state);

API void
otrng_client_state_set_max_stored_msg_keys(unsigned int max_stored_msg_keys,
                                           otrng_client_state_s *client_state);

API void otrng_client_state_set_max_published_prekey_msg(
    unsigned int max_published_prekey_msg, otrng_client_state_s *client_state);

API otrng_result otrng_client_state_get_max_published_prekey_msg(
    otrng_client_state_s *client_state);

API void otrng_client_state_set_minimum_stored_prekey_msg(
    unsigned int minimum_stored_prekey_msg, otrng_client_state_s *client_state);

API otrng_result otrng_client_state_get_minimum_stored_prekey_msg(
    otrng_client_state_s *client_state);

#ifdef DEBUG_API
API void otrng_client_state_debug_print(FILE *, int, otrng_client_state_s *);
#endif

#ifdef OTRNG_CLIENT_STATE_PRIVATE

#endif

#endif
