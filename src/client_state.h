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

#include <stdbool.h>

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
  const void *client_id; /* Data in the messaging application context that
                            represents a client and should map directly to it.
                            For example, in libpurple-based apps (like Pidgin)
                            this could be a PurpleAccount */

  // TODO: @client Replace with a callback that knows how to get these from the
  // client_id.
  char *account_name;
  char *protocol_name;

  const struct otrng_client_callbacks_s *callbacks;

  // TODO: @client We could point it directly to the user state and have access
  // to the callback and v3 user state
  OtrlUserState user_state;
  otrng_keypair_s *keypair;

  // TODO: @client One or many?
  client_profile_s *client_profile;
  otrng_prekey_profile_s *prekey_profile;
  list_element_s *our_prekeys; // otrng_stored_prekeys_s

  /* @secret: this should be deleted once the prekey profile expires */
  otrng_shared_prekey_pair_s
      *shared_prekey_pair; // TODO: @client is this something the
                           // client will generate? The
                           // spec does not specify.

  int max_stored_msg_keys;
  int (*should_heartbeat)(int last_sent);
  bool pad; // TODO: @client @refactoring this can be replaced by length

  // OtrlPrivKey *privkeyv3; // ???
  // otrng_instag_s *instag; // TODO: @client Store the instance tag here rather
  // than use v3 User State as a store for instance tags
} otrng_client_state_s, otrng_client_state_p[1];

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

INTERNAL void store_my_prekey_message(uint32_t id, uint32_t instance_tag,
                                      const ecdh_keypair_p ecdh_pair,
                                      const dh_keypair_p dh_pair,
                                      otrng_client_state_s *state);

INTERNAL void delete_my_prekey_message_by_id(uint32_t id,
                                             otrng_client_state_s *state);

INTERNAL const otrng_stored_prekeys_s *
get_my_prekeys_by_id(uint32_t id, const otrng_client_state_s *state);

API int otrng_client_state_instance_tag_read_FILEp(otrng_client_state_s *state,
                                                   FILE *instag);

INTERNAL unsigned int
otrng_client_state_get_instance_tag(otrng_client_state_s *state);

INTERNAL int otrng_client_state_add_instance_tag(otrng_client_state_s *state,
                                                 unsigned int instag);

// TODO: @client @refactoring remove
INTERNAL int
otrng_client_state_add_shared_prekey_v4(otrng_client_state_s *state,
                                        const uint8_t sym[ED448_PRIVATE_BYTES]);

API const client_profile_s *
otrng_client_state_get_client_profile(otrng_client_state_s *state);

API int otrng_client_state_add_client_profile(otrng_client_state_s *state,
                                              const client_profile_s *profile);

API const otrng_prekey_profile_s *
otrng_client_state_get_prekey_profile(otrng_client_state_s *state);

API int
otrng_client_state_add_prekey_profile(otrng_client_state_s *state,
                                      const otrng_prekey_profile_s *profile);

// TODO: @client Read/Write prekey_profiles from/to a file.
INTERNAL int
otrng_client_state_private_key_v4_read_FILEp(otrng_client_state_s *state,
                                             FILE *privf);

INTERNAL int
otrng_client_state_private_key_v4_write_FILEp(otrng_client_state_s *state,
                                              FILE *privf);

INTERNAL int otrng_client_state_private_key_v3_generate_FILEp(
    const otrng_client_state_s *state, FILE *privf);

INTERNAL otrng_keypair_s *
otrng_client_state_get_private_key_v4(otrng_client_state_s *state);

INTERNAL int
otrng_client_state_add_private_key_v4(otrng_client_state_s *state,
                                      const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL void otrng_client_state_free(otrng_client_state_s *);

INTERNAL otrng_client_state_s *otrng_client_state_new(const void *client_id);

INTERNAL const client_profile_s *
otrng_client_state_get_client_profile_by_id(uint32_t id,
                                            otrng_client_state_s *state);

INTERNAL const client_profile_s *
otrng_client_state_get_or_create_client_profile(otrng_client_state_s *state);

INTERNAL const otrng_prekey_profile_s *
otrng_client_state_get_or_create_prekey_profile(otrng_client_state_s *state);

INTERNAL const otrng_prekey_profile_s *
otrng_client_state_get_prekey_profile_by_id(uint32_t id,
                                            otrng_client_state_s *state);

#ifdef OTRNG_CLIENT_STATE_PRIVATE

#endif

#endif
