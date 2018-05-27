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
#include "shared.h"

typedef struct heartbeat_s {
  int time;
  time_t last_msg_sent;
} heartbeat_s, heartbeat_p[1];

typedef struct otrng_client_state_s {
  const void *client_id; /* Data in the messaging application context that
                            represents a client and should map directly to it.
                            For example, in libpurple-based apps (like Pidgin)
                            this could be a PurpleAccount */

  // TODO: Replace with a callback that knows how to get these from the
  // client_id.
  char *account_name;
  char *protocol_name;

  const struct otrng_client_callbacks_s *callbacks;

  // TODO: We could point it directly to the user state and have access to the
  // callback and v3 user state
  OtrlUserState user_state;
  otrng_keypair_s *keypair;

  // TODO: One or many?
  client_profile_s *client_profile;
  otrng_shared_prekey_pair_s *shared_prekey_pair; // TODO: is this something the
                                                  // client will generate? The
                                                  // spec does not specify.
  char *phi; // this is the shared session state
  bool pad;  // TODO: this can be replaced by length
  int max_stored_msg_keys;
  heartbeat_s *heartbeat;

  // OtrlPrivKey *privkeyv3; // ???
  // otrng_instag_s *instag; // TODO: Store the instance tag here rather than
  // use v3 User State as a store for instance tags
} otrng_client_state_s, otrng_client_state_p[1];

API int otrng_client_state_instance_tag_read_FILEp(otrng_client_state_s *state,
                                                   FILE *instag);

INTERNAL unsigned int
otrng_client_state_get_instance_tag(otrng_client_state_s *state);

INTERNAL int otrng_client_state_add_instance_tag(otrng_client_state_s *state,
                                                 unsigned int instag);

INTERNAL int
otrng_client_state_add_shared_prekey_v4(otrng_client_state_s *state,
                                        const uint8_t sym[ED448_PRIVATE_BYTES]);

API const client_profile_s *
otrng_client_state_get_client_profile(otrng_client_state_s *state);

API int otrng_client_state_add_client_profile(otrng_client_state_s *state,
                                              const client_profile_s *profile);

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

#ifdef OTRNG_CLIENT_STATE_PRIVATE

tstatic heartbeat_s *set_heartbeat(int wait);

#endif

#endif
