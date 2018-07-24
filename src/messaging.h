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

#ifndef OTRNG_MESSAGING_H_
#define OTRNG_MESSAGING_H_

/* Defines an API to be used by an IM-plugin, like pidgin-otr-ng */

/*
 * state = otrng_user_state_new();
 * otrng_user_state_private_key_v4_read_FILEp(state, priv4);
 * otrng_user_state_private_key_v4_write_FILEp(state, priv4);
 * otrng_user_state_private_key_v3_read_FILEp(state, priv3);
 * otrng_user_state_private_key_v3_write_FILEp(state, priv3);
 * otrng_user_state_add_private_key_v4(state, alice_xmpp, alice_priv4);
 * otrng_user_state_add_private_key_v3(state, alice_xmpp, alice_priv3);
 *
 * PurpleAccount *alice_xmpp;
 * client = otrng_messaging_client_new(state, alice_xmpp);
 *
 * client = otrng_messaging_client_get(alice_xmpp);
 *
 * PurpleConversation *alice_talking_to_bob;
 * otrng_messaging_client_sending(client, alice_talking_to_bob, instance, "hi");
 * otrng_messaging_client_receiving(client, alice_talking_to_bob);
 */

#include "client.h"
#include "list.h"
#include "shared.h"

// TODO: Remove?
typedef otrng_client_s otrng_messaging_client_s;

typedef struct otrng_user_state_s {
  list_element_s *states;
  list_element_s *clients;

  const otrng_client_callbacks_s *callbacks;
  OtrlUserState user_state_v3;
} otrng_user_state_s, otrng_user_state_p[1];

API int
otrng_user_state_private_key_v3_generate_FILEp(otrng_user_state_s *state,
                                               void *client_id, FILE *privf);

API int otrng_user_state_private_key_v3_read_FILEp(otrng_user_state_s *state,
                                                   FILE *keys);

API int otrng_user_state_generate_private_key(otrng_user_state_s *state,
                                              void *client_id);

API int otrng_user_state_generate_client_profile(otrng_user_state_s *state,
                                                 void *client_id);

API int otrng_user_state_generate_shared_prekey(otrng_user_state_s *state,
                                                void *client_id);

API int
otrng_user_state_private_key_v4_write_FILEp(const otrng_user_state_s *state,
                                            FILE *privf);

int otrng_user_state_add_instance_tag(otrng_user_state_s *state,
                                      void *client_id, unsigned int instag);

unsigned int otrng_user_state_get_instance_tag(otrng_user_state_s *state,
                                               void *client_id);

API int
otrng_user_state_instag_generate_generate_FILEp(otrng_user_state_s *state,
                                                void *client_id, FILE *instag);

int otrng_user_state_instance_tags_read_FILEp(otrng_user_state_s *state,
                                              FILE *instag);

otrng_messaging_client_s *otrng_messaging_client_get(otrng_user_state_s *state,
                                                     void *client_id);

API int otrng_user_state_private_key_v4_read_FILEp(
    otrng_user_state_s *state, FILE *privf,
    const void *(*read_client_id_for_key)(FILE *filep));

API otrng_keypair_s *
otrng_user_state_get_private_key_v4(otrng_user_state_s *state,
                                    const void *client_id);

API otrng_user_state_s *
otrng_user_state_new(const otrng_client_callbacks_s *cb);

API void otrng_user_state_free(otrng_user_state_s *);

#ifdef OTRNG_MESSAGING_PRIVATE

tstatic int
otrng_user_state_add_private_key_v4(otrng_user_state_s *state,
                                    const void *clientop,
                                    const uint8_t sym[ED448_PRIVATE_BYTES]);

/* tstatic otrng_messaging_client_t
 * *otrng_messaging_client_new(otrng_user_state_s *state, */
/*                                                    void *client_id); */

#endif

#endif
