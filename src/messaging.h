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

/**
 * The functions in this file only operate on their arguments, and doesn't touch
 * any global state. It is safe to call these functions concurrently from
 * different threads, as long as arguments pointing to the same memory areas are
 * not used from different threads. However, since the global state points to
 * everything related to a specific OTR clients functionality, it has a lot of
 * references to subordinate objects. To be on the safe side, it's a good idea
 * to serialize access.
 */

#ifndef OTRNG_MESSAGING_H_
#define OTRNG_MESSAGING_H_

/* Defines an API to be used by an IM-plugin, like pidgin-otr-ng */

/*
 * state = otrng_global_state_new();
 * otrng_global_state_private_key_v4_read_from(state, priv4);
 * otrng_global_state_private_key_v4_write_to(state, priv4);
 * otrng_global_state_private_key_v3_read_from(state, priv3);
 * otrng_global_state_private_key_v3_write_FILEp(state, priv3);
 * otrng_global_state_add_private_key_v4(state, alice_xmpp, alice_priv4);
 * otrng_global_state_add_private_key_v3(state, alice_xmpp, alice_priv3);
 *
 * PurpleAccount *alice_xmpp;
 * client = otrng_client_get(state, alice_xmpp);
 *
 * PurpleConversation *alice_talking_to_bob;
 * TODO: fix the below comment, since it doesn't match existing functions
 * otrng_messaging_client_sending(client, alice_talking_to_bob, instance, "hi");
 * otrng_messaging_client_receiving(client, alice_talking_to_bob);
 */

#include "client.h"
#include "list.h"
#include "shared.h"

typedef struct otrng_global_state_s {
  list_element_s *clients;

  const otrng_client_callbacks_s *callbacks;
  OtrlUserState user_state_v3;
  otrng_bool fingerprints_v3_loaded;
} otrng_global_state_s;

API otrng_global_state_s *
otrng_global_state_new(const otrng_client_callbacks_s *cb, otrng_bool die);

API void otrng_global_state_free(otrng_global_state_s *gs);

API otrng_client_s *otrng_client_get(otrng_global_state_s *gs,
                                     const otrng_client_id_s client_id);

API otrng_result otrng_global_state_instag_generate_into(
    otrng_global_state_s *gs, const otrng_client_id_s client_id, FILE *instag);

API otrng_result otrng_global_state_private_key_v3_generate_into(
    otrng_global_state_s *gs, const otrng_client_id_s client_id, FILE *privf);

API otrng_result otrng_global_state_generate_private_key(
    otrng_global_state_s *gs, const otrng_client_id_s client_id);

API otrng_result otrng_global_state_generate_private_key_v3(
    otrng_global_state_s *gs, const otrng_client_id_s client_id);

API otrng_result otrng_global_state_generate_forging_key(
    otrng_global_state_s *gs, const otrng_client_id_s client_id);

API otrng_result otrng_global_state_generate_client_profile(
    otrng_global_state_s *gs, const otrng_client_id_s client_id);

API otrng_result otrng_global_state_generate_prekey_profile(
    otrng_global_state_s *gs, const otrng_client_id_s client_id);

API otrng_result otrng_global_state_private_key_v4_write_to(
    const otrng_global_state_s *gs, FILE *privf);

API otrng_result otrng_global_state_private_key_v3_write_to(
    const otrng_global_state_s *gs, FILE *privf);

API otrng_result otrng_global_state_forging_key_write_to(
    const otrng_global_state_s *gs, FILE *f);

API otrng_result otrng_global_state_client_profile_write_to(
    const otrng_global_state_s *gs, FILE *privf);

API otrng_result otrng_global_state_expired_client_profile_write_to(
    const otrng_global_state_s *gs, FILE *privf);

API otrng_result otrng_global_state_expired_prekey_profile_write_to(
    const otrng_global_state_s *gs, FILE *privf);

API otrng_result otrng_global_state_prekey_profile_write_to(
    const otrng_global_state_s *gs, FILE *privf);

API otrng_result otrng_global_state_prekey_messages_write_to(
    const otrng_global_state_s *gs, FILE *privf);

API otrng_result otrng_global_state_instance_tags_read_from(
    otrng_global_state_s *gs, FILE *instag);

API otrng_result otrng_global_state_private_key_v3_read_from(
    otrng_global_state_s *gs, FILE *keys,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep));

API otrng_result otrng_global_state_private_key_v4_read_from(
    otrng_global_state_s *gs, FILE *privf,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep));

API otrng_result otrng_global_state_forging_key_read_from(
    otrng_global_state_s *gs, FILE *f,
    otrng_client_id_s (*read_client_id_for_key)(FILE *f));

API otrng_result otrng_global_state_client_profile_read_from(
    otrng_global_state_s *gs, FILE *profile_filep,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep));

API otrng_result otrng_global_state_expired_client_profile_read_from(
    otrng_global_state_s *gs, FILE *exp_profile_filep,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep));

API otrng_result otrng_global_state_prekey_profile_read_from(
    otrng_global_state_s *gs, FILE *profile_filep,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep));

API otrng_result otrng_global_state_expired_prekey_profile_read_from(
    otrng_global_state_s *gs, FILE *exp_profile_filep,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep));

API otrng_result otrng_global_state_prekeys_read_from(
    otrng_global_state_s *gs, FILE *prekey_filep,
    otrng_client_id_s (*read_client_id_for_prekey)(FILE *filep));

API void otrng_global_state_clean_all(otrng_global_state_s *gs);

API otrng_result otrng_global_state_fingerprints_v4_read_from(
    otrng_global_state_s *gs, FILE *fp,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep));

API otrng_result otrng_global_state_fingerprints_v3_read_from(
    otrng_global_state_s *gs, FILE *fp,
    otrng_client_id_s (*read_client_id_for_key)(FILE *filep));

API otrng_result otrng_global_state_fingerprints_v4_write_to(
    const otrng_global_state_s *gs, FILE *privf);

API otrng_result otrng_global_state_fingerprints_v3_write_to(
    const otrng_global_state_s *gs, FILE *privf);

API void otrng_global_state_do_all_fingerprints(
    const otrng_global_state_s *gs,
    void (*fn)(const otrng_client_s *, otrng_known_fingerprint_s *, void *),
    void *context);

API void otrng_global_state_do_all_fingerprints_v3(
    const otrng_global_state_s *gs,
    void (*fn)(const otrng_client_s *, otrng_known_fingerprint_v3_s *, void *),
    void *context);

/**
 * @brief This function does cleanup based on timed intervals
 *
 * The function should be called every few minutes in order to clean
 * up expired resources. If it's not called properly, forward secrecy
 * could be impacted.
 */
API void otrng_poll(otrng_global_state_s *gs);

INTERNAL void
otrng_global_state_fingerprints_v3_loaded(otrng_global_state_s *gs);

#ifdef DEBUG_API

API void otrng_global_state_debug_print(FILE *, int, otrng_global_state_s *gs);

#endif

#ifdef OTRNG_MESSAGING_PRIVATE

tstatic otrng_result otrng_global_state_add_private_key_v4(
    otrng_global_state_s *gs, const otrng_client_id_s clientop,
    const uint8_t sym[ED448_PRIVATE_BYTES]);

otrng_keypair_s *
otrng_global_state_get_private_key_v4(otrng_global_state_s *gs,
                                      const otrng_client_id_s client_id);

tstatic otrng_result otrng_global_state_add_forging_key(
    otrng_global_state_s *gs, const otrng_client_id_s clientop,
    otrng_public_key *fk);

tstatic otrng_client_s *get_client(otrng_global_state_s *gs,
                                   const otrng_client_id_s client_id);

#endif

#endif
