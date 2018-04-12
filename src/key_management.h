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

#ifndef OTRNG_KEY_MANAGEMENT_H
#define OTRNG_KEY_MANAGEMENT_H

#include <stdbool.h>

#include "constants.h"
#include "dh.h"
#include "ed448.h"
#include "keys.h"
#include "list.h"
#include "shared.h"

typedef uint8_t k_dh_t[384];
typedef uint8_t brace_key_t[BRACE_KEY_BYTES];
typedef uint8_t k_ecdh_t[ED448_POINT_BYTES];
typedef uint8_t shared_secret_t[SHARED_SECRET_BYTES];

typedef uint8_t root_key_t[ROOT_KEY_BYTES];
typedef uint8_t chain_key_t[CHAIN_KEY_BYTES];
typedef uint8_t m_enc_key_t[32];
typedef uint8_t m_mac_key_t[MAC_KEY_BYTES];

typedef struct _chain_link {
  int id;
  chain_key_t key;
  struct _chain_link *next;
} chain_link_t;

typedef struct {
  root_key_t root_key;
  chain_link_t chain_a[1];
  chain_link_t chain_b[1];
} ratchet_t;

typedef enum {
  SESSION_ID_FIRST_HALF_BOLD,
  SESSION_ID_SECOND_HALF_BOLD
} session_id_half;

typedef struct {
  /* AKE context */
  ecdh_keypair_t our_ecdh[1];
  dh_keypair_t our_dh;

  ec_point_t their_ecdh;
  dh_public_key_t their_dh;

  otrng_shared_prekey_pub_t our_shared_prekey;
  otrng_shared_prekey_pub_t their_shared_prekey;

  /* Data message context */
  int i, j; // TODO: We need to add k (maybe), but why dont we need to add a
            // receiving_ratchet_id
  ratchet_t *current;

  brace_key_t brace_key;

  uint8_t ssid[8];
  session_id_half ssid_half;
  uint8_t extra_key[HASH_BYTES];
  uint8_t tmp_key[HASH_BYTES];

  list_element_t *old_mac_keys;

  time_t lastgenerated;
} key_manager_t;

// clang-format off
typedef struct { const chain_link_t *sending, *receiving; } message_chain_t;

// clang-format on

INTERNAL void otrng_key_manager_init(key_manager_t *manager);

INTERNAL void otrng_key_manager_destroy(key_manager_t *manager);

INTERNAL void otrng_key_manager_set_their_ecdh(ec_point_t their,
                                               key_manager_t *manager);

INTERNAL void otrng_key_manager_set_their_dh(dh_public_key_t their,
                                             key_manager_t *manager);

INTERNAL otrng_err_t
otrng_key_manager_generate_ephemeral_keys(key_manager_t *manager);

INTERNAL otrng_err_t otrng_key_manager_ratcheting_init(int j, bool interactive,
                                                       key_manager_t *manager);

INTERNAL void otrng_key_manager_set_their_keys(ec_point_t their_ecdh,
                                               dh_public_key_t their_dh,
                                               key_manager_t *manager);

INTERNAL void otrng_key_manager_prepare_to_ratchet(key_manager_t *manager);

INTERNAL otrng_err_t
otrng_key_manager_ensure_on_ratchet(key_manager_t *manager);

INTERNAL void
otrng_ecdh_shared_secret_from_prekey(uint8_t *shared,
                                     otrng_shared_prekey_pair_t *shared_prekey,
                                     const ec_point_t their_pub);

INTERNAL void otrng_ecdh_shared_secret_from_keypair(uint8_t *shared,
                                                    otrng_keypair_t *keypair,
                                                    const ec_point_t their_pub);

INTERNAL otrng_err_t otrng_key_manager_retrieve_receiving_message_keys(
    m_enc_key_t enc_key, m_mac_key_t mac_key, int message_id,
    key_manager_t *manager);

INTERNAL otrng_err_t
otrng_key_manager_prepare_next_chain_key(key_manager_t *manager);

INTERNAL otrng_err_t otrng_key_manager_retrieve_sending_message_keys(
    m_enc_key_t enc_key, m_mac_key_t mac_key, key_manager_t *manager);
INTERNAL uint8_t *
otrng_key_manager_old_mac_keys_serialize(list_element_t *old_mac_keys);

#ifdef OTRNG_KEY_MANAGEMENT_PRIVATE
tstatic otrng_err_t key_manager_new_ratchet(key_manager_t *manager,
                                            const shared_secret_t shared);

tstatic int key_manager_get_sending_chain_key(chain_key_t sending,
                                              const key_manager_t *manager);

tstatic otrng_err_t key_manager_get_receiving_chain_key(
    chain_key_t receiving, int message_id, const key_manager_t *manager);

tstatic void calculate_shared_secret(shared_secret_t dst, const k_ecdh_t k_ecdh,
                                     const chain_key_t chain_key);

tstatic void calculate_ssid(key_manager_t *manager,
                            const shared_secret_t shared_secret);

#endif

#endif
