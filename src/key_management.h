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

// TODO: extract constant
typedef uint8_t k_dh_p[384];
typedef uint8_t brace_key_p[BRACE_KEY_BYTES];
typedef uint8_t k_ecdh_p[ED448_POINT_BYTES];
typedef uint8_t shared_secret_p[SHARED_SECRET_BYTES];

typedef uint8_t root_key_p[ROOT_KEY_BYTES];
typedef uint8_t sending_chain_key_p[CHAIN_KEY_BYTES];
typedef uint8_t receiving_chain_key_p[CHAIN_KEY_BYTES];
typedef uint8_t m_enc_key_p[32];
typedef uint8_t m_mac_key_p[MAC_KEY_BYTES];

typedef struct ratchet_s {
  root_key_p root_key;
  sending_chain_key_p chain_s;
  receiving_chain_key_p chain_r;
} ratchet_s, ratchet_p[1];

typedef enum {
  SESSION_ID_FIRST_HALF_BOLD,
  SESSION_ID_SECOND_HALF_BOLD
} session_id_half;

typedef struct key_manager_s {
  /* AKE context */
  ecdh_keypair_p our_ecdh;
  dh_keypair_p our_dh;

  ec_point_p their_ecdh;
  dh_public_key_p their_dh;

  otrng_shared_prekey_pub_p our_shared_prekey;
  otrng_shared_prekey_pub_p their_shared_prekey;

  /* Data message context */
  int i, j, k, pn;
  ratchet_s *current;

  brace_key_p brace_key;
  shared_secret_p shared_secret;

  uint8_t ssid[8];
  session_id_half ssid_half;
  uint8_t extra_key[HASH_BYTES];
  uint8_t tmp_key[HASH_BYTES];

  list_element_s *old_mac_keys;

  time_t lastgenerated;
} key_manager_s, key_manager_p[1];

INTERNAL void otrng_key_manager_init(key_manager_s *manager);

INTERNAL void otrng_key_manager_destroy(key_manager_s *manager);

INTERNAL void otrng_key_manager_set_their_ecdh(ec_point_p their,
                                               key_manager_s *manager);

INTERNAL void otrng_key_manager_set_their_dh(dh_public_key_p their,
                                             key_manager_s *manager);

INTERNAL otrng_err
otrng_key_manager_generate_ephemeral_keys(key_manager_s *manager);

INTERNAL otrng_err otrng_key_manager_generate_shared_secret(
    key_manager_s *manager, bool interactive);

INTERNAL otrng_err otrng_key_manager_ratcheting_init(key_manager_s *manager,
                                                     bool ours);

INTERNAL void otrng_key_manager_set_their_keys(ec_point_p their_ecdh,
                                               dh_public_key_p their_dh,
                                               key_manager_s *manager);

INTERNAL void
otrng_ecdh_shared_secret_from_prekey(uint8_t *shared,
                                     otrng_shared_prekey_pair_s *shared_prekey,
                                     const ec_point_p their_pub);

INTERNAL void otrng_ecdh_shared_secret_from_keypair(uint8_t *shared,
                                                    otrng_keypair_s *keypair,
                                                    const ec_point_p their_pub);

INTERNAL otrng_err otrng_key_manager_derive_receiving_keys(
    m_enc_key_p enc_key, m_mac_key_p mac_key, key_manager_s *manager);

INTERNAL otrng_err
otrng_key_manager_derive_dh_ratchet_keys(key_manager_s *manager, bool sending);

INTERNAL void otrng_key_manager_derive_sending_keys(m_enc_key_p enc_key,
                                                    m_mac_key_p mac_key,
                                                    key_manager_s *manager);
INTERNAL uint8_t *
otrng_key_manager_old_mac_keys_serialize(list_element_s *old_mac_keys);

#ifdef OTRNG_KEY_MANAGEMENT_PRIVATE
tstatic otrng_err key_manager_new_ratchet(key_manager_s *manager, bool sending);

// TODO: are we only exporting this for the test?
tstatic void calculate_ssid(key_manager_s *manager);

tstatic otrng_err calculate_brace_key(key_manager_s *manager);
#endif

#endif
