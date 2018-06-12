/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or (at
 *  your option) any later version.
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

#include "constants.h"
#include "dh.h"
#include "ed448.h"
#include "keys.h"
#include "list.h"
#include "shared.h"

typedef enum {
  OTRNG_INTERACTIVE = 0,
  OTRNG_NON_INTERACTIVE = 1,
} otrng_information_flow;

typedef enum {
  OTRNG_SENDING = 0,
  OTRNG_RECEIVING = 1,
} otrng_participant_action;

typedef enum {
  OTRNG_DH_RATCHET = 0,
  OTRNG_CHAIN_RATCHET = 1,
} otrng_ratchet_type;

/* the different kind of keys for the key management */
typedef uint8_t k_dh_p[DH_KEY_BYTES];
typedef uint8_t brace_key_p[BRACE_KEY_BYTES];
typedef uint8_t k_ecdh_p[ED448_POINT_BYTES];
typedef uint8_t shared_secret_p[SHARED_SECRET_BYTES];

typedef uint8_t root_key_p[ROOT_KEY_BYTES];
typedef uint8_t sending_chain_key_p[CHAIN_KEY_BYTES];
typedef uint8_t receiving_chain_key_p[CHAIN_KEY_BYTES];
typedef uint8_t m_enc_key_p[ENC_KEY_BYTES];
typedef uint8_t m_mac_key_p[MAC_KEY_BYTES];
typedef uint8_t extra_symmetric_key_p[EXTRA_SYMMETRIC_KEY_BYTES];

/* the different kind of keys needed for a chain ratchet */
typedef struct ratchet_s {
  root_key_p root_key;
  sending_chain_key_p chain_s;
  receiving_chain_key_p chain_r;
} ratchet_s, ratchet_p[1];

typedef struct skipped_keys_s {
  int i; // Counter of the ratchet
  int j; // Counter of the messages
  extra_symmetric_key_p extra_symmetric_key;
  m_enc_key_p m_enc_key;
} skipped_keys_s, skipped_keys_p[1];

typedef struct extra_symm_key_usage_s {
  int use_extra_symm;
  int use;
  const unsigned char *use_data;
  size_t use_data_len;
  const unsigned char *extra_symmetric_key;
} extra_symm_key_usage_s, extra_symm_key_usage_p[1];

/* define which half of the secure session id should be shown in bold*/
typedef enum {
  SESSION_ID_FIRST_HALF_BOLD,
  SESSION_ID_SECOND_HALF_BOLD
} session_id_half;

/* represents the different values needed for key management */
typedef struct key_manager_s {
  /* AKE context */
  ecdh_keypair_p our_ecdh;
  dh_keypair_p our_dh;

  ec_point_p their_ecdh;
  dh_public_key_p their_dh;

  // TODO: REMOVE THIS
  // or turn it into a pair and store both this and the long term keypair on
  // this key manager.
  otrng_shared_prekey_pub_p our_shared_prekey;
  otrng_shared_prekey_pub_p their_shared_prekey;

  /* Data message context */
  uint i;  // the ratchet id.
  uint j;  // the sending message id.
  uint k;  // the receiving message id.
  uint pn; // the number of messages in the previous DH ratchet.<Paste>

  ratchet_s *current;

  brace_key_p brace_key;
  shared_secret_p shared_secret;

  uint8_t ssid[SSID_BYTES];
  session_id_half ssid_half;
  extra_symmetric_key_p extra_symmetric_key;
  uint8_t tmp_key[HASH_BYTES];

  list_element_s *skipped_keys;
  list_element_s *old_mac_keys;

  extra_symm_key_usage_p extra_symm_key_usage;

  time_t last_generated;
} key_manager_s, key_manager_p[1];

/**
 * @brief Initialize the key manager.
 *
 * @param [manager]   The key manager.
 */
INTERNAL void otrng_key_manager_init(key_manager_s *manager);

/**
 * @brief Destroy the key manager.
 *
 * @param [manager]   The key manager.
 */
INTERNAL void otrng_key_manager_destroy(key_manager_s *manager);

/**
 * @brief Securely replace their ecdh and their dh keys.
 *
 * @param [their_ecdh]  The new their_ecdh key.
 * @param [their_dh]  The new their_dh key.
 * @param [manager]   The key manager.
 */
INTERNAL void otrng_key_manager_set_their_keys(ec_point_p their_ecdh,
                                               dh_public_key_p their_dh,
                                               key_manager_s *manager);

/**
 * @brief Securely replace their ecdh keys.
 *
 * @param [their_ecdh]  The new their_ecdh key.
 * @param [manager]   The key manager.
 */
INTERNAL void otrng_key_manager_set_their_ecdh(const ec_point_p their_ecdh,
                                               key_manager_s *manager);

/**
 * @brief Securely replace their dh keys.
 *
 * @param [their_ecdh]  The new their_dh key.
 * @param [manager]   The key manager.
 */
INTERNAL void otrng_key_manager_set_their_dh(const dh_public_key_p their_dh,
                                             key_manager_s *manager);

/**
 * @brief Generate the ephemeral ecdh and dh keys.
 *
 * @param [manager]   The key manager.
 */
INTERNAL otrng_err
otrng_key_manager_generate_ephemeral_keys(key_manager_s *manager);

/**
 * @brief Generate the Mixed Shared Secret.
 *        If it is part of the interactive DAKE, generate it
 *        from the shared ecdh and brace keys. If not,
 *        generate it from the tmp key.
 *
 * @param [manager]   The key manager.
 * @param [flow]      If it is part of the interactive DAKE or not.
 */
INTERNAL otrng_err otrng_key_manager_generate_shared_secret(
    key_manager_s *manager, otrng_information_flow flow);

/**
 * @brief Generate a Shared Secret from the shared prekey.
 *
 * @param [shared_secret]   The shared secret.
 * @param [shared_prekey]   The shared prekey.
 * @param [their_pub]   Their public key.
 */
INTERNAL otrng_err otrng_ecdh_shared_secret_from_prekey(
    uint8_t *shared_secret, const otrng_shared_prekey_pair_s *shared_prekey,
    const ec_point_p their_pub);

/**
 * @brief Generate a Shared Secret from the keypair.
 *
 * @param [shared_secret]   The shared secret.
 * @param [shared_prekey]   The keypair.
 * @param [their_pub]   Their public key.
 */
INTERNAL otrng_err otrng_ecdh_shared_secret_from_keypair(
    uint8_t *shared, otrng_keypair_s *keypair, const ec_point_p their_pub);

/**
 * @brief Initialize the double ratchet algorithm.
 *
 * @param [manager]       The key manager.
 * @param [participant]   If this corresponds to our or their key manager.
 */
INTERNAL otrng_err otrng_key_manager_ratcheting_init(
    key_manager_s *manager, otrng_participant participant);

/**
 * @brief Get the correct message keys.
 *
 * @param [enc_key]     The encryption key.
 * @param [mac_key]     The mac key.
 * @param [ratchet_id]  The receiving ratchet id (i).
 * @param [message_id]  The receiving message id (j).
 * @param [manager]     The key manager.
 */
INTERNAL otrng_err otrng_key_get_skipped_keys(m_enc_key_p enc_key,
                                              m_mac_key_p mac_key,
                                              int ratchet_id, int message_id,
                                              key_manager_s *manager);

/**
 * @brief Derive ratchet chain keys.
 *
 * @param [enc_key]     The encryption key.
 * @param [mac_key]     The mac key.
 * @param [max_skip]    The maximum number of enc_keys to be stored.
 * @param [message_id]  The receiving message id (j).
 * @param [manager]     The key manager.
 * @param [action]      Defines if this is the sending or receiving chain.
 */
INTERNAL otrng_err otrng_key_manager_derive_chain_keys(
    m_enc_key_p enc_key, m_mac_key_p mac_key, key_manager_s *manager,
    int max_skip, int message_id, otrng_participant_action action);

/**
 * @brief Derive the dh ratchet keys.
 *
 * @param [manager]     The key manager.
 * @param [max_skip]    The maximum number of enc_keys to be stored.
 * @param [message_id]  The receiving message id (j).
 * @param [action]      Defines if this is the sending or receiving chain.
 */
INTERNAL otrng_err otrng_key_manager_derive_dh_ratchet_keys(
    key_manager_s *manager, int max_skip, int message_id, int previous_n,
    otrng_participant_action action);

/**
 * @brief Store old mac keys to reveal later.
 *
 * @param [manager]   The key manager.
 * @param [mac_key]   The mac key to store.
 */
INTERNAL otrng_err otrng_store_old_mac_keys(key_manager_s *manager,
                                            m_mac_key_p mac_key);

INTERNAL uint8_t *otrng_reveal_mac_keys_on_tlv(key_manager_s *manager);

/**
 * @brief Derive keys from the extra symmetric key.
 *
 * @param [usage]     The usage for the KDF.
 * @param [manager]   The key manager.
 */
API uint8_t *derive_key_from_extra_symm_key(uint8_t usage,
                                            key_manager_s *manager);

#ifdef OTRNG_KEY_MANAGEMENT_PRIVATE

/**
 * @brief Calculate the brace key.
 *
 * @param [manager]   The key manager.
 */
tstatic otrng_err calculate_brace_key(key_manager_s *manager);

/**
 * @brief Derive ratchet keys.
 *
 * @param [manager]   The key manager.
 * @param [action]    Defines if this is the sending or receiving chain.
 */
tstatic otrng_err key_manager_derive_ratchet_keys(
    key_manager_s *manager, otrng_participant_action action);

/**
 * @brief Calculate the secure session id.
 *
 * @param [manager]   The key manager.
 */
tstatic void calculate_ssid(key_manager_s *manager);

/**
 * @brief Calculate the extra symmetric key.
 *
 * @param [manager]   The key manager.
 * @param [action]    Defines if this is the sending or receiving chain.
 */
tstatic void calculate_extra_key(key_manager_s *manager,
                                 otrng_participant_action action);

#endif

#endif
