/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published
 *  by the Free Software Foundation, either version 2.1 of the License, or (at
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

#include "client_callbacks.h"
#include "constants.h"
#include "dh.h"
#include "ed448.h"
#include "keys.h"
#include "list.h"
#include "shared.h"

/* the different kind of keys for the key management */
typedef uint8_t k_brace[BRACE_KEY_BYTES];
typedef uint8_t k_ecdh[ED448_POINT_BYTES];
typedef uint8_t k_shared_secret[SHARED_SECRET_BYTES];

typedef uint8_t k_root[ROOT_KEY_BYTES];
typedef uint8_t k_sending_chain[CHAIN_KEY_BYTES];
typedef uint8_t k_receiving_chain[CHAIN_KEY_BYTES];
typedef uint8_t k_msg_enc[ENC_KEY_BYTES];
typedef uint8_t k_msg_mac[MAC_KEY_BYTES];
typedef uint8_t k_extra_symmetric[EXTRA_SYMMETRIC_KEY_BYTES];

/* the different kind of keys needed for a chain ratchet */
typedef struct ratchet_s {
  k_root root_key;
  k_sending_chain chain_s;
  k_receiving_chain chain_r;
} ratchet_s;

/* the list of stored message and extra symmetric keys */
typedef struct skipped_keys_s {
  ec_point their_ecdh; /* Current their_ecdh key */
  uint32_t k;          /* Counter of the receiving messages */
  k_extra_symmetric extra_symmetric_key;
  k_msg_enc enc_key;
} skipped_keys_s;

/* a temporary structure used to hold the values of the receiving ratchet */
typedef struct receiving_ratchet_s {
  ec_scalar our_ecdh_priv;
  dh_private_key our_dh_priv;

  ec_point their_ecdh;
  dh_public_key their_dh;

  k_brace brace_key;
  k_shared_secret shared_secret;

  uint32_t i;  /* Counter of the ratchet */
  uint32_t k;  /* Counter of the receiving ratchet */
  uint32_t j;  /* Counter of the sending ratchet */
  uint32_t pn; /* the number of messages in the previous DH ratchet. */
  k_root root_key;
  k_receiving_chain chain_r;

  k_extra_symmetric extra_symmetric_key;

  list_element_s *skipped_keys;
} receiving_ratchet_s;

/* represents the different values needed for key management */
typedef struct key_manager_s {
  /* AKE context */
  ecdh_keypair_s *our_ecdh;
  dh_keypair_s *our_dh;

  ec_point their_ecdh;
  dh_public_key their_dh;

  // TODO: @refactoring REMOVE THIS
  // or turn it into a pair and store both this and the long term keypair on
  // this key manager.
  otrng_shared_prekey_pub our_shared_prekey;
  otrng_shared_prekey_pub their_shared_prekey;

  /* Data message context */
  unsigned int i;  /* the ratchet id. */
  unsigned int j;  /* the sending message id. */
  unsigned int k;  /* the receiving message id. */
  unsigned int pn; /* the number of messages in the previous DH ratchet. */

  ratchet_s *current;

  k_brace brace_key;
  k_shared_secret shared_secret;

  uint8_t ssid[SSID_BYTES];
  otrng_bool ssid_half_first;
  k_extra_symmetric extra_symmetric_key;
  uint8_t tmp_key[HASH_BYTES];

  list_element_s *skipped_keys;
  list_element_s *old_mac_keys;

  time_t last_generated;
} key_manager_s;

/*
 * @brief Creates a new key manager.
 *
 * @return A new key manager [key_manager_s].
 * */
INTERNAL key_manager_s *otrng_key_manager_new(void);

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
 * @brief Free the given key manager.
 *
 * @param [manager]   The key manager.
 */
INTERNAL void otrng_key_manager_free(key_manager_s *manager);

/**
 * @brief Securely deletes the shared prekeys used in the DAKE.
 *
 * @param [manager]   The key manager.
 */
INTERNAL void otrng_key_manager_wipe_shared_prekeys(key_manager_s *manager);

/**
 * @brief Create a temporary receiving ratchet to be used to prevent a ratchet
 * corruption.
 *
 * @param [manager]    The current key manager.
 *
 * @return [manager]   The receiving ratchet [receiving_ratchet_s].
 */

INTERNAL receiving_ratchet_s *
otrng_receiving_ratchet_new(key_manager_s *manager);

/**
 * @brief Copy a temporary receiving ratchet into the key manager.
 *
 * @param [dst]   The key manager.
 * @param [src]   The receiving ratchet.
 */
INTERNAL void otrng_receiving_ratchet_copy(key_manager_s *dst,
                                           receiving_ratchet_s *src);

/**
 * @brief Destroy a temporary receiving ratchet to be used to prevent a ratchet
 * corruption.
 *
 * @param [manager]   The receiving ratchet.
 */
INTERNAL void otrng_receiving_ratchet_destroy(receiving_ratchet_s *ratchet);

/**
 * @brief Securely replace their ecdh and their dh keys.
 *
 * @param [their_ecdh]               The new their_ecdh key.
 * @param [their_dh]                 The new their_dh key.
 * @param [tmp_receiving_ratchet]    The receiving ratchet.
 */
INTERNAL void otrng_key_manager_set_their_tmp_keys(
    ec_point their_ecdh, dh_public_key their_dh,
    receiving_ratchet_s *tmp_receiving_ratchet);

/**
 * @brief Securely replace their ecdh keys.
 *
 * @param [their_ecdh]  The new their_ecdh key.
 * @param [manager]     The key manager.
 */
INTERNAL void otrng_key_manager_set_their_ecdh(const ec_point their_ecdh,
                                               key_manager_s *manager);

/**
 * @brief Securely replace their dh keys.
 *
 * @param [their_ecdh]  The new their_dh key.
 * @param [manager]     The key manager.
 */
INTERNAL void otrng_key_manager_set_their_dh(const dh_public_key their_dh,
                                             key_manager_s *manager);

/**
 * @brief Generate the ephemeral ecdh and dh keys.
 *
 * @param [manager]   The key manager.
 */
INTERNAL otrng_result
otrng_key_manager_generate_ephemeral_keys(key_manager_s *manager);

/**
 * @brief Generate the temporary key to be used by the non-interactive DAKE.
 *
 * @param [tmp_key]      The tmp manager.
 * @param [ecdh_key]     The ecdh key.
 * @param [brace_k]      The brace key.
 * @param [tmp_ecdh_k1]  A temporary ecdh key.
 * @param [tmp_ecdh_k2]  A temporary ecdh key.
 */
INTERNAL otrng_result otrng_key_manager_calculate_tmp_key(uint8_t *tmp_key,
                                                          k_ecdh ecdh_key,
                                                          k_brace brace_key,
                                                          k_ecdh tmp_ecdh_k1,
                                                          k_ecdh tmp_ecdh_k2);

/**
 * @brief Generate the auth_mac to be used by the non-interactive DAKE.
 *
 * @param [auth_mac]      The auth mac.
 * @param [auth_mac_key]  The auth mac key.
 * @param [t]             The message to mac.
 * @param [t_len]         The length of the message to mac.
 */
INTERNAL otrng_result otrng_key_manager_calculate_auth_mac(
    uint8_t *auth_mac, const uint8_t *auth_mac_key, const uint8_t *t,
    size_t t_len);

/**
 * @brief Generate the data message authenticator.
 *
 * @param [authenticator]  The authenticator.
 * @param [mac_key]        The mac key.
 * @param [sections]       The data message sections to mac.
 */
INTERNAL otrng_result otrng_key_manager_calculate_authenticator(
    uint8_t *authenticator, const uint8_t *mac_key, const uint8_t *sections);

/**
 * @brief Generate the Mixed Shared Secret.
 *        If it is part of the interactive DAKE, generate it
 *        from the shared ecdh and brace keys. If not,
 *        generate it from the tmp key.
 *
 * @param [manager]     The key manager.
 * @param [interactive] True if interactive DAKE, false otherwise
 */
INTERNAL otrng_result otrng_key_manager_generate_shared_secret(
    key_manager_s *manager, const otrng_bool interactive);

/**
 * @brief Initialize the double ratchet algorithm.
 *
 * @param [manager]       The key manager.
 * @param [participant]   If this corresponds to our or their key manager. 'u'
 * for us, 't' for them
 */
INTERNAL otrng_result otrng_key_manager_ratcheting_init(key_manager_s *manager,
                                                        const char participant);

/**
 * @brief Get the correct message keys.
 *
 * @param [enc_key]     The encryption key.
 * @param [mac_key]     The mac key.
 * @param [ratchet_id]  The receiving ratchet id (i).
 * @param [msg_id]  The receiving message id (j).
 * @param [manager]     The key manager.
 */
INTERNAL otrng_result otrng_key_get_skipped_keys(
    k_msg_enc enc_key, k_msg_mac mac_key, ec_point msg_ecdh,
    unsigned int msg_id, key_manager_s *manager,
    receiving_ratchet_s *tmp_receiving_ratchet);

/**
 * @brief Derive ratchet chain keys.
 *
 * @param [enc_key]     The encryption key.
 * @param [mac_key]     The mac key.
 * @param [max_skip]    The maximum number of enc_keys to be stored.
 * @param [msg_id]  The receiving message id (j).
 * @param [manager]     The key manager.
 * @param [action]      's' for sending chain, 'r' for receiving
 */
INTERNAL otrng_result otrng_key_manager_derive_chain_keys(
    k_msg_enc enc_key, k_msg_mac mac_key, key_manager_s *manager,
    receiving_ratchet_s *tmp_receiving_ratchet, unsigned int max_skip,
    uint32_t msg_id, const char action, const otrng_client_callbacks_s *cb);

/**
 * @brief Derive the dh ratchet keys.
 *
 * @param [manager]     The key manager.
 * @param [max_skip]    The maximum number of enc_keys to be stored.
 * @param [msg_id]  The receiving message id (j).
 * @param [action]      's' for sending chain, 'r' for receiving
 */
INTERNAL otrng_result otrng_key_manager_derive_dh_ratchet_keys(
    key_manager_s *manager, unsigned int max_skip,
    receiving_ratchet_s *tmp_receiving_ratchet, ec_point msg_ecdh,
    uint32_t previous_n, const char action, const otrng_client_callbacks_s *cb);

/**
 * @brief Store old mac keys to reveal later.
 *
 * @param [manager]   The key manager.
 * @param [mac_key]   The mac key to store.
 */
INTERNAL otrng_result otrng_store_old_mac_keys(key_manager_s *manager,
                                               k_msg_mac mac_key);

INTERNAL uint8_t *otrng_reveal_mac_keys_on_tlv(key_manager_s *manager);

#ifdef OTRNG_KEY_MANAGEMENT_PRIVATE

/**
 * @brief Calculate the brace key.
 *
 * @param [manager]   The key manager.
 */
tstatic otrng_result calculate_brace_key(
    key_manager_s *manager, receiving_ratchet_s *tmp_receiving_ratchet,
    const char action);

/**
 * @brief Derive ratchet keys.
 *
 * @param [manager]   The key manager.
 * @param [action]    's' for sending chain, 'r' for receiving
 */
tstatic otrng_result key_manager_derive_ratchet_keys(
    key_manager_s *manager, receiving_ratchet_s *tmp_receiving_ratchet,
    const char action);

/**
 * @brief Calculate the secure session id.
 *
 * @param [manager]   The key manager.
 */
tstatic otrng_result calculate_ssid(key_manager_s *manager);

/**
 * @brief Calculate the extra symmetric key.
 *
 * @param [manager]   The key manager.
 * @param [action]    's' for sending chain, 'r' for receiving
 */
tstatic otrng_result calculate_extra_key(
    key_manager_s *manager, receiving_ratchet_s *tmp_receiving_ratchet,
    const char action);

#endif

#endif
