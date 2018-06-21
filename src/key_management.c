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

#include <sodium.h>
#include <string.h>
#include <time.h>

#define OTRNG_KEY_MANAGEMENT_PRIVATE

#include "key_management.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"

#include "debug.h"

tstatic ratchet_s *ratchet_new() {
  ratchet_s *ratchet = malloc(sizeof(ratchet_s));
  if (!ratchet) {
    return NULL;
  }

  memset(ratchet->root_key, 0, sizeof(ratchet->root_key));
  memset(ratchet->chain_s, 0, sizeof(ratchet->chain_s));
  memset(ratchet->chain_r, 0, sizeof(ratchet->chain_r));

  return ratchet;
}

tstatic void ratchet_free(ratchet_s *ratchet) {
  if (!ratchet) {
    return;
  }

  sodium_memzero(ratchet->root_key, sizeof(root_key_p));
  sodium_memzero(ratchet->chain_s, sizeof(sending_chain_key_p));
  sodium_memzero(ratchet->chain_r, sizeof(receiving_chain_key_p));

  free(ratchet);
  ratchet = NULL;
}

INTERNAL void
otrng_key_manager_init(key_manager_s *manager) // make like ratchet_new?
{
  otrng_ec_bzero(manager->our_ecdh->pub, ED448_POINT_BYTES);
  manager->our_dh->pub = NULL;
  manager->our_dh->priv = NULL;

  otrng_ec_bzero(manager->their_ecdh, ED448_POINT_BYTES);
  manager->their_dh = NULL;

  otrng_ec_bzero(manager->their_shared_prekey, ED448_POINT_BYTES);
  otrng_ec_bzero(manager->our_shared_prekey, ED448_POINT_BYTES);

  manager->i = 0;
  manager->j = 0;
  manager->k = 0;
  manager->pn = 0;
  manager->current = ratchet_new();

  memset(manager->brace_key, 0, sizeof(manager->brace_key));
  memset(manager->shared_secret, 0, sizeof(manager->shared_secret));

  memset(manager->ssid, 0, sizeof(manager->ssid));
  manager->ssid_half = 0;
  memset(manager->extra_symmetric_key, 0, sizeof(manager->extra_symmetric_key));
  memset(manager->tmp_key, 0, sizeof(manager->tmp_key));

  manager->skipped_keys = NULL;
  manager->old_mac_keys = NULL;
}

INTERNAL void otrng_key_manager_destroy(key_manager_s *manager) {
  otrng_ecdh_keypair_destroy(manager->our_ecdh);
  otrng_dh_keypair_destroy(manager->our_dh);

  otrng_ec_point_destroy(manager->their_ecdh);

  gcry_mpi_release(manager->their_dh);
  manager->their_dh = NULL;

  manager->i = 0;
  manager->j = 0;
  manager->k = 0;
  manager->pn = 0;

  ratchet_free(manager->current);
  manager->current = NULL;

  // TODO: @freeing once dake is finished should be wiped out
  sodium_memzero(manager->their_shared_prekey, ED448_POINT_BYTES);
  sodium_memzero(manager->our_shared_prekey, ED448_POINT_BYTES);

  sodium_memzero(manager->brace_key, sizeof(manager->brace_key));
  sodium_memzero(manager->shared_secret, sizeof(manager->shared_secret));
  sodium_memzero(manager->ssid, sizeof(manager->ssid));
  manager->ssid_half = 0;
  sodium_memzero(manager->extra_symmetric_key,
                 sizeof(manager->extra_symmetric_key));
  // TODO: @freeing once dake is finished should be wiped out
  sodium_memzero(manager->tmp_key, sizeof(manager->tmp_key));

  list_element_s *el;
  for (el = manager->skipped_keys; el; el = el->next) {
    free((skipped_keys_s *)el->data);
    el->data = NULL;
  }

  otrng_list_free_full(manager->skipped_keys);
  manager->skipped_keys = NULL;

  list_element_s *el_2;
  for (el_2 = manager->old_mac_keys; el_2; el_2 = el_2->next) {
    free((uint8_t *)el_2->data);
    el_2->data = NULL;
  }

  otrng_list_free_full(manager->old_mac_keys);
  manager->old_mac_keys = NULL;
}

INTERNAL void otrng_key_manager_set_their_keys(ec_point_p their_ecdh,
                                               dh_public_key_p their_dh,
                                               key_manager_s *manager) {
  otrng_ec_point_destroy(manager->their_ecdh);
  otrng_ec_point_copy(manager->their_ecdh, their_ecdh);
  otrng_dh_mpi_release(manager->their_dh);
  manager->their_dh = otrng_dh_mpi_copy(their_dh);
}

INTERNAL void otrng_key_manager_set_their_ecdh(const ec_point_p their_ecdh,
                                               key_manager_s *manager) {
  otrng_ec_point_copy(manager->their_ecdh, their_ecdh);
}

INTERNAL void otrng_key_manager_set_their_dh(const dh_public_key_p their_dh,
                                             key_manager_s *manager) {
  otrng_dh_mpi_release(manager->their_dh);
  manager->their_dh = otrng_dh_mpi_copy(their_dh);
}

INTERNAL otrng_err
otrng_key_manager_generate_ephemeral_keys(key_manager_s *manager) {
  time_t now;
  uint8_t sym[ED448_PRIVATE_BYTES];
  memset(sym, 0, sizeof(sym));
  random_bytes(sym, ED448_PRIVATE_BYTES);

  now = time(NULL);
  otrng_ecdh_keypair_destroy(manager->our_ecdh);
  otrng_ecdh_keypair_generate(manager->our_ecdh, sym);

  manager->last_generated = now;

  if (manager->i % 3 == 0) {
    otrng_dh_keypair_destroy(manager->our_dh);

    if (!otrng_dh_keypair_generate(manager->our_dh)) {
      return ERROR;
    }
  }

  return SUCCESS;
}

// Generate the ephemeral keys just as the DAKE is finished
tstatic otrng_err generate_first_ephemeral_keys(key_manager_s *manager,
                                                otrng_participant participant) {
  uint8_t random_buff[ED448_PRIVATE_BYTES];
  uint8_t usage_ECDH_first_ephemeral = 0x12;

  if (participant == OTRNG_US) {
    shake_256_kdf1(random_buff, sizeof random_buff, usage_ECDH_first_ephemeral,
                   manager->shared_secret, sizeof(shared_secret_p));

    otrng_ec_point_destroy(manager->our_ecdh->pub);
    otrng_ecdh_keypair_generate(manager->our_ecdh, random_buff);

    otrng_dh_keypair_destroy(manager->our_dh);
    if (!otrng_dh_keypair_generate_from_shared_secret(
            manager->shared_secret, manager->our_dh, participant)) {
      return ERROR;
    }

  } else if (participant == OTRNG_THEM) {
    shake_256_kdf1(random_buff, sizeof random_buff, usage_ECDH_first_ephemeral,
                   manager->shared_secret, sizeof(shared_secret_p));

    otrng_ec_point_destroy(manager->their_ecdh);
    otrng_ecdh_keypair_generate_their(manager->their_ecdh, random_buff);

    gcry_mpi_release(manager->their_dh);
    manager->their_dh = NULL;
    dh_keypair_p tmp_their_dh;

    if (!otrng_dh_keypair_generate_from_shared_secret(
            manager->shared_secret, tmp_their_dh, participant)) {
      return ERROR;
    }

    manager->their_dh = tmp_their_dh->pub;
  }
  return SUCCESS;
}

tstatic otrng_err calculate_brace_key(key_manager_s *manager) {
  k_dh_p k_dh;
  uint8_t usage_third_brace_key = 0x02;
  uint8_t usage_brace_key = 0x03;

  if (manager->i % 3 == 0) {
    if (!otrng_dh_shared_secret(k_dh, sizeof(k_dh_p), manager->our_dh->priv,
                                manager->their_dh)) {
      return ERROR;
    }

    // Although k_dh has variable length (bc it is mod p), it is considered to
    // have 384 bytes because otrng_dh_shared_secret adds leading zeroes to the
    // serialized secret. Note that DH(a, B) (in the spec) does not mandate
    // doing so.
    // Also note that OTRv3 serializes DH values in MPI (no leading zeroes).
    shake_256_kdf1(manager->brace_key, BRACE_KEY_BYTES, usage_third_brace_key,
                   k_dh, sizeof(k_dh_p));

    sodium_memzero(k_dh, sizeof(k_dh_p));
  } else {
    shake_256_kdf1(manager->brace_key, BRACE_KEY_BYTES, usage_brace_key,
                   manager->brace_key, sizeof(brace_key_p));
  }

  sodium_memzero(k_dh, sizeof(k_dh_p));

  return SUCCESS;
}

static uint8_t usage_shared_secret = 0x04;

tstatic void calculate_shared_secret(key_manager_s *manager, k_ecdh_p k_ecdh) {
  goldilocks_shake256_ctx_p hd;

  hash_init_with_usage(hd, usage_shared_secret);
  hash_update(hd, k_ecdh, sizeof(k_ecdh_p));
  hash_update(hd, manager->brace_key, sizeof(brace_key_p));
  hash_final(hd, manager->shared_secret, sizeof(shared_secret_p));
  hash_destroy(hd);

  sodium_memzero(k_ecdh, sizeof(k_ecdh_p));
  sodium_memzero(manager->brace_key, sizeof(brace_key_p));
}

INTERNAL otrng_err otrng_key_manager_generate_shared_secret(
    key_manager_s *manager, otrng_information_flow flow) {

  if (flow == OTRNG_INTERACTIVE) {
    k_ecdh_p k_ecdh;

    otrng_ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);
    otrng_ec_bzero(manager->our_ecdh->priv, sizeof(ec_scalar_p));

    if (!otrng_ecdh_valid_secret(k_ecdh)) {
      return ERROR;
    }

    if (!calculate_brace_key(manager)) {
      return ERROR;
    }
    otrng_dh_priv_key_destroy(manager->our_dh);

    calculate_shared_secret(manager, k_ecdh);

  } else if (flow == OTRNG_NON_INTERACTIVE) {
    shake_256_kdf1(manager->shared_secret, sizeof(shared_secret_p),
                   usage_shared_secret, manager->tmp_key,
                   sizeof(manager->tmp_key));

    sodium_memzero(manager->brace_key, sizeof(brace_key_p));
  }

  calculate_ssid(manager);

#ifdef DEBUG
  printf("\n");
  printf("THE SHARED SECRET\n");
  otrng_memdump(manager->shared_secret, sizeof(manager->shared_secret));
  printf("THE SSID\n");
  otrng_memdump(manager->ssid, sizeof(manager->ssid));
#endif

  if (gcry_mpi_cmp(manager->our_dh->pub, manager->their_dh) > 0) {
    manager->ssid_half = SESSION_ID_SECOND_HALF_BOLD;
  } else {
    manager->ssid_half = SESSION_ID_FIRST_HALF_BOLD;
  }

#ifdef DEBUG
  printf("\n");
  printf("THE SECURE SESSION ID\n");
  printf("ssid: \n");

  if (manager->ssid_half == SESSION_ID_FIRST_HALF_BOLD) {
    printf("the first 4 bytes = ");
    printf("0x");
    for (unsigned int i = 0; i < 4; i++) {
      printf("%x", manager->ssid[i]);
    }
  } else {
    printf("the last 4 bytes = ");
    printf("0x");
    for (unsigned int i = 4; i < 8; i++) {
      printf("%x", manager->ssid[i]);
    }
    printf("\n");
  }
#endif

  return SUCCESS;
}

INTERNAL otrng_err otrng_ecdh_shared_secret_from_prekey(
    uint8_t *shared_secret, const otrng_shared_prekey_pair_s *shared_prekey,
    const ec_point_p their_pub) {
  goldilocks_448_point_p p;
  goldilocks_448_point_scalarmul(p, their_pub, shared_prekey->priv);

  if (!otrng_ec_point_valid(p)) {
    return ERROR;
  }

  otrng_serialize_ec_point(shared_secret, p);

  if (!otrng_ecdh_valid_secret(shared_secret)) {
    return ERROR;
  }

  return SUCCESS;
}

INTERNAL otrng_err otrng_ecdh_shared_secret_from_keypair(
    uint8_t *shared_secret, otrng_keypair_s *keypair,
    const ec_point_p their_pub) {
  goldilocks_448_point_p p;
  goldilocks_448_point_scalarmul(p, their_pub, keypair->priv);

  if (!otrng_ec_point_valid(p)) {
    return ERROR;
  }

  otrng_serialize_ec_point(shared_secret, p);

  if (!otrng_ecdh_valid_secret(shared_secret)) {
    return ERROR;
  }

  return SUCCESS;
}

tstatic void calculate_ssid(key_manager_s *manager) {
  uint8_t usage_SSID = 0x05;
  shake_256_kdf1(manager->ssid, sizeof(manager->ssid), usage_SSID,
                 manager->shared_secret, sizeof(shared_secret_p));
}

INTERNAL otrng_err otrng_key_manager_ratcheting_init(
    key_manager_s *manager, otrng_participant participant) {
  if (!generate_first_ephemeral_keys(manager, participant)) {
    return ERROR;
  }

  manager->i = 0;
  manager->j = 0;
  manager->k = 0;
  manager->pn = 0;

  memcpy(manager->current->root_key, manager->shared_secret, 64);
  sodium_memzero(manager->shared_secret, 64);

  return SUCCESS;
}

tstatic otrng_err enter_new_ratchet(key_manager_s *manager,
                                    otrng_participant_action action) {
  k_ecdh_p k_ecdh;

  // K_ecdh = ECDH(our_ecdh.secret, their_ecdh)
  otrng_ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);

  // if i % 3 == 0 : brace_key = KDF_1(usage_third_brace_key || k_dh, 32)
  // else brace_key = KDF_1(usage_brace_key || brace_key, 32)
  if (!calculate_brace_key(manager)) {
    return ERROR;
  }

  // K = KDF_1(usage_shared_secret || K_ecdh || brace_key, 64)
  calculate_shared_secret(manager, k_ecdh);

#ifdef DEBUG
  printf("\n");
  printf("ENTERING NEW RATCHET\n");
  printf("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_p));
  printf("brace_key = ");
  otrng_memdump(manager->brace_key, sizeof(brace_key_p));
  printf("THE SHARED SECRET\n");
  otrng_memdump(manager->shared_secret, sizeof(manager->shared_secret));
#endif

  key_manager_derive_ratchet_keys(manager, action);

  sodium_memzero(manager->shared_secret, SHARED_SECRET_BYTES);
  return SUCCESS;
}

tstatic otrng_err rotate_keys(key_manager_s *manager,
                              otrng_participant_action action) {

  if (action == OTRNG_SENDING) {
    // our_ecdh = generateECDH()
    // if i % 3 == 0, our_dh = generateDH()
    if (!otrng_key_manager_generate_ephemeral_keys(manager)) {
      return ERROR;
    }

    manager->last_generated = time(NULL);
  }

  if (!enter_new_ratchet(manager, action)) {
    return ERROR;
  }

  if (action == OTRNG_RECEIVING) {
    otrng_ec_scalar_destroy(manager->our_ecdh->priv);
    if (manager->i % 3 == 0) {
      otrng_dh_priv_key_destroy(manager->our_dh);
    }

    manager->pn = manager->j;
    manager->j = 0;
    manager->k = 0;
  }

  manager->i++;

  return SUCCESS;
}

tstatic void key_manager_derive_ratchet_keys(key_manager_s *manager,
                                             otrng_participant_action action) {
  // root_key[i], chain_key_s[i][j] = derive_ratchet_keys(sending,
  // root_key[i-1], K) root_key[i] = KDF_1(usage_root_key || root_key[i-1] || K,
  // 64)

  uint8_t usage_root_key = 0x14;
  uint8_t usage_chain_key = 0x15;

  goldilocks_shake256_ctx_p hd;
  hash_init_with_usage(hd, usage_root_key);
  hash_update(hd, manager->current->root_key, sizeof(root_key_p));
  hash_update(hd, manager->shared_secret, sizeof(shared_secret_p));
  hash_final(hd, manager->current->root_key, sizeof(root_key_p));
  hash_destroy(hd);

  hash_init_with_usage(hd, usage_chain_key);
  hash_update(hd, manager->current->root_key, sizeof(root_key_p));
  hash_update(hd, manager->shared_secret, sizeof(shared_secret_p));

  // chain_key_purpose[i][j] = KDF_1(usage_chain_key || root_key[i-1] || K, 64)
  if (action == OTRNG_SENDING) {
    hash_final(hd, manager->current->chain_s, sizeof(sending_chain_key_p));
  } else if (action == OTRNG_RECEIVING) {
    hash_final(hd, manager->current->chain_r, sizeof(receiving_chain_key_p));
  }

  hash_destroy(hd);

#ifdef DEBUG
  printf("\n");
  printf("ROOT KEY = ");
  otrng_memdump(manager->current->root_key, sizeof(manager->current->root_key));
  printf("CHAIN_S = ");
  otrng_memdump(ratchet->chain_s, sizeof(ratchet->chain_s));
  printf("CHAIN_R = ");
  otrng_memdump(ratchet->chain_r, sizeof(ratchet->chain_r));
#endif
}

static uint8_t usage_next_chain_key = 0x16;
static uint8_t usage_message_key = 0x17;
static uint8_t usage_mac_key = 0x18;
static uint8_t usage_extra_symm_key = 0x20;

tstatic void derive_next_chain_key(key_manager_s *manager,
                                   otrng_participant_action action) {
  // chain_key_s[i-1][j+1] = KDF_1(usage_next_chain_key || chain_key_s[i-1][j],
  // 64)
  if (action == OTRNG_SENDING) {
    shake_256_kdf1(manager->current->chain_s, sizeof(sending_chain_key_p),
                   usage_next_chain_key, manager->current->chain_s,
                   sizeof(sending_chain_key_p));

  } else if (action == OTRNG_RECEIVING) {

    shake_256_kdf1(manager->current->chain_r, sizeof(receiving_chain_key_p),
                   usage_next_chain_key, manager->current->chain_r,
                   sizeof(receiving_chain_key_p));
  }
}

tstatic void derive_encryption_and_mac_keys(m_enc_key_p enc_key,
                                            m_mac_key_p mac_key,
                                            key_manager_s *manager,
                                            otrng_participant_action action) {
  // MKenc, MKmac = derive_enc_mac_keys(chain_key_s[i-1][j])
  // MKenc = KDF_1(usage_message_key || chain_key, 32)
  // MKmac = KDF_1(usage_mac_key || MKenc, 64)

  if (action == OTRNG_SENDING) {
    shake_256_kdf1(enc_key, sizeof(m_enc_key_p), usage_message_key,
                   manager->current->chain_s, sizeof(sending_chain_key_p));

  } else if (action == OTRNG_RECEIVING) {
    shake_256_kdf1(enc_key, sizeof(m_enc_key_p), usage_message_key,
                   manager->current->chain_r, sizeof(receiving_chain_key_p));
  }
  shake_256_kdf1(mac_key, sizeof(m_mac_key_p), usage_mac_key, enc_key,
                 sizeof(m_enc_key_p));
}

tstatic void calculate_extra_key(key_manager_s *manager,
                                 otrng_participant_action action) {
  goldilocks_shake256_ctx_p hd;
  uint8_t extra_key_buff[EXTRA_SYMMETRIC_KEY_BYTES];
  uint8_t magic[1] = {0xFF};

  hash_init_with_usage(hd, usage_extra_symm_key);
  hash_update(hd, magic, 1);

  // extra_symm_key = KDF_1(usage_extra_symm_key || 0xFF || chain_key_s[i-1][j],
  // 32)
  if (action == OTRNG_SENDING) {
    hash_update(hd, manager->current->chain_s, sizeof(sending_chain_key_p));
  } else if (action == OTRNG_SENDING) {
    hash_update(hd, manager->current->chain_r, sizeof(receiving_chain_key_p));
  }
  hash_final(hd, extra_key_buff, EXTRA_SYMMETRIC_KEY_BYTES);
  hash_destroy(hd);

  memcpy(manager->extra_symmetric_key, extra_key_buff,
         sizeof(manager->extra_symmetric_key));

#ifdef DEBUG
  printf("\n");
  printf("EXTRA KEY = ");
  otrng_memdump(manager->extra_symmetric_key,
                sizeof(manager->extra_symmetric_key));
#endif
}

tstatic void delete_stored_enc_keys(key_manager_s *manager) {
  list_element_s *el;
  for (el = manager->skipped_keys; el; el = el->next) {
    free((skipped_keys_s *)el->data);
    el->data = NULL;
  }

  otrng_list_free_full(manager->skipped_keys);
  manager->skipped_keys = NULL;
}

tstatic otrng_err store_enc_keys(m_enc_key_p enc_key, key_manager_s *manager,
                                 int max_skip, int until,
                                 otrng_ratchet_type type, otrng_notif notif) {
  if (manager->i ==
      100) { // TODO: @client should we make this optional to the client?
    delete_stored_enc_keys(manager);
  }

  if ((manager->k + max_skip) < until) {
    notif = NOTIF_MSG_STORAGE_FULL;
    return SUCCESS;
  }

  uint8_t zero_buff[CHAIN_KEY_BYTES] = {};
  if (!(memcmp(manager->current->chain_r, zero_buff,
               sizeof(manager->current->chain_r)) == 0)) {

    while (manager->k < until) {
      shake_256_kdf1(enc_key, sizeof(m_enc_key_p), usage_message_key,
                     manager->current->chain_r, sizeof(receiving_chain_key_p));

      goldilocks_shake256_ctx_p hd;
      uint8_t extra_key[EXTRA_SYMMETRIC_KEY_BYTES];
      uint8_t magic[1] = {0xFF};

      hash_init_with_usage(hd, usage_extra_symm_key);
      hash_update(hd, magic, 1);

      hash_update(hd, manager->current->chain_r, sizeof(receiving_chain_key_p));
      hash_final(hd, extra_key, EXTRA_SYMMETRIC_KEY_BYTES);
      hash_destroy(hd);

      shake_256_kdf1(manager->current->chain_r, sizeof(receiving_chain_key_p),
                     usage_next_chain_key, manager->current->chain_r,
                     sizeof(receiving_chain_key_p));

      skipped_keys_s *skipped_m_enc_key = malloc(sizeof(skipped_keys_s));
      if (!skipped_m_enc_key) {
        return ERROR;
      }

      if (type == OTRNG_DH_RATCHET) {
        skipped_m_enc_key->i =
            manager->i - 1; // ratchet_id - 1 for the dh ratchet
      } else if (type == OTRNG_CHAIN_RATCHET) {
        skipped_m_enc_key->i = manager->i;
      }

      skipped_m_enc_key->j = manager->k;

      memcpy(skipped_m_enc_key->extra_symmetric_key, extra_key,
             EXTRA_SYMMETRIC_KEY_BYTES);
      memcpy(skipped_m_enc_key->m_enc_key, enc_key, ENC_KEY_BYTES);

      manager->skipped_keys =
          otrng_list_add(skipped_m_enc_key, manager->skipped_keys);

      sodium_memzero(enc_key, sizeof(m_enc_key_p));
      manager->k++;
    }
  }

  return SUCCESS;
}

/* MKenc, extra_symm_key = skipped_MKenc[ratchet_id, message_id]
   MKmac = KDF_1(usage_mac_key || MKenc, 64).
*/
INTERNAL otrng_err otrng_key_get_skipped_keys(m_enc_key_p enc_key,
                                              m_mac_key_p mac_key,
                                              int ratchet_id, int message_id,
                                              key_manager_s *manager) {
  list_element_s *current = manager->skipped_keys;
  while (current) {
    skipped_keys_s *skipped_keys = current->data;

    if (skipped_keys->i == ratchet_id && skipped_keys->j == message_id) {
      memcpy(enc_key, skipped_keys->m_enc_key, sizeof(m_enc_key_p));
      shake_256_kdf1(mac_key, MAC_KEY_BYTES, usage_mac_key, enc_key,
                     ENC_KEY_BYTES);

      memcpy(manager->extra_symmetric_key, skipped_keys->extra_symmetric_key,
             sizeof(extra_symmetric_key_p));

      manager->skipped_keys =
          otrng_list_remove_element(current, manager->skipped_keys);
      otrng_list_free_full(current);

      return SUCCESS;
    }

    current = current->next;
  }

  // This is not an actual error, it is just that the key we need was not
  // skipped
  return ERROR;
}

INTERNAL otrng_err otrng_key_manager_derive_chain_keys(
    m_enc_key_p enc_key, m_mac_key_p mac_key, key_manager_s *manager,
    int max_skip, int message_id, otrng_participant_action action,
    otrng_notif notif) {

  if (action == OTRNG_RECEIVING) {
    if (!store_enc_keys(enc_key, manager, max_skip, message_id,
                        OTRNG_CHAIN_RATCHET, notif)) {
      return ERROR;
    }
  }

  derive_encryption_and_mac_keys(enc_key, mac_key, manager, action);
  calculate_extra_key(manager, action);
  derive_next_chain_key(manager, action);

#ifdef DEBUG
  printf("\n");
  printf("GOT SENDING KEYS:\n");
  printf("enc_key = ");
  otrng_memdump(enc_key, sizeof(m_enc_key_p));
  printf("mac_key = ");
  otrng_memdump(mac_key, sizeof(m_mac_key_p));
#endif

  return SUCCESS;
}

INTERNAL otrng_err otrng_key_manager_derive_dh_ratchet_keys(
    key_manager_s *manager, int max_skip, int message_id, int previous_n,
    otrng_participant_action action, otrng_notif notif) {
  /* Derive new ECDH and DH keys */
  m_enc_key_p enc_key;

  if (message_id == 0) {
    if (action == OTRNG_RECEIVING) {
      /* Store any message keys from the previous DH Ratchet */
      if (!store_enc_keys(enc_key, manager, max_skip, previous_n,
                          OTRNG_DH_RATCHET, notif)) {
        return ERROR;
      }
    }
    return rotate_keys(manager, action);
  }

  return SUCCESS;
}

INTERNAL otrng_err otrng_store_old_mac_keys(key_manager_s *manager,
                                            m_mac_key_p mac_key) {
  uint8_t *to_store_mac = malloc(MAC_KEY_BYTES);
  if (!to_store_mac) {
    return ERROR;
  }

  memcpy(to_store_mac, mac_key, sizeof(m_mac_key_p));
  manager->old_mac_keys = otrng_list_add(to_store_mac, manager->old_mac_keys);

  return SUCCESS;
}

INTERNAL uint8_t *otrng_reveal_mac_keys_on_tlv(key_manager_s *manager) {
  size_t num_stored_keys = otrng_list_len(manager->skipped_keys);
  size_t serlen = num_stored_keys * MAC_KEY_BYTES;
  uint8_t *ser_mac_keys;

  if (serlen != 0) {
    ser_mac_keys = malloc(serlen);
    if (!ser_mac_keys) {
      return NULL;
    }

    m_mac_key_p mac_key;
    m_enc_key_p enc_key;
    memset(enc_key, 0, sizeof enc_key);
    memset(mac_key, 0, sizeof mac_key);

    for (int i = 0; i < num_stored_keys; i++) {
      list_element_s *last = otrng_list_get_last(manager->skipped_keys);
      skipped_keys_s *skipped_keys = last->data;
      memcpy(enc_key, skipped_keys->m_enc_key, sizeof(m_enc_key_p));
      shake_256_kdf1(mac_key, sizeof(m_mac_key_p), usage_mac_key, enc_key,
                     sizeof(m_enc_key_p));
      memcpy(ser_mac_keys + i * MAC_KEY_BYTES, mac_key, MAC_KEY_BYTES);
      manager->skipped_keys =
          otrng_list_remove_element(last, manager->skipped_keys);
      otrng_list_free_full(last);
    }
    otrng_list_free_nodes(manager->skipped_keys);

    return ser_mac_keys;
  }

  return NULL;
}

// TODO: @refactoring define this here?
API uint8_t *
derive_key_from_extra_symm_key(uint8_t usage, const unsigned char *use_data,
                               size_t use_data_len,
                               const unsigned char *extra_symm_key) {
  uint8_t *derived_key = malloc(EXTRA_SYMMETRIC_KEY_BYTES);
  if (!derived_key) {
    return NULL;
  }

  goldilocks_shake256_ctx_p hd;

  hash_init_with_usage(hd, usage);
  hash_update(hd, use_data, use_data_len);
  hash_update(hd, extra_symm_key, EXTRA_SYMMETRIC_KEY_BYTES);

  hash_final(hd, derived_key, EXTRA_SYMMETRIC_KEY_BYTES);
  hash_destroy(hd);

  return derived_key;
}
