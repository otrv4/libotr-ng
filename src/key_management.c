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

#include <assert.h>
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

  memset(ratchet->root_key, 0, sizeof(root_key_p));
  memset(ratchet->chain_s, 0, sizeof(sending_chain_key_p));
  memset(ratchet->chain_r, 0, sizeof(receiving_chain_key_p));

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
}

INTERNAL void otrng_key_manager_init(key_manager_s *manager) {
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

  memset(manager->brace_key, 0, sizeof(brace_key_p));
  memset(manager->shared_secret, 0, sizeof(shared_secret_p));

  memset(manager->ssid, 0, sizeof(manager->ssid));
  manager->ssid_half_first = otrng_false;

  memset(manager->extra_symmetric_key, 0, sizeof(extra_symmetric_key_p));
  memset(manager->tmp_key, 0, sizeof(manager->tmp_key));

  manager->skipped_keys = NULL;
  manager->old_mac_keys = NULL;
}

INTERNAL key_manager_s *otrng_key_manager_new(void) {
  key_manager_s *manager = malloc(sizeof(key_manager_s));
  if (!manager) {
    return NULL;
  }

  otrng_key_manager_init(manager);
  return manager;
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

  sodium_memzero(manager->brace_key, sizeof(manager->brace_key));
  sodium_memzero(manager->shared_secret, sizeof(manager->shared_secret));
  sodium_memzero(manager->ssid, sizeof(manager->ssid));
  manager->ssid_half_first = otrng_false;
  sodium_memzero(manager->extra_symmetric_key,
                 sizeof(manager->extra_symmetric_key));

  otrng_list_free_full(manager->skipped_keys);
  manager->skipped_keys = NULL;

  otrng_list_free_full(manager->old_mac_keys);
  manager->old_mac_keys = NULL;
}

INTERNAL void otrng_key_manager_free(key_manager_s *manager) {
  otrng_key_manager_destroy(manager);
  free(manager);
}

INTERNAL void otrng_key_manager_wipe_shared_prekeys(key_manager_s *manager) {
  sodium_memzero(manager->their_shared_prekey,
                 sizeof(otrng_shared_prekey_pub_p));
  sodium_memzero(manager->our_shared_prekey, sizeof(otrng_shared_prekey_pub_p));
}

INTERNAL receiving_ratchet_s *
otrng_receiving_ratchet_new(key_manager_s *manager) {
  receiving_ratchet_s *ratchet = malloc(sizeof(receiving_ratchet_s));
  if (!ratchet) {
    return NULL;
  }

  otrng_ec_scalar_copy(ratchet->our_ecdh_priv, manager->our_ecdh->priv);
  ratchet->our_dh_priv = NULL;

  otrng_ec_bzero(ratchet->their_ecdh, ED448_POINT_BYTES);
  ratchet->their_dh = NULL;

  memset(ratchet->brace_key, 0, sizeof(brace_key_p));

  ratchet->i = manager->i;
  ratchet->j = manager->j;
  ratchet->k = manager->k;
  ratchet->pn = manager->pn;

  memcpy(ratchet->root_key, manager->current->root_key, sizeof(root_key_p));
  memcpy(ratchet->chain_r, manager->current->chain_r,
         sizeof(receiving_chain_key_p));

  ratchet->skipped_keys = manager->skipped_keys;

  return ratchet;
}

tstatic void otrng_key_manager_set_their_keys(ec_point_p their_ecdh,
                                              dh_public_key_p their_dh,
                                              key_manager_s *manager) {
  otrng_ec_point_destroy(manager->their_ecdh);
  otrng_ec_point_copy(manager->their_ecdh, their_ecdh);
  otrng_dh_mpi_release(manager->their_dh);
  manager->their_dh = otrng_dh_mpi_copy(their_dh);
}

INTERNAL void otrng_receiving_ratchet_copy(key_manager_s *dst,
                                           receiving_ratchet_s *src) {
  if (!dst || !src) {
    return;
  }
  otrng_ec_scalar_copy(dst->our_ecdh->priv, src->our_ecdh_priv);

  otrng_key_manager_set_their_keys(src->their_ecdh, src->their_dh, dst);

  memcpy(dst->brace_key, src->brace_key, sizeof(brace_key_p));
  memcpy(dst->shared_secret, src->shared_secret, sizeof(shared_secret_p));

  dst->i = src->i;
  dst->j = src->j;
  dst->k = src->k;
  dst->pn = src->pn;

  memcpy(dst->current->root_key, src->root_key, ROOT_KEY_BYTES);
  memcpy(dst->current->chain_r, src->chain_r, CHAIN_KEY_BYTES);

  dst->skipped_keys = src->skipped_keys;
}

INTERNAL void otrng_receiving_ratchet_destroy(receiving_ratchet_s *ratchet) {
  otrng_ec_bzero(ratchet->our_ecdh_priv, ED448_SCALAR_BYTES);

  if (ratchet->our_dh_priv) {
    gcry_mpi_release(ratchet->our_dh_priv);
  }
  ratchet->our_dh_priv = NULL;

  otrng_ec_bzero(ratchet->their_ecdh, ED448_POINT_BYTES);

  gcry_mpi_release(ratchet->their_dh);
  ratchet->their_dh = NULL;

  memset(ratchet->brace_key, 0, sizeof(brace_key_p));

  ratchet->i = 0;
  ratchet->k = 0;
  ratchet->pn = 0;

  sodium_memzero(ratchet->root_key, sizeof(root_key_p));
  sodium_memzero(ratchet->chain_r, sizeof(receiving_chain_key_p));

  ratchet->skipped_keys = NULL;

  free(ratchet);
  ratchet = NULL;
}

INTERNAL void otrng_key_manager_set_their_tmp_keys(
    ec_point_p their_ecdh, dh_public_key_p their_dh,
    receiving_ratchet_s *tmp_receiving_ratchet) {
  otrng_ec_point_destroy(tmp_receiving_ratchet->their_ecdh);
  otrng_ec_point_copy(tmp_receiving_ratchet->their_ecdh, their_ecdh);
  otrng_dh_mpi_release(tmp_receiving_ratchet->their_dh);
  tmp_receiving_ratchet->their_dh = otrng_dh_mpi_copy(their_dh);
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

  random_bytes(sym, ED448_PRIVATE_BYTES);

  now = time(NULL);
  otrng_ecdh_keypair_destroy(manager->our_ecdh);
  /* @secret the ecdh keypair will last
     1. for the first generation: until the ratchet is initialized
     2. when receiving a new dh ratchet
  */
  otrng_ecdh_keypair_generate(manager->our_ecdh, sym);
  goldilocks_bzero(sym, ED448_PRIVATE_BYTES);

  manager->last_generated = now;

  if (manager->i % 3 == 0) {
    otrng_dh_keypair_destroy(manager->our_dh);

    /* @secret the dh keypair will last
       1. for the first generation: until the ratchet is initialized
       2. when receiving a new dh ratchet
    */
    if (!otrng_dh_keypair_generate(manager->our_dh)) {
      return OTRNG_ERROR;
    }
  }

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_key_manager_calculate_tmp_key(uint8_t *tmp_key,
                                                  k_ecdh_p k_ecdh,
                                                  brace_key_p brace_key,
                                                  k_ecdh_p tmp_ecdh_k1,
                                                  k_ecdh_p tmp_ecdh_k2) {
  uint8_t usage_tmp_key = 0x0B;
  goldilocks_shake256_ctx_p hd;

  hash_init_with_usage(hd, usage_tmp_key);
  hash_update(hd, k_ecdh, ED448_POINT_BYTES);
  hash_update(hd, tmp_ecdh_k1, ED448_POINT_BYTES);
  hash_update(hd, tmp_ecdh_k2, ED448_POINT_BYTES);
  hash_update(hd, brace_key, sizeof(brace_key_p));

  hash_final(hd, tmp_key, HASH_BYTES);
  hash_destroy(hd);
}

INTERNAL void otrng_key_manager_calculate_auth_mac(uint8_t *auth_mac,
                                                   const uint8_t *auth_mac_key,
                                                   const uint8_t *t,
                                                   size_t t_len) {
  uint8_t usage_auth_mac = 0x10;

  goldilocks_shake256_ctx_p hd;

  hash_init_with_usage(hd, usage_auth_mac);
  hash_update(hd, auth_mac_key, sizeof(auth_mac_key));
  hash_update(hd, t, t_len);

  hash_final(hd, auth_mac, HASH_BYTES);
  hash_destroy(hd);
}

INTERNAL void otrng_key_manager_calculate_authenticator(
    uint8_t *authenticator, const uint8_t *mac_key, const uint8_t *sections) {

  uint8_t usage_authenticator = 0x1A;

  goldilocks_shake256_ctx_p hd;
  hash_init_with_usage(hd, usage_authenticator);
  hash_update(hd, mac_key, sizeof(msg_mac_key_p));
  hash_update(hd, sections, HASH_BYTES);

  hash_final(hd, authenticator, DATA_MSG_MAC_BYTES);
  hash_destroy(hd);
}

/* Generate the ephemeral keys just as the DAKE is finished */
tstatic otrng_err generate_first_ephemeral_keys(key_manager_s *manager,
                                                const char participant) {
  uint8_t random_buff[ED448_PRIVATE_BYTES];
  uint8_t usage_ECDH_first_ephemeral = 0x11;

  assert(participant == 'u' || participant == 't');

  if (participant == 'u') {
    shake_256_kdf1(random_buff, sizeof random_buff, usage_ECDH_first_ephemeral,
                   manager->shared_secret, sizeof(shared_secret_p));

    otrng_ec_point_destroy(manager->our_ecdh->pub);
    /* @secret this will be deleted once sent a new data message in a new
     * ratchet */
    otrng_ecdh_keypair_generate(manager->our_ecdh, random_buff);
    goldilocks_bzero(random_buff, ED448_PRIVATE_BYTES);

    otrng_dh_keypair_destroy(manager->our_dh);
    /* @secret this will be deleted once sent a new data message in a new
     * ratchet */
    if (!otrng_dh_keypair_generate_from_shared_secret(
            manager->shared_secret, manager->our_dh, participant)) {
      return OTRNG_ERROR;
    }

  } else if (participant == 't') {
    shake_256_kdf1(random_buff, sizeof random_buff, usage_ECDH_first_ephemeral,
                   manager->shared_secret, sizeof(shared_secret_p));

    otrng_ec_point_destroy(manager->their_ecdh);
    /* @secret this will be deleted once received a new data message in a new
     * ratchet */
    otrng_ecdh_keypair_generate_their(manager->their_ecdh, random_buff);
    goldilocks_bzero(random_buff, ED448_PRIVATE_BYTES);

    gcry_mpi_release(manager->their_dh);
    manager->their_dh = NULL;

    dh_keypair_p tmp_their_dh;
    /* @secret this will be deleted once received a new data message in a new
     * ratchet */
    if (!otrng_dh_keypair_generate_from_shared_secret(
            manager->shared_secret, tmp_their_dh, participant)) {
      return OTRNG_ERROR;
    }

    manager->their_dh = tmp_their_dh->pub;
  }
  return OTRNG_SUCCESS;
}

tstatic otrng_err calculate_brace_key(
    key_manager_s *manager, receiving_ratchet_s *tmp_receiving_ratchet,
    const char action) {
  uint8_t usage_third_brace_key = 0x01;
  uint8_t usage_brace_key = 0x02;

  dh_shared_secret_p k_dh;
  size_t k_dh_len = 0;

  assert(action == 's' || action == 'r');
  if (action == 's') {
    if (manager->i % 3 == 0) {
      if (!otrng_dh_shared_secret(k_dh, &k_dh_len, manager->our_dh->priv,
                                  manager->their_dh)) {
        return OTRNG_ERROR;
      }
      shake_256_kdf1(manager->brace_key, BRACE_KEY_BYTES, usage_third_brace_key,
                     k_dh, k_dh_len);
    } else {
      shake_256_kdf1(manager->brace_key, BRACE_KEY_BYTES, usage_brace_key,
                     manager->brace_key, sizeof(brace_key_p));
    }
  } else if (action == 'r') {
    if (manager->i % 3 == 0) {
      // TODO: should take tmp too
      if (!otrng_dh_shared_secret(k_dh, &k_dh_len, manager->our_dh->priv,
                                  tmp_receiving_ratchet->their_dh)) {
        return OTRNG_ERROR;
      }
      shake_256_kdf1(tmp_receiving_ratchet->brace_key, BRACE_KEY_BYTES,
                     usage_third_brace_key, k_dh, k_dh_len);
    } else {
      shake_256_kdf1(tmp_receiving_ratchet->brace_key, BRACE_KEY_BYTES,
                     usage_brace_key, manager->brace_key, sizeof(brace_key_p));
    }
  }
  sodium_memzero(k_dh, sizeof(k_dh));

  return OTRNG_SUCCESS;
}

static uint8_t usage_shared_secret = 0x03;

tstatic void calculate_shared_secret(key_manager_s *manager,
                                     receiving_ratchet_s *tmp_receiving_ratchet,
                                     k_ecdh_p k_ecdh, const char action) {
  goldilocks_shake256_ctx_p hd;

  hash_init_with_usage(hd, usage_shared_secret);
  hash_update(hd, k_ecdh, sizeof(k_ecdh_p));

  assert(action == 's' || action == 'r');
  if (action == 's') {
    hash_update(hd, manager->brace_key, sizeof(brace_key_p));
    hash_final(hd, manager->shared_secret, sizeof(shared_secret_p));
    hash_destroy(hd);

    sodium_memzero(manager->brace_key, sizeof(brace_key_p));
  } else if (action == 'r') {
    hash_update(hd, tmp_receiving_ratchet->brace_key, sizeof(brace_key_p));
    hash_final(hd, tmp_receiving_ratchet->shared_secret,
               sizeof(shared_secret_p));
    hash_destroy(hd);

    sodium_memzero(tmp_receiving_ratchet->brace_key, sizeof(brace_key_p));
  }

  sodium_memzero(k_ecdh, sizeof(k_ecdh_p));
}

INTERNAL otrng_err otrng_key_manager_generate_shared_secret(
    key_manager_s *manager, const otrng_bool interactive) {

  if (interactive) {
    k_ecdh_p k_ecdh;

    otrng_ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);
    otrng_ec_bzero(manager->our_ecdh->priv, sizeof(ec_scalar_p));

    if (!otrng_ecdh_valid_secret(k_ecdh)) {
      return OTRNG_ERROR;
    }

    if (!calculate_brace_key(manager, NULL, 's')) {
      return OTRNG_ERROR;
    }
    otrng_dh_priv_key_destroy(manager->our_dh);

    calculate_shared_secret(manager, NULL, k_ecdh, 's');

  } else if (!interactive) {
    shake_256_kdf1(manager->shared_secret, sizeof(shared_secret_p),
                   usage_shared_secret, manager->tmp_key,
                   sizeof(manager->tmp_key));

    sodium_memzero(manager->tmp_key, sizeof(brace_key_p));
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
    manager->ssid_half_first = otrng_false;
  } else {
    manager->ssid_half_first = otrng_true;
  }

#ifdef DEBUG
  printf("\n");
  printf("THE SECURE SESSION ID\n");
  printf("ssid: \n");

  if (manager->ssid_half_first) {
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

  return OTRNG_SUCCESS;
}

INTERNAL otrng_err otrng_ecdh_shared_secret_from_prekey(
    uint8_t *shared_secret, const otrng_shared_prekey_pair_s *shared_prekey,
    const ec_point_p their_pub) {
  goldilocks_448_point_p p;
  goldilocks_448_point_scalarmul(p, their_pub, shared_prekey->priv);

  if (!otrng_ec_point_valid(p)) {
    return OTRNG_ERROR;
  }

  otrng_serialize_ec_point(shared_secret, p);

  if (!otrng_ecdh_valid_secret(shared_secret)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_err otrng_ecdh_shared_secret_from_keypair(
    uint8_t *shared_secret, otrng_keypair_s *keypair,
    const ec_point_p their_pub) {
  goldilocks_448_point_p p;
  goldilocks_448_point_scalarmul(p, their_pub, keypair->priv);

  if (!otrng_ec_point_valid(p)) {
    return OTRNG_ERROR;
  }

  otrng_serialize_ec_point(shared_secret, p);

  if (!otrng_ecdh_valid_secret(shared_secret)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic void calculate_ssid(key_manager_s *manager) {
  uint8_t usage_SSID = 0x04;
  shake_256_kdf1(manager->ssid, sizeof(manager->ssid), usage_SSID,
                 manager->shared_secret, sizeof(shared_secret_p));
}

INTERNAL otrng_err otrng_key_manager_ratcheting_init(key_manager_s *manager,
                                                     const char participant) {
  if (!generate_first_ephemeral_keys(manager, participant)) {
    return OTRNG_ERROR;
  }

  manager->i = 0;
  manager->j = 0;
  manager->k = 0;
  manager->pn = 0;

  memcpy(manager->current->root_key, manager->shared_secret,
         sizeof(root_key_p));
  sodium_memzero(manager->shared_secret, sizeof(shared_secret_p));

  return OTRNG_SUCCESS;
}

tstatic otrng_err enter_new_ratchet(key_manager_s *manager,
                                    receiving_ratchet_s *tmp_receiving_ratchet,
                                    const char action) {
  k_ecdh_p k_ecdh;

  /* K_ecdh = ECDH(our_ecdh.secret, their_ecdh) */
  assert(action == 's' || action == 'r');
  if (action == 's') {
    otrng_ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);
  } else if (action == 'r') {
    otrng_ecdh_shared_secret(k_ecdh, manager->our_ecdh,
                             tmp_receiving_ratchet->their_ecdh);
  }

  /* if i % 3 == 0 : brace_key = KDF_1(usage_third_brace_key || k_dh, 32)
     else brace_key = KDF_1(usage_brace_key || brace_key, 32) */
  if (!calculate_brace_key(manager, tmp_receiving_ratchet, action)) {
    return OTRNG_ERROR;
  }

  /* K = KDF_1(usage_shared_secret || K_ecdh || brace_key, 64) */
  calculate_shared_secret(manager, tmp_receiving_ratchet, k_ecdh, action);

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

  key_manager_derive_ratchet_keys(manager, tmp_receiving_ratchet, action);

  return OTRNG_SUCCESS;
}

tstatic otrng_err rotate_keys(key_manager_s *manager,
                              receiving_ratchet_s *tmp_receiving_ratchet,
                              const char action) {
  assert(action == 's' || action == 'r');
  if (action == 's') {
    /* our_ecdh = generateECDH()
       if i % 3 == 0, our_dh = generateDH() */
    if (!otrng_key_manager_generate_ephemeral_keys(manager)) {
      return OTRNG_ERROR;
    }

    manager->last_generated = time(NULL);

    if (!enter_new_ratchet(manager, NULL, action)) {
      return OTRNG_ERROR;
    }

    manager->i++;
  }

  if (action == 'r') {
    if (!enter_new_ratchet(manager, tmp_receiving_ratchet, action)) {
      return OTRNG_ERROR;
    }

    otrng_ec_scalar_destroy(tmp_receiving_ratchet->our_ecdh_priv);
    // TODO: this should destroy the tmp data
    if (tmp_receiving_ratchet->i % 3 == 0) {
      otrng_dh_priv_key_destroy(manager->our_dh);
    }

    tmp_receiving_ratchet->pn = tmp_receiving_ratchet->j;
    tmp_receiving_ratchet->j = 0;
    tmp_receiving_ratchet->k = 0;
    tmp_receiving_ratchet->i = tmp_receiving_ratchet->i + 1;
  }

  return OTRNG_SUCCESS;
}

tstatic void
key_manager_derive_ratchet_keys(key_manager_s *manager,
                                receiving_ratchet_s *tmp_receiving_ratchet,
                                const char action) {
  /* root_key[i], chain_key_s[i][j] = derive_ratchet_keys(sending,
     root_key[i-1], K) root_key[i] = KDF_1(usage_root_key || root_key[i-1] || K,
     64)
     @secret should be deleted when the new root key is derived
  */
  uint8_t usage_root_key = 0x13;
  uint8_t usage_chain_key = 0x14;

  goldilocks_shake256_ctx_p hd;

  assert(action == 's' || action == 'r');

  /* chain_key_purpose[i][j] = KDF_1(usage_chain_key || root_key[i-1] || K, 64)
     @secret: should be deleted when the next chain key is derived
  */
  if (action == 's') {
    hash_init_with_usage(hd, usage_root_key);
    hash_update(hd, manager->current->root_key, sizeof(root_key_p));
    hash_update(hd, manager->shared_secret, sizeof(shared_secret_p));
    hash_final(hd, manager->current->root_key, sizeof(root_key_p));
    hash_destroy(hd);

    hash_init_with_usage(hd, usage_chain_key);
    hash_update(hd, manager->current->root_key, sizeof(root_key_p));
    hash_update(hd, manager->shared_secret, sizeof(shared_secret_p));

    hash_final(hd, manager->current->chain_s, sizeof(sending_chain_key_p));

    sodium_memzero(manager->shared_secret, sizeof(shared_secret_p));
  } else if (action == 'r') {
    hash_init_with_usage(hd, usage_root_key);
    hash_update(hd, tmp_receiving_ratchet->root_key, sizeof(root_key_p));
    hash_update(hd, tmp_receiving_ratchet->shared_secret,
                sizeof(shared_secret_p));
    hash_final(hd, tmp_receiving_ratchet->root_key, sizeof(root_key_p));
    hash_destroy(hd);

    hash_init_with_usage(hd, usage_chain_key);
    hash_update(hd, tmp_receiving_ratchet->root_key, sizeof(root_key_p));
    hash_update(hd, tmp_receiving_ratchet->shared_secret,
                sizeof(shared_secret_p));

    hash_final(hd, tmp_receiving_ratchet->chain_r,
               sizeof(receiving_chain_key_p));

    sodium_memzero(tmp_receiving_ratchet->shared_secret,
                   sizeof(shared_secret_p));
  }

  hash_destroy(hd);

#ifdef DEBUG
  printf("\n");
  printf("ROOT KEY = ");
  otrng_memdump(manager->current->root_key, sizeof(root_key_p));
  printf("CHAIN_S = ");
  otrng_memdump(ratchet->chain_s, sizeof(sending_chain_key_p));
  printf("CHAIN_R = ");
  otrng_memdump(ratchet->chain_r, sizeof(receiving_chain_key_p));
#endif
}

static uint8_t usage_next_chain_key = 0x15;
static uint8_t usage_message_key = 0x16;
static uint8_t usage_mac_key = 0x17;
static uint8_t usage_extra_symm_key = 0x18;

tstatic void derive_next_chain_key(key_manager_s *manager,
                                   receiving_ratchet_s *tmp_receiving_ratchet,
                                   const char action) {
  /* chain_key_s[i-1][j+1] = KDF_1(usage_next_chain_key || chain_key_s[i-1][j],
   * 64) */
  assert(action == 's' || action == 'r');
  if (action == 's') {
    shake_256_kdf1(manager->current->chain_s, sizeof(sending_chain_key_p),
                   usage_next_chain_key, manager->current->chain_s,
                   sizeof(sending_chain_key_p));
  } else if (action == 'r') {
    shake_256_kdf1(tmp_receiving_ratchet->chain_r,
                   sizeof(receiving_chain_key_p), usage_next_chain_key,
                   tmp_receiving_ratchet->chain_r,
                   sizeof(receiving_chain_key_p));
  }
}

tstatic void derive_encryption_and_mac_keys(
    msg_enc_key_p enc_key, msg_mac_key_p mac_key, key_manager_s *manager,
    receiving_ratchet_s *tmp_receiving_ratchet, const char action) {
  /* MKenc, MKmac = derive_enc_mac_keys(chain_key_s[i-1][j])
     MKenc = KDF_1(usage_message_key || chain_key, 32)
     MKmac = KDF_1(usage_mac_key || MKenc, 64)
  */

  assert(action == 's' || action == 'r');
  if (action == 's') {
    shake_256_kdf1(enc_key, sizeof(msg_enc_key_p), usage_message_key,
                   manager->current->chain_s, sizeof(sending_chain_key_p));

  } else if (action == 'r') {
    shake_256_kdf1(enc_key, sizeof(msg_enc_key_p), usage_message_key,
                   tmp_receiving_ratchet->chain_r,
                   sizeof(receiving_chain_key_p));
  }
  shake_256_kdf1(mac_key, sizeof(msg_mac_key_p), usage_mac_key, enc_key,
                 sizeof(msg_enc_key_p));
}

tstatic void calculate_extra_key(key_manager_s *manager, const char action) {
  goldilocks_shake256_ctx_p hd;
  uint8_t extra_key_buff[EXTRA_SYMMETRIC_KEY_BYTES];
  uint8_t magic[1] = {0xFF};

  hash_init_with_usage(hd, usage_extra_symm_key);
  hash_update(hd, magic, 1);

  /* extra_symm_key = KDF_1(usage_extra_symm_key || 0xFF || chain_key_s[i-1][j],
   * 32) */
  assert(action == 's' || action == 'r');
  if (action == 's') {
    hash_update(hd, manager->current->chain_s, sizeof(sending_chain_key_p));
  } else if (action == 'r') {
    hash_update(hd, manager->current->chain_r, sizeof(receiving_chain_key_p));
  }
  hash_final(hd, extra_key_buff, EXTRA_SYMMETRIC_KEY_BYTES);
  hash_destroy(hd);

  // TODO: add to tmp
  memcpy(manager->extra_symmetric_key, extra_key_buff,
         sizeof(extra_symmetric_key_p));

#ifdef DEBUG
  printf("\n");
  printf("EXTRA KEY = ");
  otrng_memdump(manager->extra_symmetric_key,
                sizeof(manager->extra_symmetric_key));
#endif
}

// tstatic void delete_stored_enc_keys(key_manager_s *manager) {
//  otrng_list_free_full(manager->skipped_keys);
//  manager->skipped_keys = NULL;
//}

tstatic otrng_err store_enc_keys(msg_enc_key_p enc_key,
                                 receiving_ratchet_s *tmp_receiving_ratchet,
                                 const int until, const int max_skip,
                                 const char ratchet_type, otrng_notif notif) {
  if ((tmp_receiving_ratchet->k + max_skip) < until) {
    notif = OTRNG_NOTIF_MSG_STORAGE_FULL;
    return OTRNG_SUCCESS;
  }

  uint8_t zero_buff[CHAIN_KEY_BYTES] = {0};
  if (!(memcmp(tmp_receiving_ratchet->chain_r, zero_buff,
               sizeof(receiving_chain_key_p)) == 0)) {
    while (tmp_receiving_ratchet->k < until) {
      shake_256_kdf1(enc_key, sizeof(msg_enc_key_p), usage_message_key,
                     tmp_receiving_ratchet->chain_r,
                     sizeof(receiving_chain_key_p));

      goldilocks_shake256_ctx_p hd;
      uint8_t extra_key[EXTRA_SYMMETRIC_KEY_BYTES];
      uint8_t magic[1] = {0xFF};

      hash_init_with_usage(hd, usage_extra_symm_key);
      hash_update(hd, magic, 1);

      hash_update(hd, tmp_receiving_ratchet->chain_r,
                  sizeof(receiving_chain_key_p));
      hash_final(hd, extra_key, sizeof(extra_symmetric_key_p));
      hash_destroy(hd);

      shake_256_kdf1(tmp_receiving_ratchet->chain_r,
                     sizeof(receiving_chain_key_p), usage_next_chain_key,
                     tmp_receiving_ratchet->chain_r,
                     sizeof(receiving_chain_key_p));

      skipped_keys_s *skipped_msg_enc_key = malloc(sizeof(skipped_keys_s));
      if (!skipped_msg_enc_key) {
        return OTRNG_ERROR;
      }

      assert(ratchet_type == 'd' || ratchet_type == 'c');
      if (ratchet_type == 'd') {
        skipped_msg_enc_key->i = tmp_receiving_ratchet->i -
                                 1; /* ratchet_id - 1 for the dh ratchet */
      } else if (ratchet_type == 'c') {
        skipped_msg_enc_key->i = tmp_receiving_ratchet->i;
      }

      skipped_msg_enc_key->j = tmp_receiving_ratchet->k;

      memcpy(skipped_msg_enc_key->extra_symmetric_key, extra_key,
             sizeof(extra_symmetric_key_p));
      memcpy(skipped_msg_enc_key->enc_key, enc_key, sizeof(msg_enc_key_p));

      /*
         @secret: should be deleted when:
         1. session expired
         2. the key is retrieved
      */
      tmp_receiving_ratchet->skipped_keys = otrng_list_add(
          skipped_msg_enc_key, tmp_receiving_ratchet->skipped_keys);
      sodium_memzero(enc_key, sizeof(msg_enc_key_p));
      tmp_receiving_ratchet->k++;
    }
  }

  return OTRNG_SUCCESS;
}

/*
   MKenc, extra_symm_key = skipped_MKenc[ratchet_id, message_id]
   MKmac = KDF_1(usage_mac_key || MKenc, 64).
*/
INTERNAL otrng_err otrng_key_get_skipped_keys(
    msg_enc_key_p enc_key, msg_mac_key_p mac_key, int ratchet_id,
    int message_id, key_manager_s *manager,
    receiving_ratchet_s *tmp_receiving_ratchet) {
  list_element_s *current = tmp_receiving_ratchet->skipped_keys;
  while (current) {
    skipped_keys_s *skipped_keys = current->data;

    if (skipped_keys->i == ratchet_id && skipped_keys->j == message_id) {
      memcpy(enc_key, skipped_keys->enc_key, sizeof(msg_enc_key_p));
      shake_256_kdf1(mac_key, MAC_KEY_BYTES, usage_mac_key, enc_key,
                     ENC_KEY_BYTES);
      // TODO: add to tmp struct
      memcpy(manager->extra_symmetric_key, skipped_keys->extra_symmetric_key,
             sizeof(extra_symmetric_key_p));

      tmp_receiving_ratchet->skipped_keys = otrng_list_remove_element(
          current, tmp_receiving_ratchet->skipped_keys);
      otrng_list_free_full(current);

      return OTRNG_SUCCESS;
    }

    current = current->next;
  }

  /* This is not an actual error, it is just that the key we need was not
  skipped */
  return OTRNG_ERROR;
}

INTERNAL otrng_err otrng_key_manager_derive_chain_keys(
    msg_enc_key_p enc_key, msg_mac_key_p mac_key, key_manager_s *manager,
    receiving_ratchet_s *tmp_receiving_ratchet, int max_skip, int message_id,
    const char action, otrng_notif notif) {

  assert(action == 's' || action == 'r');
  if (action == 'r') {
    if (!store_enc_keys(enc_key, tmp_receiving_ratchet, message_id, max_skip,
                        'c', notif)) {
      return OTRNG_ERROR;
    }
  }

  /* @secret should be deleted after being used to encrypt and mac the message
   */
  derive_encryption_and_mac_keys(enc_key, mac_key, manager,
                                 tmp_receiving_ratchet, action);
  calculate_extra_key(manager, action);
  /* @secret should be deleted when the new chain key is derived */
  derive_next_chain_key(manager, tmp_receiving_ratchet, action);

#ifdef DEBUG
  printf("\n");
  printf("GOT SENDING KEYS:\n");
  printf("enc_key = ");
  otrng_memdump(enc_key, sizeof(msg_enc_key_p));
  printf("mac_key = ");
  otrng_memdump(mac_key, sizeof(msg_mac_key_p));
#endif

  return OTRNG_SUCCESS;
}

INTERNAL otrng_err otrng_key_manager_derive_dh_ratchet_keys(
    key_manager_s *manager, int max_skip,
    receiving_ratchet_s *tmp_receiving_ratchet, int message_id, int previous_n,
    const char action, otrng_notif notif) {
  /* Derive new ECDH and DH keys */
  msg_enc_key_p enc_key;

  if (message_id == 0) {
    assert(action == 's' || action == 'r');
    if (action == 'r') {
      /* Store any message keys from the previous DH Ratchet */
      if (!store_enc_keys(enc_key, tmp_receiving_ratchet, previous_n, max_skip,
                          'd', notif)) {
        return OTRNG_ERROR;
      }
    }
    return rotate_keys(manager, tmp_receiving_ratchet, action);
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_err otrng_store_old_mac_keys(key_manager_s *manager,
                                            msg_mac_key_p mac_key) {
  uint8_t *to_store_mac = malloc(MAC_KEY_BYTES);
  if (!to_store_mac) {
    return OTRNG_ERROR;
  }

  memcpy(to_store_mac, mac_key, sizeof(msg_mac_key_p));
  manager->old_mac_keys = otrng_list_add(to_store_mac, manager->old_mac_keys);

  return OTRNG_SUCCESS;
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

    msg_mac_key_p mac_key;
    msg_enc_key_p enc_key;

    memset(enc_key, 0, sizeof(msg_enc_key_p));
    memset(mac_key, 0, sizeof(msg_mac_key_p));

    for (int i = 0; i < num_stored_keys; i++) {
      list_element_s *last = otrng_list_get_last(manager->skipped_keys);
      skipped_keys_s *skipped_keys = last->data;
      memcpy(enc_key, skipped_keys->enc_key, sizeof(msg_enc_key_p));
      shake_256_kdf1(mac_key, sizeof(msg_mac_key_p), usage_mac_key, enc_key,
                     sizeof(msg_enc_key_p));
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
