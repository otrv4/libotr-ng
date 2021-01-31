/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

#include <assert.h>
#include <string.h>
#include <time.h>

#define OTRNG_KEY_MANAGEMENT_PRIVATE

#include "alloc.h"
#include "key_management.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"
#include "util.h"

#include "debug.h"

tstatic ratchet_s *ratchet_new() {
  ratchet_s *ratchet = otrng_secure_alloc(sizeof(ratchet_s));

  return ratchet;
}

tstatic void ratchet_free(ratchet_s *ratchet) {
  if (!ratchet) {
    return;
  }

  otrng_secure_wipe(ratchet->root_key, ROOT_KEY_BYTES);
  otrng_secure_wipe(ratchet->chain_s, CHAIN_KEY_BYTES);
  otrng_secure_wipe(ratchet->chain_r, CHAIN_KEY_BYTES);

  otrng_secure_free(ratchet);
}

INTERNAL void otrng_key_manager_init(key_manager_s *manager) {
  memset(manager, 0, sizeof(key_manager_s));
  manager->current = ratchet_new();
  manager->ssid_half_first = otrng_false;

  manager->our_ecdh = otrng_secure_alloc(sizeof(ecdh_keypair_s));
  manager->our_ecdh_first = otrng_secure_alloc(sizeof(ecdh_keypair_s));

  manager->our_dh = otrng_secure_alloc(sizeof(dh_keypair_s));
  manager->our_dh->pub = NULL;
  manager->our_dh->priv = NULL;

  manager->our_dh_first = otrng_secure_alloc(sizeof(dh_keypair_s));
  manager->our_dh_first->pub = NULL;
  manager->our_dh_first->priv = NULL;
}

INTERNAL key_manager_s *otrng_key_manager_new(void) {
  key_manager_s *manager = otrng_secure_alloc(sizeof(key_manager_s));
  otrng_key_manager_init(manager);
  return manager;
}

INTERNAL void otrng_key_manager_destroy(key_manager_s *manager) {
  otrng_ecdh_keypair_destroy(manager->our_ecdh);
  otrng_secure_free(manager->our_ecdh);

  if (manager->our_ecdh_first) {
    otrng_ecdh_keypair_destroy(manager->our_ecdh_first);
    otrng_secure_free(manager->our_ecdh_first);
  }

  otrng_dh_keypair_destroy(manager->our_dh);
  otrng_secure_free(manager->our_dh);

  if (manager->our_dh_first) {
    otrng_dh_keypair_destroy(manager->our_dh_first);
    otrng_secure_free(manager->our_dh_first);
  }

  otrng_ec_point_destroy(manager->their_ecdh);

  gcry_mpi_release(manager->their_dh);
  manager->their_dh = NULL;

  manager->i = 0;
  manager->j = 0;
  manager->k = 0;
  manager->pn = 0;

  ratchet_free(manager->current);
  manager->current = NULL;

  otrng_secure_wipe(manager->brace_key, BRACE_KEY_BYTES);
  otrng_secure_wipe(manager->shared_secret, SHARED_SECRET_BYTES);
  otrng_secure_wipe(manager->ssid, SSID_BYTES);
  manager->ssid_half_first = otrng_false;
  otrng_secure_wipe(manager->extra_symmetric_key, EXTRA_SYMMETRIC_KEY_BYTES);

  otrng_list_free(manager->skipped_keys, otrng_secure_free);
  manager->skipped_keys = NULL;

  otrng_list_free(manager->old_mac_keys, otrng_secure_free);
  manager->old_mac_keys = NULL;

  otrng_secure_wipe(manager, sizeof(key_manager_s));
}

INTERNAL void otrng_key_manager_free(key_manager_s *manager) {
  otrng_key_manager_destroy(manager);
  otrng_secure_free(manager);
}

INTERNAL void otrng_key_manager_wipe_shared_prekeys(key_manager_s *manager) {
  otrng_secure_wipe(manager->their_shared_prekey,
                    sizeof(otrng_shared_prekey_pub));
  otrng_secure_wipe(manager->our_shared_prekey,
                    sizeof(otrng_shared_prekey_pub));
}

INTERNAL /*@null@*/ receiving_ratchet_s *
otrng_receiving_ratchet_new(key_manager_s *manager) {
  receiving_ratchet_s *ratchet =
      otrng_secure_alloc(sizeof(receiving_ratchet_s));
  otrng_ec_scalar_copy(ratchet->our_ecdh_priv, manager->our_ecdh->priv);
  ratchet->our_dh_priv = NULL;

  otrng_secure_wipe(ratchet->their_ecdh, ED448_POINT_BYTES);
  ratchet->their_dh = NULL;

  memset(ratchet->brace_key, 0, BRACE_KEY_BYTES);

  ratchet->i = manager->i;
  ratchet->j = manager->j;
  ratchet->k = manager->k;
  ratchet->pn = manager->pn;

  memcpy(ratchet->root_key, manager->current->root_key, ROOT_KEY_BYTES);
  memcpy(ratchet->chain_r, manager->current->chain_r, CHAIN_KEY_BYTES);

  memcpy(ratchet->extra_symmetric_key, manager->extra_symmetric_key,
         EXTRA_SYMMETRIC_KEY_BYTES);

  ratchet->skipped_keys = manager->skipped_keys;

  return ratchet;
}

tstatic void otrng_key_manager_set_their_keys(ec_point their_ecdh,
                                              dh_public_key their_dh,
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

  memcpy(dst->brace_key, src->brace_key, BRACE_KEY_BYTES);
  memcpy(dst->shared_secret, src->shared_secret, SHARED_SECRET_BYTES);

  dst->i = src->i;
  dst->j = src->j;
  dst->k = src->k;
  dst->pn = src->pn;

  memcpy(dst->current->root_key, src->root_key, ROOT_KEY_BYTES);
  memcpy(dst->current->chain_r, src->chain_r, CHAIN_KEY_BYTES);

  memcpy(dst->extra_symmetric_key, src->extra_symmetric_key,
         EXTRA_SYMMETRIC_KEY_BYTES);

  dst->skipped_keys = src->skipped_keys;
}

INTERNAL void otrng_receiving_ratchet_destroy(receiving_ratchet_s *ratchet) {
  otrng_secure_wipe(ratchet->our_ecdh_priv, ED448_SCALAR_BYTES);

  if (ratchet->our_dh_priv) {
    gcry_mpi_release(ratchet->our_dh_priv);
  }

  otrng_secure_wipe(ratchet->their_ecdh, ED448_POINT_BYTES);

  gcry_mpi_release(ratchet->their_dh);

  memset(ratchet->brace_key, 0, BRACE_KEY_BYTES);

  otrng_secure_wipe(ratchet->root_key, ROOT_KEY_BYTES);
  otrng_secure_wipe(ratchet->chain_r, CHAIN_KEY_BYTES);
  otrng_secure_wipe(ratchet->extra_symmetric_key, EXTRA_SYMMETRIC_KEY_BYTES);

  otrng_secure_free(ratchet);
}

INTERNAL void otrng_key_manager_set_their_tmp_keys(
    ec_point their_ecdh, dh_public_key their_dh,
    receiving_ratchet_s *tmp_receiving_ratchet) {
  otrng_ec_point_destroy(tmp_receiving_ratchet->their_ecdh);
  otrng_ec_point_copy(tmp_receiving_ratchet->their_ecdh, their_ecdh);
  otrng_dh_mpi_release(tmp_receiving_ratchet->their_dh);
  tmp_receiving_ratchet->their_dh = otrng_dh_mpi_copy(their_dh);
}

INTERNAL void otrng_key_manager_set_their_ecdh(const ec_point their_ecdh,
                                               key_manager_s *manager) {
  otrng_ec_point_copy(manager->their_ecdh, their_ecdh);
}

INTERNAL void otrng_key_manager_set_their_dh(const dh_public_key their_dh,
                                             key_manager_s *manager) {
  otrng_dh_mpi_release(manager->their_dh);
  manager->their_dh = otrng_dh_mpi_copy(their_dh);
}

INTERNAL otrng_result
otrng_key_manager_generate_ephemeral_keys(key_manager_s *manager) {
  time_t now;
  uint8_t *sym = otrng_secure_alloc(ED448_PRIVATE_BYTES);
  uint8_t *sym_first = otrng_secure_alloc(ED448_PRIVATE_BYTES);

  random_bytes(sym, ED448_PRIVATE_BYTES);
  random_bytes(sym_first, ED448_PRIVATE_BYTES);

  now = time(NULL);
  otrng_ecdh_keypair_destroy(manager->our_ecdh);
  otrng_ecdh_keypair_destroy(manager->our_ecdh_first);
  /* @secret the ecdh keypair will last
     1. for the first generation: until the ratchet is initialized
     2. when receiving a new dh ratchet
  */
  if (!otrng_ecdh_keypair_generate(manager->our_ecdh, sym)) {
    otrng_secure_free(sym);
    otrng_secure_free(sym_first);
    return OTRNG_ERROR;
  }
  otrng_secure_free(sym);

  if (!otrng_ecdh_keypair_generate(manager->our_ecdh_first, sym_first)) {
    otrng_secure_free(sym_first);
    return OTRNG_ERROR;
  }
  otrng_secure_free(sym_first);

  manager->last_generated = now;

  if (manager->i % 3 == 0) {
    otrng_dh_keypair_destroy(manager->our_dh);
    otrng_dh_keypair_destroy(manager->our_dh_first);

    /* @secret the dh keypair will last
       1. for the first generation: until the ratchet is initialized
       2. when receiving a new dh ratchet
    */
    if (!otrng_dh_keypair_generate(manager->our_dh)) {
      return OTRNG_ERROR;
    }

    if (!otrng_dh_keypair_generate(manager->our_dh_first)) {
      return OTRNG_ERROR;
    }
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_key_manager_calculate_tmp_key(uint8_t *tmp_key,
                                                          k_ecdh ecdh_key,
                                                          k_brace brace_key,
                                                          k_ecdh tmp_ecdh_k1,
                                                          k_ecdh tmp_ecdh_k2) {
  uint8_t usage_tmp_key = 0x0C;
  goldilocks_shake256_ctx_p hd;

  if (!hash_init_with_usage(hd, usage_tmp_key)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, ecdh_key, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, tmp_ecdh_k1, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, tmp_ecdh_k2, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, brace_key, BRACE_KEY_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, tmp_key, HASH_BYTES);
  hash_destroy(hd);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_key_manager_calculate_auth_mac(
    uint8_t *auth_mac, const uint8_t *auth_mac_key, const uint8_t *t,
    size_t t_len) {
  uint8_t usage_auth_mac = 0x11;

  goldilocks_shake256_ctx_p hd;

  if (!hash_init_with_usage(hd, usage_auth_mac)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, auth_mac_key, HASH_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, t, t_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, auth_mac, HASH_BYTES);
  hash_destroy(hd);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_key_manager_calculate_authenticator(
    uint8_t *authenticator, const uint8_t *mac_key, const uint8_t *sections,
    size_t sections_len) {

  uint8_t usage_authenticator = 0x1A;

  goldilocks_shake256_ctx_p hd;
  if (!hash_init_with_usage(hd, usage_authenticator)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, mac_key, MAC_KEY_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, sections, sections_len) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  hash_final(hd, authenticator, DATA_MSG_MAC_BYTES);
  hash_destroy(hd);

  return OTRNG_SUCCESS;
}

/* Generate the ephemeral keys just as the DAKE is finished */
tstatic otrng_result generate_first_ephemeral_keys(key_manager_s *manager,
                                                   const char participant) {
  uint8_t *random_buffer = otrng_secure_alloc(ED448_PRIVATE_BYTES);
  uint8_t usage_ECDH_first_ephemeral = 0x12;

  assert(participant == 'u' || participant == 't');

  if (participant == 'u') {
    if (!shake_256_kdf1(random_buffer, ED448_PRIVATE_BYTES,
                        usage_ECDH_first_ephemeral, manager->shared_secret,
                        SHARED_SECRET_BYTES)) {
      otrng_secure_free(random_buffer);
      return OTRNG_ERROR;
    }

    otrng_ec_point_destroy(manager->our_ecdh->pub);
    /* @secret this will be deleted once sent a new data message in a new
     * ratchet */
    if (!otrng_ecdh_keypair_generate(manager->our_ecdh, random_buffer)) {
      otrng_secure_free(random_buffer);
      return OTRNG_ERROR;
    }

    otrng_secure_free(random_buffer);

    otrng_dh_keypair_destroy(manager->our_dh);
    /* @secret this will be deleted once sent a new data message in a new
     * ratchet */
    if (!otrng_dh_keypair_generate_from_shared_secret(
            manager->shared_secret, manager->our_dh, participant)) {
      return OTRNG_ERROR;
    }

  } else if (participant == 't') {
    dh_keypair_s tmp_their_dh = {.pub = NULL, .priv = NULL};

    if (!shake_256_kdf1(random_buffer, ED448_PRIVATE_BYTES,
                        usage_ECDH_first_ephemeral, manager->shared_secret,
                        SHARED_SECRET_BYTES)) {
      otrng_secure_free(random_buffer);
      return OTRNG_ERROR;
    }

    otrng_ec_point_destroy(manager->their_ecdh);
    /* @secret this will be deleted once received a new data message in a new
     * ratchet */
    if (!otrng_ecdh_keypair_generate_their(manager->their_ecdh,
                                           random_buffer)) {
      otrng_secure_free(random_buffer);
      return OTRNG_ERROR;
    }

    otrng_secure_free(random_buffer);

    gcry_mpi_release(manager->their_dh);
    manager->their_dh = NULL;

    /* @secret this will be deleted once received a new data message in a new
     * ratchet */
    if (!otrng_dh_keypair_generate_from_shared_secret(
            manager->shared_secret, &tmp_their_dh, participant)) {
      return OTRNG_ERROR;
    }

    manager->their_dh = tmp_their_dh.pub;
  }
  return OTRNG_SUCCESS;
}

tstatic otrng_result calculate_brace_key(
    key_manager_s *manager, receiving_ratchet_s *tmp_receiving_ratchet,
    const char action) {
  uint8_t usage_third_brace_key = 0x01;
  uint8_t usage_brace_key = 0x02;

  dh_shared_secret k_dh;
  size_t k_dh_len = 0;

  assert(action == 's' || action == 'r');
  if (action == 's') {
    if (manager->i % 3 == 0) {
      if (!otrng_dh_shared_secret(k_dh, &k_dh_len, manager->our_dh->priv,
                                  manager->their_dh)) {
        return OTRNG_ERROR;
      }
      if (!shake_256_kdf1(manager->brace_key, BRACE_KEY_BYTES,
                          usage_third_brace_key, k_dh, k_dh_len)) {
        return OTRNG_ERROR;
      }
    } else {
      if (!shake_256_kdf1(manager->brace_key, BRACE_KEY_BYTES, usage_brace_key,
                          manager->brace_key, BRACE_KEY_BYTES)) {
        return OTRNG_ERROR;
      }
    }
  } else if (action == 'r') {
    if (manager->i % 3 == 0) {
      // TODO: should take tmp too
      if (!otrng_dh_shared_secret(k_dh, &k_dh_len, manager->our_dh->priv,
                                  tmp_receiving_ratchet->their_dh)) {
        return OTRNG_ERROR;
      }
      if (!shake_256_kdf1(tmp_receiving_ratchet->brace_key, BRACE_KEY_BYTES,
                          usage_third_brace_key, k_dh, k_dh_len)) {
        return OTRNG_ERROR;
      }
    } else {
      if (!shake_256_kdf1(tmp_receiving_ratchet->brace_key, BRACE_KEY_BYTES,
                          usage_brace_key, manager->brace_key,
                          BRACE_KEY_BYTES)) {
        return OTRNG_ERROR;
      }
    }
  }
  otrng_secure_wipe(k_dh, DH3072_MOD_LEN_BYTES);

  return OTRNG_SUCCESS;
}

static uint8_t usage_shared_secret = 0x03;

tstatic otrng_result calculate_shared_secret(
    key_manager_s *manager, receiving_ratchet_s *tmp_receiving_ratchet,
    k_ecdh ecdh_key, const char action) {
  goldilocks_shake256_ctx_p hd;

  if (!hash_init_with_usage(hd, usage_shared_secret)) {
    return OTRNG_ERROR;
  }

  if (hash_update(hd, ecdh_key, ED448_POINT_BYTES) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    return OTRNG_ERROR;
  }

  assert(action == 's' || action == 'r');
  if (action == 's') {
    if (hash_update(hd, manager->brace_key, BRACE_KEY_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    hash_final(hd, manager->shared_secret, SHARED_SECRET_BYTES);
    hash_destroy(hd);

    otrng_secure_wipe(manager->brace_key, BRACE_KEY_BYTES);
  } else if (action == 'r') {
    if (hash_update(hd, tmp_receiving_ratchet->brace_key, BRACE_KEY_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    hash_final(hd, tmp_receiving_ratchet->shared_secret, SHARED_SECRET_BYTES);
    hash_destroy(hd);

    otrng_secure_wipe(tmp_receiving_ratchet->brace_key, BRACE_KEY_BYTES);
  }

  otrng_secure_wipe(ecdh_key, ED448_POINT_BYTES);
  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_key_manager_generate_shared_secret(
    key_manager_s *manager, const otrng_bool interactive) {

  if (interactive) {
    k_ecdh ecdh_key;

    if (!otrng_ecdh_shared_secret(ecdh_key, ED448_POINT_BYTES,
                                  manager->our_ecdh->priv,
                                  manager->their_ecdh)) {
      return OTRNG_ERROR;
    }

    otrng_secure_wipe(manager->our_ecdh->priv, sizeof(ec_scalar));

    if (!calculate_brace_key(manager, NULL, 's')) {
      return OTRNG_ERROR;
    }

    otrng_dh_priv_key_destroy(manager->our_dh);

    if (!calculate_shared_secret(manager, NULL, ecdh_key, 's')) {
      return OTRNG_ERROR;
    }

  } else if (!interactive) {
    if (!shake_256_kdf1(manager->shared_secret, SHARED_SECRET_BYTES,
                        usage_shared_secret, manager->tmp_key, HASH_BYTES)) {
      otrng_secure_wipe(manager->tmp_key, BRACE_KEY_BYTES);
      otrng_secure_wipe(manager->brace_key, BRACE_KEY_BYTES);
      return OTRNG_ERROR;
    }

    otrng_secure_wipe(manager->tmp_key, BRACE_KEY_BYTES);
    otrng_secure_wipe(manager->brace_key, BRACE_KEY_BYTES);
  }

  if (!calculate_ssid(manager)) {
    // TODO: wipe the keys?
    return OTRNG_ERROR;
  }

#ifdef DEBUG
  debug_print("\n");
  debug_print("THE SHARED SECRET\n");
  otrng_memdump(manager->shared_secret, SHARED_SECRET_BYTES);
  debug_print("THE SSID\n");
  otrng_memdump(manager->ssid, SSID_BYTES);
#endif

  if (gcry_mpi_cmp(manager->our_dh->pub, manager->their_dh) > 0) {
    manager->ssid_half_first = otrng_false;
  } else {
    manager->ssid_half_first = otrng_true;
  }

#ifdef DEBUG
  debug_print("\n");
  debug_print("THE SECURE SESSION ID\n");
  debug_print("ssid: \n");

  if (manager->ssid_half_first) {
    debug_print("the first 4 bytes = ");
    debug_print("0x");
    for (unsigned int i = 0; i < 4; i++) {
      debug_print("%x", manager->ssid[i]);
    }
  } else {
    debug_print("the last 4 bytes = ");
    debug_print("0x");
    for (unsigned int i = 4; i < 8; i++) {
      debug_print("%x", manager->ssid[i]);
    }
    debug_print("\n");
  }
#endif

  return OTRNG_SUCCESS;
}

tstatic otrng_result calculate_ssid(key_manager_s *manager) {
  uint8_t usage_SSID = 0x04;
  if (!shake_256_kdf1(manager->ssid, SSID_BYTES, usage_SSID,
                      manager->shared_secret, SHARED_SECRET_BYTES)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_key_manager_ratcheting_init(
    key_manager_s *manager, const char participant) {
  uint8_t usage_first_root_key = 0x0B;

  if (!generate_first_ephemeral_keys(manager, participant)) {
    return OTRNG_ERROR;
  }

  manager->i = 0;
  manager->j = 0;
  manager->k = 0;
  manager->pn = 0;

  if (!shake_256_kdf1(manager->current->root_key, ROOT_KEY_BYTES,
                      usage_first_root_key, manager->shared_secret,
                      SHARED_SECRET_BYTES)) {
    return OTRNG_ERROR;
  }

  otrng_secure_wipe(manager->shared_secret, SHARED_SECRET_BYTES);

  return OTRNG_SUCCESS;
}

tstatic otrng_result enter_new_ratchet(
    key_manager_s *manager, receiving_ratchet_s *tmp_receiving_ratchet,
    const char action) {
  k_ecdh ecdh_key;

  /* K_ecdh = ECDH(our_ecdh.secret, their_ecdh) */
  assert(action == 's' || action == 'r');
  if (action == 's') {
    if (!otrng_ecdh_shared_secret(ecdh_key, ED448_POINT_BYTES,
                                  manager->our_ecdh->priv,
                                  manager->their_ecdh)) {
      return OTRNG_ERROR;
    }
  } else if (action == 'r') {
    if (!otrng_ecdh_shared_secret(ecdh_key, ED448_POINT_BYTES,
                                  manager->our_ecdh->priv,
                                  tmp_receiving_ratchet->their_ecdh)) {
      return OTRNG_ERROR;
    }
  }

  /* if i % 3 == 0 : brace_key = KDF_1(usage_third_brace_key || k_dh, 32)
     else brace_key = KDF_1(usage_brace_key || brace_key, 32) */
  if (!calculate_brace_key(manager, tmp_receiving_ratchet, action)) {
    return OTRNG_ERROR;
  }

  /* K = KDF_1(usage_shared_secret || K_ecdh || brace_key, 64) */
  if (!calculate_shared_secret(manager, tmp_receiving_ratchet, ecdh_key,
                               action)) {
    return OTRNG_ERROR;
  }

#ifdef DEBUG
  debug_print("\n");
  debug_print("ENTERING NEW RATCHET\n");
  debug_print("K_ecdh = ");
  otrng_memdump(ecdh_key, ED448_POINT_BYTES);
  debug_print("brace_key = ");
  otrng_memdump(manager->brace_key, BRACE_KEY_BYTES);
  debug_print("THE SHARED SECRET\n");
  otrng_memdump(manager->shared_secret, SHARED_SECRET_BYTES);
#endif

  if (!key_manager_derive_ratchet_keys(manager, tmp_receiving_ratchet,
                                       action)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result rotate_keys(key_manager_s *manager,
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

tstatic otrng_result key_manager_derive_ratchet_keys(
    key_manager_s *manager, receiving_ratchet_s *tmp_receiving_ratchet,
    const char action) {
  /* root_key[i], chain_key_s[i][j] = derive_ratchet_keys(sending,
     root_key[i-1], K) root_key[i] = KDF_1(usage_root_key || root_key[i-1] || K,
     64)
     @secret should be deleted when the new root key is derived
  */
  uint8_t usage_root_key = 0x14;
  uint8_t usage_chain_key = 0x15;

  goldilocks_shake256_ctx_p hd;

  assert(action == 's' || action == 'r');

  /* chain_key_purpose[i][j] = KDF_1(usage_chain_key || root_key[i-1] || K, 64)
     @secret: should be deleted when the next chain key is derived
  */
  if (action == 's') {
    if (!hash_init_with_usage(hd, usage_root_key)) {
      return OTRNG_ERROR;
    }

    if (hash_update(hd, manager->current->root_key, ROOT_KEY_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    if (hash_update(hd, manager->shared_secret, SHARED_SECRET_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    hash_final(hd, manager->current->root_key, ROOT_KEY_BYTES);
    hash_destroy(hd);

    if (!hash_init_with_usage(hd, usage_chain_key)) {
      return OTRNG_ERROR;
    }

    if (hash_update(hd, manager->current->root_key, ROOT_KEY_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    if (hash_update(hd, manager->shared_secret, SHARED_SECRET_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    hash_final(hd, manager->current->chain_s, CHAIN_KEY_BYTES);

    otrng_secure_wipe(manager->shared_secret, SHARED_SECRET_BYTES);
  } else if (action == 'r') {
    if (!hash_init_with_usage(hd, usage_root_key)) {
      return OTRNG_ERROR;
    }

    if (hash_update(hd, tmp_receiving_ratchet->root_key, ROOT_KEY_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    if (hash_update(hd, tmp_receiving_ratchet->shared_secret,
                    SHARED_SECRET_BYTES) == GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    hash_final(hd, tmp_receiving_ratchet->root_key, ROOT_KEY_BYTES);
    hash_destroy(hd);

    if (!hash_init_with_usage(hd, usage_chain_key)) {
      return OTRNG_ERROR;
    }

    if (hash_update(hd, tmp_receiving_ratchet->root_key, ROOT_KEY_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    if (hash_update(hd, tmp_receiving_ratchet->shared_secret,
                    SHARED_SECRET_BYTES) == GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      return OTRNG_ERROR;
    }

    hash_final(hd, tmp_receiving_ratchet->chain_r, CHAIN_KEY_BYTES);

    otrng_secure_wipe(tmp_receiving_ratchet->shared_secret,
                      SHARED_SECRET_BYTES);
  }

  hash_destroy(hd);

#ifdef DEBUG
  debug_print("\n");
  debug_print("ROOT KEY = ");
  otrng_memdump(manager->current->root_key, ROOT_KEY_BYTES);
  /* debug_print("CHAIN_S = "); */
  /* otrng_memdump(ratchet->chain_s, CHAIN_KEY_BYTES); */
  /* debug_print("CHAIN_R = "); */
  /* otrng_memdump(ratchet->chain_r, CHAIN_KEY_BYTES); */
#endif

  return OTRNG_SUCCESS;
}

static uint8_t usage_next_chain_key = 0x16;
static uint8_t usage_message_key = 0x17;
static uint8_t usage_mac_key = 0x18;
static uint8_t usage_extra_symm_key = 0x19;

static otrng_result
derive_next_chain_key(key_manager_s *manager,
                      receiving_ratchet_s *tmp_receiving_ratchet,
                      const char action) {
  /* chain_key_s[i-1][j+1] = KDF_1(usage_next_chain_key || chain_key_s[i-1][j],
   * 64) */
  assert(action == 's' || action == 'r');
  if (action == 's') {
    if (!shake_256_kdf1(manager->current->chain_s, CHAIN_KEY_BYTES,
                        usage_next_chain_key, manager->current->chain_s,
                        CHAIN_KEY_BYTES)) {
      return OTRNG_ERROR;
    }

  } else if (action == 'r') {
    if (!shake_256_kdf1(tmp_receiving_ratchet->chain_r, CHAIN_KEY_BYTES,
                        usage_next_chain_key, tmp_receiving_ratchet->chain_r,
                        CHAIN_KEY_BYTES)) {
      return OTRNG_ERROR;
    }
  }

  return OTRNG_SUCCESS;
}

static otrng_result derive_encryption_and_mac_keys(
    k_msg_enc enc_key, k_msg_mac mac_key, key_manager_s *manager,
    receiving_ratchet_s *tmp_receiving_ratchet, const char action) {
  assert(action == 's' || action == 'r');

  /* MKenc, MKmac = derive_enc_mac_keys(chain_key_s[i-1][j])
     MKenc = KDF_1(usage_message_key || chain_key, 64)
     MKmac = KDF_1(usage_mac_key || MKenc, 64)
  */
  if (action == 's') {
    if (!shake_256_kdf1(enc_key, ENC_KEY_BYTES, usage_message_key,
                        manager->current->chain_s, CHAIN_KEY_BYTES)) {
      return OTRNG_ERROR;
    }
  } else if (action == 'r') {
    if (!shake_256_kdf1(enc_key, ENC_KEY_BYTES, usage_message_key,
                        tmp_receiving_ratchet->chain_r, CHAIN_KEY_BYTES)) {
      return OTRNG_ERROR;
    }
  }

  if (!shake_256_kdf1(mac_key, MAC_KEY_BYTES, usage_mac_key, enc_key,
                      ENC_KEY_BYTES)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic otrng_result calculate_extra_key(
    key_manager_s *manager, receiving_ratchet_s *tmp_receiving_ratchet,
    const char action) {
  goldilocks_shake256_ctx_p hd;
  uint8_t *extra_key_buffer = otrng_secure_alloc(EXTRA_SYMMETRIC_KEY_BYTES);
  uint8_t magic[1] = {0xFF};

  if (!hash_init_with_usage(hd, usage_extra_symm_key)) {
    otrng_secure_free(extra_key_buffer);
    return OTRNG_ERROR;
  }

  if (hash_update(hd, magic, 1) == GOLDILOCKS_FAILURE) {
    hash_destroy(hd);
    otrng_secure_free(extra_key_buffer);
    return OTRNG_ERROR;
  }

  /* extra_symm_key = KDF_1(usage_extra_symm_key || 0xFF || chain_key_s[i-1][j],
   * 64) */
  assert(action == 's' || action == 'r');
  if (action == 's') {
    if (hash_update(hd, manager->current->chain_s, CHAIN_KEY_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      otrng_secure_free(extra_key_buffer);
      return OTRNG_ERROR;
    }

    hash_final(hd, extra_key_buffer, EXTRA_SYMMETRIC_KEY_BYTES);
    hash_destroy(hd);

    memcpy(manager->extra_symmetric_key, extra_key_buffer,
           EXTRA_SYMMETRIC_KEY_BYTES);
  } else if (action == 'r') {
    if (hash_update(hd, tmp_receiving_ratchet->chain_r, CHAIN_KEY_BYTES) ==
        GOLDILOCKS_FAILURE) {
      hash_destroy(hd);
      otrng_secure_wipe(extra_key_buffer, EXTRA_SYMMETRIC_KEY_BYTES);
      otrng_free(extra_key_buffer);
      return OTRNG_ERROR;
    }

    hash_final(hd, extra_key_buffer, EXTRA_SYMMETRIC_KEY_BYTES);
    hash_destroy(hd);

    memcpy(tmp_receiving_ratchet->extra_symmetric_key, extra_key_buffer,
           EXTRA_SYMMETRIC_KEY_BYTES);
  }
  otrng_secure_free(extra_key_buffer);

// TODO: add to tmp
#ifdef DEBUG
  debug_print("\n");
  debug_print("EXTRA KEY = ");
  otrng_memdump(manager->extra_symmetric_key, EXTRA_SYMMETRIC_KEY_BYTES);
#endif

  return OTRNG_SUCCESS;
}

tstatic otrng_result store_enc_keys(
    k_msg_enc enc_key, receiving_ratchet_s *tmp_receiving_ratchet,
    const uint32_t until, const unsigned int max_skip, const char ratchet_type,
    const otrng_client_callbacks_s *cb, key_manager_s *manager) {
  goldilocks_shake256_ctx_p hd;
  uint8_t *extra_key = otrng_secure_alloc(EXTRA_SYMMETRIC_KEY_BYTES);
  uint8_t magic[1] = {0xFF};
  skipped_keys_s *skipped_msg_enc_key;

  if ((tmp_receiving_ratchet->k + max_skip) < until) {
    otrng_client_callbacks_handle_event(cb,
                                        OTRNG_MSG_EVENT_MSG_KEYS_STORAGE_FULL);

    otrng_secure_free(extra_key);
    return OTRNG_SUCCESS;
  }

  if (!otrng_bool_is_true(otrng_is_empty_array(tmp_receiving_ratchet->chain_r,
                                               CHAIN_KEY_BYTES))) {
    while (tmp_receiving_ratchet->k < until) {
      if (!shake_256_kdf1(enc_key, ENC_KEY_BYTES, usage_message_key,
                          tmp_receiving_ratchet->chain_r, CHAIN_KEY_BYTES)) {
        otrng_secure_free(extra_key);
        return OTRNG_ERROR;
      }

      if (!hash_init_with_usage(hd, usage_extra_symm_key)) {
        otrng_secure_free(extra_key);
        return OTRNG_ERROR;
      }

      if (hash_update(hd, magic, 1) == GOLDILOCKS_FAILURE) {
        hash_destroy(hd);
        otrng_secure_free(extra_key);
        return OTRNG_ERROR;
      }

      if (hash_update(hd, tmp_receiving_ratchet->chain_r, CHAIN_KEY_BYTES) ==
          GOLDILOCKS_FAILURE) {
        hash_destroy(hd);
        otrng_secure_free(extra_key);
        return OTRNG_ERROR;
      }

      hash_final(hd, extra_key, EXTRA_SYMMETRIC_KEY_BYTES);
      hash_destroy(hd);

      if (!shake_256_kdf1(tmp_receiving_ratchet->chain_r, CHAIN_KEY_BYTES,
                          usage_next_chain_key, tmp_receiving_ratchet->chain_r,
                          CHAIN_KEY_BYTES)) {
        otrng_secure_free(extra_key);
        return OTRNG_ERROR;
      }

      skipped_msg_enc_key = otrng_secure_alloc(sizeof(skipped_keys_s));

      assert(ratchet_type == 'd' || ratchet_type == 'c');

      if (ratchet_type == 'd') {
        otrng_ec_point_copy(skipped_msg_enc_key->their_ecdh,
                            manager->their_ecdh);
      } else if (ratchet_type == 'c') {
        otrng_ec_point_copy(skipped_msg_enc_key->their_ecdh,
                            tmp_receiving_ratchet->their_ecdh);
      }

      skipped_msg_enc_key->k = tmp_receiving_ratchet->k;

      memcpy(skipped_msg_enc_key->extra_symmetric_key, extra_key,
             EXTRA_SYMMETRIC_KEY_BYTES);
      memcpy(skipped_msg_enc_key->enc_key, enc_key, ENC_KEY_BYTES);

      /*
         @secret: should be deleted when:
         1. session expired
         2. the key is retrieved
      */
      tmp_receiving_ratchet->skipped_keys = otrng_list_add(
          skipped_msg_enc_key, tmp_receiving_ratchet->skipped_keys);
      otrng_secure_wipe(enc_key, ENC_KEY_BYTES);
      tmp_receiving_ratchet->k++;
    }
  }
  otrng_secure_free(extra_key);

  return OTRNG_SUCCESS;
}

/*
   MKenc, extra_symm_key = skipped_MKenc[ratchet_id, message_id]
   MKmac = KDF_1(usage_mac_key || MKenc, 64).
*/
INTERNAL otrng_result otrng_key_get_skipped_keys(
    k_msg_enc enc_key, k_msg_mac mac_key, ec_point msg_ecdh,
    unsigned int msg_id, key_manager_s *manager,
    receiving_ratchet_s *tmp_receiving_ratchet) {
  list_element_s *current = tmp_receiving_ratchet->skipped_keys;
  (void)manager;

  while (current) {
    skipped_keys_s *skipped_keys = current->data;

    if ((goldilocks_448_point_eq(msg_ecdh, skipped_keys->their_ecdh) ==
         GOLDILOCKS_TRUE) &&
        skipped_keys->k == msg_id) {
      memcpy(enc_key, skipped_keys->enc_key, ENC_KEY_BYTES);
      if (!shake_256_kdf1(mac_key, MAC_KEY_BYTES, usage_mac_key, enc_key,
                          ENC_KEY_BYTES)) {
        return OTRNG_ERROR;
      }

      memcpy(tmp_receiving_ratchet->extra_symmetric_key,
             skipped_keys->extra_symmetric_key, EXTRA_SYMMETRIC_KEY_BYTES);

      tmp_receiving_ratchet->skipped_keys = otrng_list_remove_element(
          current, tmp_receiving_ratchet->skipped_keys);
      otrng_list_free(current, otrng_secure_free);

      return OTRNG_SUCCESS;
    }

    current = current->next;
  }

  /* This is not an actual error, it is just that the key we need was not
  skipped */
  return OTRNG_ERROR;
}

INTERNAL otrng_result otrng_key_manager_derive_chain_keys(
    k_msg_enc enc_key, k_msg_mac mac_key, key_manager_s *manager,
    receiving_ratchet_s *tmp_receiving_ratchet, unsigned int max_skip,
    uint32_t msg_id, const char action, const otrng_client_callbacks_s *cb) {

  assert(action == 's' || action == 'r');
  if (action == 'r') {
    if (!store_enc_keys(enc_key, tmp_receiving_ratchet, msg_id, max_skip, 'c',
                        cb, manager)) {
      return OTRNG_ERROR;
    }
  }

  /* @secret should be deleted after being used to encrypt and mac the message
   */
  if (!derive_encryption_and_mac_keys(enc_key, mac_key, manager,
                                      tmp_receiving_ratchet, action)) {
    return OTRNG_ERROR;
  }

  if (!calculate_extra_key(manager, tmp_receiving_ratchet, action)) {
    return OTRNG_ERROR;
  }

  /* @secret should be deleted when the new chain key is derived */
  if (!derive_next_chain_key(manager, tmp_receiving_ratchet, action)) {
    return OTRNG_ERROR;
  }

#ifdef DEBUG
  debug_print("\n");
  debug_print("GOT SENDING KEYS:\n");
  debug_print("enc_key = ");
  otrng_memdump(enc_key, ENC_KEY_BYTES);
  debug_print("mac_key = ");
  otrng_memdump(mac_key, MAC_KEY_BYTES);
#endif

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_key_manager_derive_dh_ratchet_keys(
    key_manager_s *manager, unsigned int max_skip,
    receiving_ratchet_s *tmp_receiving_ratchet, ec_point msg_ecdh,
    uint32_t previous_n, const char action,
    const otrng_client_callbacks_s *cb) {
  /* Derive new ECDH and DH keys */
  k_msg_enc enc_key;

  assert(action == 's' || action == 'r');

  if (action == 's') {

    if (manager->j == 0) {
      return rotate_keys(manager, tmp_receiving_ratchet, action);
    }

  } else if (action == 'r') {
    if (goldilocks_448_point_eq(msg_ecdh, manager->their_ecdh) ==
        GOLDILOCKS_FALSE) {
      /* Store any message keys from the previous DH Ratchet */
      if (!store_enc_keys(enc_key, tmp_receiving_ratchet, previous_n, max_skip,
                          'd', cb, manager)) {
        return OTRNG_ERROR;
      }
      return rotate_keys(manager, tmp_receiving_ratchet, action);
    }
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_store_old_mac_keys(key_manager_s *manager,
                                               k_msg_mac mac_key) {
  uint8_t *to_store_mac = otrng_secure_alloc(MAC_KEY_BYTES);

  memcpy(to_store_mac, mac_key, ENC_KEY_BYTES);
  manager->old_mac_keys = otrng_list_add(to_store_mac, manager->old_mac_keys);

  return OTRNG_SUCCESS;
}

INTERNAL /*@null@*/ uint8_t *
otrng_reveal_mac_keys_on_tlv(key_manager_s *manager) {
  size_t num_stored_keys = otrng_list_len(manager->skipped_keys);
  size_t serlen = num_stored_keys * MAC_KEY_BYTES;
  uint8_t *ser_mac_keys;
  k_msg_mac mac_key;
  k_msg_enc enc_key;
  size_t i;

  if (serlen != 0) {
    ser_mac_keys = otrng_secure_alloc(serlen);

    memset(enc_key, 0, ENC_KEY_BYTES);
    memset(mac_key, 0, MAC_KEY_BYTES);

    for (i = 0; i < num_stored_keys; i++) {
      list_element_s *last = otrng_list_get_last(manager->skipped_keys);
      skipped_keys_s *skipped_keys = last->data;
      memcpy(enc_key, skipped_keys->enc_key, ENC_KEY_BYTES);

      if (!shake_256_kdf1(mac_key, MAC_KEY_BYTES, usage_mac_key, enc_key,
                          ENC_KEY_BYTES)) {
        otrng_secure_free(ser_mac_keys);
        return NULL;
      }

      memcpy(ser_mac_keys + i * MAC_KEY_BYTES, mac_key, MAC_KEY_BYTES);
      manager->skipped_keys =
          otrng_list_remove_element(last, manager->skipped_keys);
      otrng_list_free(last, otrng_secure_free);
    }
    otrng_list_free_nodes(manager->skipped_keys);

    return ser_mac_keys;
  }

  return NULL;
}
