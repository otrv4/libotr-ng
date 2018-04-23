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

#include "../key_management.h"

// TODO: just tests sending
void test_derive_ratchet_keys() {
  key_manager_s *manager = malloc(sizeof(key_manager_s));
  otrng_key_manager_init(manager);

  shared_secret_p shared_secret;
  memset(shared_secret, 0, sizeof shared_secret);
  root_key_p root_key;
  memset(root_key, 0, sizeof root_key);

  otrng_assert(manager->i == 0);
  otrng_assert(key_manager_new_ratchet(manager, shared_secret, true) ==
               SUCCESS);

  root_key_p expected_root_key;
  chain_key_p expected_chain_key_s;

  uint8_t buff[1] = {0x21};

  goldilocks_shake256_ctx_p hd;
  hash_init_with_dom(hd);
  hash_update(hd, buff, 1);
  hash_update(hd, root_key, sizeof(root_key_p));
  hash_update(hd, shared_secret, sizeof(shared_secret_p));

  hash_final(hd, expected_root_key, sizeof(root_key_p));
  hash_destroy(hd);

  uint8_t buff_2[1] = {0x22};

  goldilocks_shake256_ctx_p hd_2;
  hash_init_with_dom(hd_2);
  hash_update(hd_2, buff_2, 1);
  hash_update(hd_2, root_key, sizeof(root_key_p));
  hash_update(hd_2, shared_secret, sizeof(shared_secret_p));

  hash_final(hd_2, expected_chain_key_s, sizeof(chain_key_p));
  hash_destroy(hd_2);

  otrng_assert_cmpmem(expected_root_key, manager->current->root_key,
                      sizeof(root_key_p));
  otrng_assert_cmpmem(expected_chain_key_s, manager->current->chain_s,
                      sizeof(chain_key_p));

  otrng_key_manager_destroy(manager);
  free(manager);
  manager = NULL;
}

void test_otrng_key_manager_destroy() {

  key_manager_s *manager = malloc(sizeof(key_manager_s));
  otrng_key_manager_init(manager);

  // Populate values
  otrng_assert(otrng_key_manager_generate_ephemeral_keys(manager) == SUCCESS);
  memset(manager->their_ecdh, 1, sizeof(manager->their_ecdh));
  manager->their_dh = gcry_mpi_new(DH3072_MOD_LEN_BITS);
  memset(manager->brace_key, 1, sizeof(manager->brace_key));

  otrng_assert(manager->current);
  otrng_assert(manager->our_dh->priv);
  otrng_assert(manager->our_dh->pub);
  otrng_assert(manager->their_dh);
  otrng_assert_not_zero(manager->our_ecdh->priv, ED448_SCALAR_BYTES);
  otrng_assert_not_zero(manager->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_not_zero(manager->their_ecdh, ED448_POINT_BYTES);
  otrng_assert_not_zero(manager->brace_key, BRACE_KEY_BYTES);

  otrng_key_manager_destroy(manager);

  otrng_assert(!manager->current);
  otrng_assert(!manager->our_dh->priv);
  otrng_assert(!manager->our_dh->pub);
  otrng_assert(!manager->their_dh);
  otrng_assert_zero(manager->our_ecdh->priv, ED448_SCALAR_BYTES);
  otrng_assert_zero(manager->our_ecdh->pub, ED448_POINT_BYTES);
  otrng_assert_zero(manager->their_ecdh, ED448_POINT_BYTES);
  otrng_assert_zero(manager->brace_key, BRACE_KEY_BYTES);

  free(manager);
  manager = NULL;
}

void test_calculate_ssid() {
  key_manager_p manager;
  otrng_key_manager_init(manager);

  shared_secret_p s = {};
  uint8_t expected_ssid[8] = {
      0xe4, 0x15, 0xc7, 0xa7, 0x96, 0x7c, 0xb1, 0x0f,
  };

  memcpy(s, manager->shared_secret, sizeof(shared_secret_p));

  calculate_ssid(manager);
  otrng_assert_cmpmem(expected_ssid, manager->ssid, 8);

  otrng_key_manager_destroy(manager);
}

void test_calculate_brace_key() {
  key_manager_p manager;
  otrng_key_manager_init(manager);

  // Setup a fixed their_dh
  dh_mpi_p their_dh_secret = NULL;
  const uint8_t their_secret[5] = {0x1, 0x0, 0x0, 0x0, 0x0};
  uint8_t their_public[DH3072_MOD_LEN_BYTES] = {0};
  otrng_assert(SUCCESS == otrng_dh_mpi_deserialize(&their_dh_secret,
                                                   their_secret, 5, NULL));
  otrng_assert(SUCCESS == otrng_dh_shared_secret(
                              their_public, DH3072_MOD_LEN_BYTES,
                              their_dh_secret, otrng_dh_mpi_generator()));
  otrng_dh_mpi_release(their_dh_secret);
  their_dh_secret = NULL;
  otrng_assert(SUCCESS == otrng_dh_mpi_deserialize(&manager->their_dh,
                                                   their_public,
                                                   DH3072_MOD_LEN_BYTES, NULL));

  // Setup a fixed our_dh
  const uint8_t our_secret[5] = {0x2, 0x0, 0x0, 0x0, 0x0};
  manager->our_dh->pub = NULL;
  otrng_assert(SUCCESS == otrng_dh_mpi_deserialize(&manager->our_dh->priv,
                                                   our_secret, 5, NULL));

  uint8_t expected_brace_key_from_K_dh[BRACE_KEY_BYTES] = {
      0xf8, 0x95, 0x39, 0x90, 0x33, 0x38, 0x5a, 0x4d, 0xf8, 0xba, 0x9a,
      0x47, 0xe7, 0x4b, 0xe7, 0xe0, 0x7d, 0x2c, 0xe4, 0x83, 0x58, 0x67,
      0x7b, 0x94, 0xfe, 0xcd, 0x6f, 0x2c, 0x0f, 0xa5, 0x6f, 0x2f,

  };

  // Calculates shared secret and brace key
  manager->i = 0;
  otrng_assert(SUCCESS == calculate_brace_key(manager));
  otrng_assert_cmpmem(expected_brace_key_from_K_dh, manager->brace_key,
                      BRACE_KEY_BYTES);

  uint8_t expected_brace_key_from_previous_brace_key[BRACE_KEY_BYTES] = {
      0xc1, 0xef, 0x72, 0x03, 0x4a, 0x38, 0xf4, 0xc5, 0x10, 0xb3, 0x05,
      0xf5, 0x05, 0x18, 0x0c, 0xf2, 0xf9, 0x6c, 0xa0, 0xb4, 0x6d, 0xff,
      0xc7, 0xa4, 0x4f, 0x45, 0x5c, 0xaf, 0x06, 0x91, 0xf2, 0x6e,
  };

  // Calculates brace key only
  manager->i = 1;
  otrng_assert(SUCCESS == calculate_brace_key(manager));
  otrng_assert_cmpmem(expected_brace_key_from_previous_brace_key,
                      manager->brace_key, BRACE_KEY_BYTES);

  otrng_key_manager_destroy(manager);
}
