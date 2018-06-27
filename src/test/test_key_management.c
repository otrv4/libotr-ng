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

void test_derive_ratchet_keys() {
  key_manager_s *manager = malloc(sizeof(key_manager_s));
  otrng_key_manager_init(manager);

  memset(manager->shared_secret, 0, sizeof(shared_secret_p));
  root_key_p root_key;
  memset(root_key, 0, sizeof root_key);

  key_manager_derive_ratchet_keys(manager, 's');

  root_key_p expected_root_key;
  sending_chain_key_p expected_chain_key_s;

  uint8_t buff[1] = {0x14};
  uint8_t buff2[1] = {0x15};

  goldilocks_shake256_ctx_p hd;
  hash_init_with_dom(hd);
  hash_update(hd, buff, 1);
  hash_update(hd, root_key, sizeof(root_key_p));
  hash_update(hd, manager->shared_secret, sizeof(shared_secret_p));

  hash_final(hd, expected_root_key, sizeof(root_key_p));
  hash_destroy(hd);

  goldilocks_shake256_ctx_p hd2;
  hash_init_with_dom(hd2);
  hash_update(hd2, buff2, 1);
  hash_update(hd2, root_key, sizeof(root_key_p));
  hash_update(hd2, manager->shared_secret, sizeof(shared_secret_p));

  hash_final(hd2, expected_chain_key_s, sizeof(sending_chain_key_p));
  hash_destroy(hd2);

  otrng_key_manager_destroy(manager);
  free(manager);
  manager = NULL;
}

void test_calculate_ssid() {
  key_manager_p manager;
  otrng_key_manager_init(manager);

  shared_secret_p s = {};
  uint8_t expected_ssid[8] = {
      0x78, 0x68, 0x17, 0x67, 0xfc, 0xf6, 0x72, 0x54,
  };

  memcpy(s, manager->shared_secret, sizeof(shared_secret_p));

  calculate_ssid(manager);
  otrng_assert_cmpmem(expected_ssid, manager->ssid, 8);

  otrng_key_manager_destroy(manager);
}

void test_calculate_extra_symm_key() {
  key_manager_p manager;
  otrng_key_manager_init(manager);

  shared_secret_p s = {};
  uint8_t expected_extra_key[EXTRA_SYMMETRIC_KEY_BYTES] = {
      0x65, 0x62, 0x04, 0x13, 0xc3, 0xf3, 0xa9, 0x37, 0x50, 0x59, 0x4e,
      0x97, 0xa6, 0xd6, 0xd1, 0x29, 0x9f, 0x6a, 0x6f, 0x83, 0xb6, 0x4d,
      0x29, 0x61, 0xaf, 0x87, 0x1c, 0xe5, 0xf4, 0xe6, 0xf9, 0x13,
  };

  memcpy(s, manager->current->chain_s, sizeof(sending_chain_key_p));

  calculate_extra_key(manager, 's');
  otrng_assert_cmpmem(expected_extra_key, manager->extra_symmetric_key,
                      EXTRA_SYMMETRIC_KEY_BYTES);

  otrng_key_manager_destroy(manager);
}

void test_calculate_brace_key() {
  key_manager_s *manager = malloc(sizeof(key_manager_s));
  otrng_key_manager_init(manager);

  // Setup a fixed their_dh
  dh_mpi_p their_dh_secret = NULL;
  const uint8_t their_public[5] = {0x1};
  uint8_t secret[DH3072_MOD_LEN_BYTES] = {};
  size_t secret_len = 0;

  otrng_assert_is_success(otrng_dh_mpi_deserialize(
      &their_dh_secret, their_public, sizeof their_public, NULL));
  otrng_assert_is_success(otrng_dh_shared_secret(
      secret, &secret_len, their_dh_secret, otrng_dh_mpi_generator()));
  otrng_dh_mpi_release(their_dh_secret);
  their_dh_secret = NULL;
  otrng_assert_is_success(
      otrng_dh_mpi_deserialize(&manager->their_dh, secret, secret_len, NULL));

  // Setup a fixed our_dh
  const uint8_t our_secret[5] = {0x2};
  manager->our_dh->pub = NULL;
  otrng_assert_is_success(
      otrng_dh_mpi_deserialize(&manager->our_dh->priv, our_secret, 5, NULL));

  uint8_t expected_brace_key[BRACE_KEY_BYTES] = {
      0xf9, 0xf1, 0x7f, 0xfd, 0x6c, 0x39, 0xe5, 0x30, 0x90, 0x83, 0xac,
      0xc7, 0xc6, 0x2f, 0x8f, 0xe4, 0xf2, 0xb3, 0xef, 0x1e, 0x5d, 0x50,
      0xd8, 0x20, 0xc0, 0x1c, 0x85, 0x3a, 0xcc, 0xb6, 0x81, 0x10,
  };

  // Calculate brace key from k_dh
  manager->i = 0;
  otrng_assert_is_success(calculate_brace_key(manager));
  otrng_assert_cmpmem(expected_brace_key, manager->brace_key, BRACE_KEY_BYTES);

  uint8_t expected_brace_key_2[BRACE_KEY_BYTES] = {
      0x69, 0xe8, 0xe3, 0x5b, 0x18, 0x9b, 0xbc, 0xc0, 0xbe, 0x07, 0xd7,
      0xba, 0xdf, 0x6b, 0x5b, 0xb0, 0xc3, 0x34, 0x5f, 0xdb, 0xc3, 0xda,
      0x35, 0x23, 0xa3, 0xab, 0x0f, 0x85, 0x0a, 0x35, 0x29, 0x87,
  };

  // Calculate brace key from previous brace key
  manager->i = 1;
  otrng_assert_is_success(calculate_brace_key(manager));
  otrng_assert_cmpmem(expected_brace_key_2, manager->brace_key,
                      BRACE_KEY_BYTES);

  otrng_key_manager_destroy(manager);
  free(manager);
  manager = NULL;
}
