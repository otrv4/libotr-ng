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

#include <glib.h>

#include "test_helpers.h"

#include "key_management.h"
#include "shake.h"

static void test_derive_ratchet_keys() {
  key_manager_s *manager = otrng_xmalloc_z(sizeof(key_manager_s));
  otrng_key_manager_init(manager);

  memset(manager->shared_secret, 0, sizeof(k_shared_secret));
  k_root root_key;
  memset(root_key, 0, sizeof(k_root));

  otrng_assert_is_success(key_manager_derive_ratchet_keys(manager, NULL, 's'));

  k_root expected_root_key;
  k_sending_chain expected_chain_key_s;

  uint8_t buff[1] = {0x14};
  uint8_t buff2[1] = {0x15};

  goldilocks_shake256_ctx_p hd;
  hash_init_with_dom(hd);
  hash_update(hd, buff, 1);
  hash_update(hd, root_key, sizeof(k_root));
  hash_update(hd, manager->shared_secret, sizeof(k_shared_secret));

  hash_final(hd, expected_root_key, sizeof(k_root));
  hash_destroy(hd);

  goldilocks_shake256_ctx_p hd2;
  hash_init_with_dom(hd2);
  hash_update(hd2, buff2, 1);
  hash_update(hd2, root_key, sizeof(k_root));
  hash_update(hd2, manager->shared_secret, sizeof(k_shared_secret));

  hash_final(hd2, expected_chain_key_s, sizeof(k_sending_chain));
  hash_destroy(hd2);

  otrng_key_manager_destroy(manager);
  otrng_free(manager);
}

static void test_calculate_ssid() {
  key_manager_s manager;
  otrng_key_manager_init(&manager);

  k_shared_secret s = {0};
  uint8_t expected_ssid[8] = {
      0x11, 0xee, 0xe5, 0xe1, 0xeb, 0x7e, 0x32, 0x0a,
  };

  memcpy(s, manager.shared_secret, sizeof(k_shared_secret));

  calculate_ssid(&manager);
  otrng_assert_cmpmem(expected_ssid, manager.ssid, 8);

  otrng_key_manager_destroy(&manager);
}

static void test_calculate_extra_symm_key() {
  key_manager_s manager;
  otrng_key_manager_init(&manager);

  k_shared_secret s = {0};
  uint8_t expected_extra_key[EXTRA_SYMMETRIC_KEY_BYTES] = {
      0xe9, 0xde, 0xb3, 0xf4, 0xb2, 0x51, 0x1c, 0x2e, 0xa7, 0x49, 0x70,
      0x22, 0x6b, 0xd4, 0xca, 0x04, 0xe5, 0x34, 0x83, 0x60, 0xe5, 0x32,
      0x34, 0x4b, 0xd7, 0xe8, 0x99, 0xd8, 0x43, 0xe9, 0x00, 0xd3, 0x29,
      0x07, 0xf7, 0x3b, 0xa8, 0x43, 0x3b, 0x91, 0x6c, 0x71, 0xe7, 0xa0,
      0x70, 0x9b, 0x86, 0xe7, 0x03, 0x99, 0xb3, 0xc4, 0xa3, 0xf5, 0xb6,
      0xf8, 0xa0, 0x3d, 0x01, 0xb4, 0x0a, 0xc4, 0xad, 0xd0,
  };

  memcpy(s, manager.current->chain_s, sizeof(k_sending_chain));

  calculate_extra_key(&manager, NULL, 's');
  otrng_assert_cmpmem(expected_extra_key, manager.extra_symmetric_key,
                      EXTRA_SYMMETRIC_KEY_BYTES);

  otrng_key_manager_destroy(&manager);
}

static void test_calculate_brace_key() {
  key_manager_s *manager = otrng_xmalloc_z(sizeof(key_manager_s));
  otrng_key_manager_init(manager);

  // Setup a fixed their_dh
  dh_mpi their_dh_secret = NULL;
  const uint8_t their_public[5] = {0x1};
  uint8_t secret[DH3072_MOD_LEN_BYTES] = {0};
  size_t secret_len = 0;

  otrng_assert_is_success(otrng_dh_mpi_deserialize(
      &their_dh_secret, their_public, sizeof their_public, NULL));
  otrng_assert_is_success(otrng_dh_shared_secret(
      secret, &secret_len, their_dh_secret, otrng_dh_mpi_generator()));
  otrng_dh_mpi_release(their_dh_secret);
  otrng_assert_is_success(
      otrng_dh_mpi_deserialize(&manager->their_dh, secret, secret_len, NULL));

  // Setup a fixed our_dh
  const uint8_t our_secret[5] = {0x2};
  manager->our_dh->pub = NULL;
  otrng_assert_is_success(
      otrng_dh_mpi_deserialize(&manager->our_dh->priv, our_secret, 5, NULL));

  uint8_t expected_brace_key[BRACE_KEY_BYTES] = {
      0x5e, 0xe5, 0x1a, 0xe4, 0x89, 0x84, 0x0d, 0xa5, 0x54, 0x82, 0x37,
      0x29, 0xdf, 0x0c, 0xca, 0xff, 0xdd, 0x6d, 0x0a, 0x10, 0x50, 0x79,
      0x5f, 0x0d, 0x45, 0x4f, 0x15, 0x4b, 0x71, 0x1f, 0xbc, 0x22,
  };

  // Calculate brace key from k_dh
  manager->i = 0;
  otrng_assert_is_success(calculate_brace_key(manager, NULL, 's'));
  otrng_assert_cmpmem(expected_brace_key, manager->brace_key, BRACE_KEY_BYTES);

  uint8_t expected_brace_key_2[BRACE_KEY_BYTES] = {
      0x8f, 0x2e, 0x2a, 0xae, 0x47, 0x55, 0x37, 0xf5, 0xcf, 0xfd, 0x6b,
      0x36, 0x3a, 0x50, 0x4d, 0xdc, 0xb9, 0xdc, 0xac, 0xf7, 0x5b, 0x3a,
      0x42, 0x4b, 0xfd, 0x4d, 0x84, 0xb8, 0x2f, 0xd9, 0xea, 0x5d,
  };

  // Calculate brace key from previous brace key
  manager->i = 1;
  otrng_assert_is_success(calculate_brace_key(manager, NULL, 's'));
  otrng_assert_cmpmem(expected_brace_key_2, manager->brace_key,
                      BRACE_KEY_BYTES);

  otrng_key_manager_destroy(manager);
  otrng_free(manager);
}

void units_key_management_add_tests(void) {
  g_test_add_func("/key_management/derive_ratchet_keys",
                  test_derive_ratchet_keys);
  g_test_add_func("/key_management/ssid", test_calculate_ssid);
  g_test_add_func("/key_management/extra_symm_key",
                  test_calculate_extra_symm_key);
  g_test_add_func("/key_management/brace_key", test_calculate_brace_key);
}
