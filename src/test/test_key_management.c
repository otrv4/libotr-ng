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

  otrng_assert(key_manager_derive_ratchet_keys(manager, OTRNG_SENDING) ==
               SUCCESS);

  root_key_p expected_root_key;
  sending_chain_key_p expected_chain_key_s;

  uint8_t buff[1] = {0x15};
  uint8_t buff2[1] = {0x16};

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
      0xe4, 0x15, 0xc7, 0xa7, 0x96, 0x7c, 0xb1, 0x0f,
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
      0xbb, 0x21, 0x75, 0x61, 0x3d, 0xf1, 0x99, 0x97, 0x51, 0x0e, 0xca,
      0x72, 0x5f, 0x60, 0x8f, 0x65, 0xe5, 0x7f, 0x3c, 0xc9, 0x20, 0x80,
      0xa5, 0x91, 0xf0, 0x7d, 0xfa, 0x21, 0xf6, 0x0b, 0x88, 0x7f,
  };

  memcpy(s, manager->current->chain_s, sizeof(sending_chain_key_p));

  calculate_extra_key(manager, OTRNG_SENDING);
  otrng_assert_cmpmem(expected_extra_key, manager->extra_symmetric_key,
                      EXTRA_SYMMETRIC_KEY_BYTES);

  otrng_key_manager_destroy(manager);
}

void test_calculate_brace_key() {
  key_manager_s *manager = malloc(sizeof(key_manager_s));
  otrng_key_manager_init(manager);

  // Setup a fixed their_dh
  dh_mpi_p their_dh_secret = NULL;
  const uint8_t their_secret[5] = {0x1};
  uint8_t their_public[DH3072_MOD_LEN_BYTES] = {};

  otrng_assert(otrng_dh_mpi_deserialize(&their_dh_secret, their_secret,
                                        sizeof their_secret, NULL) == SUCCESS);
  otrng_assert(otrng_dh_shared_secret(their_public, DH3072_MOD_LEN_BYTES,
                                      their_dh_secret,
                                      otrng_dh_mpi_generator()) == SUCCESS);
  otrng_dh_mpi_release(their_dh_secret);
  their_dh_secret = NULL;
  otrng_assert(otrng_dh_mpi_deserialize(&manager->their_dh, their_public,
                                        DH3072_MOD_LEN_BYTES, NULL) == SUCCESS);

  // Setup a fixed our_dh
  const uint8_t our_secret[5] = {0x2};
  manager->our_dh->pub = NULL;
  otrng_assert(otrng_dh_mpi_deserialize(&manager->our_dh->priv, our_secret, 5,
                                        NULL) == SUCCESS);

  uint8_t expected_brace_key[BRACE_KEY_BYTES] = {
      0xf8, 0x95, 0x39, 0x90, 0x33, 0x38, 0x5a, 0x4d, 0xf8, 0xba, 0x9a,
      0x47, 0xe7, 0x4b, 0xe7, 0xe0, 0x7d, 0x2c, 0xe4, 0x83, 0x58, 0x67,
      0x7b, 0x94, 0xfe, 0xcd, 0x6f, 0x2c, 0x0f, 0xa5, 0x6f, 0x2f,

  };

  // Calculate brace key from k_dh
  manager->i = 0;
  otrng_assert(calculate_brace_key(manager) == SUCCESS);
  otrng_assert_cmpmem(expected_brace_key, manager->brace_key, BRACE_KEY_BYTES);

  uint8_t expected_brace_key_2[BRACE_KEY_BYTES] = {
      0xc1, 0xef, 0x72, 0x03, 0x4a, 0x38, 0xf4, 0xc5, 0x10, 0xb3, 0x05,
      0xf5, 0x05, 0x18, 0x0c, 0xf2, 0xf9, 0x6c, 0xa0, 0xb4, 0x6d, 0xff,
      0xc7, 0xa4, 0x4f, 0x45, 0x5c, 0xaf, 0x06, 0x91, 0xf2, 0x6e,
  };

  // Calculate brace key from previous brace key
  manager->i = 1;
  otrng_assert(calculate_brace_key(manager) == SUCCESS);
  otrng_assert_cmpmem(expected_brace_key_2, manager->brace_key,
                      BRACE_KEY_BYTES);

  otrng_key_manager_destroy(manager);
  free(manager);
  manager = NULL;
}
