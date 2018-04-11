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
  key_manager_t *manager = malloc(sizeof(key_manager_t));
  otrng_key_manager_init(manager);

  shared_secret_t shared;
  memset(shared, 0, sizeof shared);

  otrng_assert(manager->i == 0);
  otrng_assert(key_manager_new_ratchet(manager, shared) == SUCCESS);

  root_key_t expected_root_key;
  chain_key_t expected_chain_key_a;
  chain_key_t expected_chain_key_b;

  uint8_t magic[3] = {0x01, 0x02, 0x03};

  shake_256_kdf(expected_root_key, sizeof(root_key_t), &magic[0], shared,
                sizeof(shared_secret_t));
  shake_256_kdf(expected_chain_key_a, sizeof(chain_key_t), &magic[1], shared,
                sizeof(shared_secret_t));
  shake_256_kdf(expected_chain_key_b, sizeof(chain_key_t), &magic[2], shared,
                sizeof(shared_secret_t));

  otrng_assert_cmpmem(expected_root_key, manager->current->root_key,
                      sizeof(root_key_t));
  otrng_assert_cmpmem(expected_chain_key_a, manager->current->chain_a->key,
                      sizeof(chain_key_t));
  otrng_assert_cmpmem(expected_chain_key_b, manager->current->chain_b->key,
                      sizeof(chain_key_t));

  shared_secret_t root_shared;
  shake_kkdf(root_shared, sizeof(shared_secret_t), manager->current->root_key,
             sizeof(root_key_t), shared, sizeof(shared_secret_t));
  shake_256_kdf(expected_root_key, sizeof(root_key_t), &magic[0], root_shared,
                sizeof(shared_secret_t));
  shake_256_kdf(expected_chain_key_a, sizeof(chain_key_t), &magic[1],
                root_shared, sizeof(shared_secret_t));
  shake_256_kdf(expected_chain_key_b, sizeof(chain_key_t), &magic[2],
                root_shared, sizeof(shared_secret_t));

  manager->i = 1;
  otrng_assert(key_manager_new_ratchet(manager, shared) == SUCCESS);

  otrng_assert_cmpmem(expected_root_key, manager->current->root_key,
                      sizeof(root_key_t));
  otrng_assert_cmpmem(expected_chain_key_a, manager->current->chain_a->key,
                      sizeof(chain_key_t));
  otrng_assert_cmpmem(expected_chain_key_b, manager->current->chain_b->key,
                      sizeof(chain_key_t));

  otrng_key_manager_destroy(manager);
  free(manager);
  manager = NULL;
}

void test_otrng_key_manager_destroy() {

  key_manager_t *manager = malloc(sizeof(key_manager_t));
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
