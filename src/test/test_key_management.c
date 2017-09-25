#include "../key_management.h"

void test_derive_ratchet_keys() {
  key_manager_t *manager = malloc(sizeof(key_manager_t));
  key_manager_init(manager);

  shared_secret_t shared;
  memset(shared, 0, sizeof(shared_secret_t));

  otrv4_assert(key_manager_new_ratchet(manager, shared) == OTR4_SUCCESS);

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

  otrv4_assert_cmpmem(expected_root_key, manager->current->root_key,
                      sizeof(root_key_t));
  otrv4_assert_cmpmem(expected_chain_key_a, manager->current->chain_a->key,
                      sizeof(chain_key_t));
  otrv4_assert_cmpmem(expected_chain_key_b, manager->current->chain_b->key,
                      sizeof(chain_key_t));

  key_manager_destroy(manager);
  free(manager);
}

void test_key_manager_destroy() {
  OTR4_INIT;

  key_manager_t *manager = malloc(sizeof(key_manager_t));
  key_manager_init(manager);

  shared_secret_t shared;
  memset(shared, 0, sizeof(shared_secret_t));

  otrv4_assert(key_manager_new_ratchet(manager, shared) == OTR4_SUCCESS);

  otrv4_assert(manager->current);
  otrv4_assert(manager->our_dh->priv);
  otrv4_assert(manager->our_dh->pub);
  otrv4_assert(manager->their_dh);
  // TODO: destroy brace_key too?
  // TODO: test destroy ecdh keys?

  key_manager_destroy(manager);

  otrv4_assert(!manager->current);
  otrv4_assert(!manager->our_dh->priv);
  otrv4_assert(!manager->our_dh->pub);
  otrv4_assert(!manager->their_dh);

  free(manager);
  manager = NULL;

  OTR4_FREE;
}
