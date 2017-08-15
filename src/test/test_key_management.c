#include "../key_management.h"

void create_sha3_512_buffer(shared_secret_t shared, gcry_md_hd_t *sha3_512, uint8_t *magic) {
  gcry_md_open(sha3_512, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
  gcry_md_write(*sha3_512, magic, 1);
  gcry_md_write(*sha3_512, shared, sizeof(shared_secret_t));
}

void test_derive_ratchet_keys() {
  key_manager_t *manager = malloc(sizeof(key_manager_t));
  key_manager_init(manager);

  shared_secret_t shared;
  memset(shared, 0, sizeof(shared_secret_t));

  otrv4_assert(key_manager_new_ratchet(manager, shared) == OTR4_SUCCESS);

  root_key_t expected_root_key;
  chain_key_t expected_chain_key_a;
  chain_key_t expected_chain_key_b;

  gcry_md_hd_t sha3_512;
  uint8_t magic[3] = {0x01, 0x02, 0x03};

  create_sha3_512_buffer(shared, &sha3_512, &magic[0]);
  memcpy(expected_root_key, gcry_md_read(sha3_512, 0), sizeof(root_key_t));
  gcry_md_close(sha3_512);
  create_sha3_512_buffer(shared, &sha3_512, &magic[1]);
  memcpy(expected_chain_key_a, gcry_md_read(sha3_512, 0), sizeof(chain_key_t));
  gcry_md_close(sha3_512);
  create_sha3_512_buffer(shared, &sha3_512, &magic[2]);
  memcpy(expected_chain_key_b, gcry_md_read(sha3_512, 0), sizeof(chain_key_t));
  gcry_md_close(sha3_512);

  otrv4_assert_cmpmem(expected_root_key, manager->current->root_key, sizeof(root_key_t));
  otrv4_assert_cmpmem(expected_chain_key_a, manager->current->chain_a->key, sizeof(chain_key_t));
  otrv4_assert_cmpmem(expected_chain_key_b, manager->current->chain_b->key, sizeof(chain_key_t));

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
  // TODO: destroy mix_key too?
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
