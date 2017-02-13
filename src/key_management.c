#include <stdlib.h>
#include <string.h>

#include "ed448.h"
#include "gcrypt.h"
#include "key_management.h"

void
append_ratchet(key_manager_t manager, ratchet_t r){
  manager->current->next = r;
  manager->current = r;
}

void
key_manager_init(key_manager_t manager){
  manager->i = 0;
  manager->j = 0;
  manager->head = NULL;
  manager->current = NULL;
}

void
key_manager_destroy(key_manager_t manager) {
  //TODO: should walk all the hierarchy and free.
}

bool
derive_key_from_shared_secret(uint8_t *key, size_t keylen, const uint8_t magic[1], const shared_secret_t shared) {
  if (gcry_md_get_algo_dlen(GCRY_MD_SHA3_512) != keylen) {
    return false;
  }

  gcry_md_hd_t hd;
  gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
  gcry_md_write(hd, magic, 1);
  gcry_md_write(hd, shared, keylen);
  memcpy(key, gcry_md_read(hd, 0), keylen);
  gcry_md_close(hd);
  return true;
}

bool
derive_root_key(root_key_t root_key, const shared_secret_t shared) {
  uint8_t magic[1] = {0x1};
  return derive_key_from_shared_secret(root_key, sizeof(root_key_t), magic, shared);
}

bool
derive_chain_key_a(chain_key_t chain_key, const shared_secret_t shared) {
  uint8_t magic[1] = {0x2};
  return derive_key_from_shared_secret(chain_key, sizeof(chain_key_t), magic, shared);
}

bool
derive_chain_key_b(chain_key_t chain_key, const shared_secret_t shared) {
  uint8_t magic[1] = {0x3};
  return derive_key_from_shared_secret(chain_key, sizeof(chain_key_t), magic, shared);
}

bool
derive_ratchet_keys(ratchet_s *ratchet, const shared_secret_t shared)
{
  if (!derive_root_key(ratchet->root_key, shared)) {
    return false;
  }

  if (!derive_chain_key_a(ratchet->chain_key_a, shared)) {
    return false;
  }

  return derive_chain_key_b(ratchet->chain_key_b, shared);
}

bool
key_manager_init_ratchet(key_manager_t manager, const shared_secret_t shared) {
  ratchet_s *ratchet = malloc(sizeof(ratchet_s));
  if (ratchet == NULL)
    return false;

  if (!derive_ratchet_keys(ratchet, shared))
    return false;

  manager->head = ratchet;
  manager->current = ratchet;

  return true;
}
