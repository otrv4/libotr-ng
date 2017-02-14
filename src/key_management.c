#include <stdlib.h>
#include <string.h>

#include "ed448.h"
#include "gcrypt.h"
#include "key_management.h"

void
key_manager_init(key_manager_t manager){
  manager->i = 0;
  manager->j = 0;
  manager->current = NULL;
  manager->previous = NULL;
}

void
key_manager_destroy(key_manager_t manager) {
  //TODO: should walk all the hierarchy and free.
}

bool
sha3_kkdf(int algo, uint8_t *dst, size_t dstlen, const uint8_t *key, size_t keylen, const uint8_t *secret, size_t secretlen) {
  if (gcry_md_get_algo_dlen(algo) != dstlen) {
    return false;
  }

  gcry_md_hd_t hd;
  gcry_md_open(&hd, algo, GCRY_MD_FLAG_SECURE);
  gcry_md_write(hd, key, keylen);
  gcry_md_write(hd, secret, secretlen);
  memcpy(dst, gcry_md_read(hd, 0), dstlen);
  gcry_md_close(hd);
  return true;
}

bool
sha3_512_mac(uint8_t *dst, size_t dstlen, const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen) {
  return sha3_kkdf(GCRY_MD_SHA3_512, dst, dstlen, key, keylen, msg, msglen);
}

bool
sha3_256_kdf(uint8_t *key, size_t keylen, const uint8_t magic[1], const uint8_t *secret, size_t secretlen) {
  return sha3_kkdf(GCRY_MD_SHA3_256, key, keylen, magic, 1, secret, secretlen);
}

bool
sha3_512_kdf(uint8_t *key, size_t keylen, const uint8_t magic[1], const uint8_t *secret, size_t secretlen) {
  return sha3_kkdf(GCRY_MD_SHA3_512, key, keylen, magic, 1, secret, secretlen);
}

bool
derive_key_from_shared_secret(uint8_t *key, size_t keylen, const uint8_t magic[1], const shared_secret_t shared) {
  return sha3_512_kdf(key, keylen, magic, shared, sizeof(shared_secret_t));
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
derive_ratchet_keys(ratchet_t *ratchet, const shared_secret_t shared)
{
  if (!derive_root_key(ratchet->root_key, shared)) {
    return false;
  }

  if (!derive_chain_key_a(ratchet->chain_a->key, shared)) {
    return false;
  }

  return derive_chain_key_b(ratchet->chain_b->key, shared);
}

bool
key_manager_init_ratchet(key_manager_t manager, const shared_secret_t shared) {
  ratchet_t *ratchet = malloc(sizeof(ratchet_t));
  if (ratchet == NULL)
    return false;

  if (!derive_ratchet_keys(ratchet, shared))
    return false;

  manager->current = ratchet;

  return true;
}

const chain_link_t*
chain_get_last(const chain_link_t *head) {
  const chain_link_t *cursor = head;
  while (cursor->next)
    cursor = cursor->next;

  return cursor;
}

message_chain_t*
decide_between_chain_keys(const ratchet_t *ratchet, const ec_public_key_t our, const ec_public_key_t their) {
  message_chain_t* ret = malloc(sizeof(message_chain_t));
  if (ret == NULL)
    return NULL;

  ret->sending = NULL;
  ret->receiving = NULL;

  size_t nbits = sizeof(ec_public_key_t);
  gcry_mpi_t our_mpi = gcry_mpi_new(nbits);
  if (gcry_mpi_scan(&our_mpi, GCRYMPI_FMT_USG, our, sizeof(ec_public_key_t), NULL)){
    gcry_mpi_release(our_mpi);
    return false;
  }

  gcry_mpi_t their_mpi = gcry_mpi_new(nbits);
  if (gcry_mpi_scan(&their_mpi, GCRYMPI_FMT_USG, their, sizeof(ec_public_key_t), NULL)){
    gcry_mpi_release(our_mpi);
    gcry_mpi_release(their_mpi);
    return false;
  }

  int cmp = gcry_mpi_cmp(our_mpi, their_mpi);
  if (cmp > 0 ) {
    ret->sending = ratchet->chain_a;
    ret->receiving = ratchet->chain_b;
  } else if (cmp < 0) {
    ret->sending = ratchet->chain_b;
    ret->receiving = ratchet->chain_a;
  }

  gcry_mpi_release(our_mpi);
  gcry_mpi_release(their_mpi);

  return ret;
}

int
key_manager_get_sending_chain_key(chain_key_t sending, const key_manager_t manager, const ec_public_key_t our_ecdh, const ec_public_key_t their_ecdh) {
  message_chain_t *chain = decide_between_chain_keys(manager->current, our_ecdh, their_ecdh);
  const chain_link_t *last = chain_get_last(chain->sending);
  memcpy(sending, last->key, sizeof(chain)); 
  free(chain);

  return last->id;
}

bool
calculate_shared_secret(shared_secret_t dst, const k_ecdh_t k_ecdh, const mix_key_t mix_key) {
  if (gcry_md_get_algo_dlen(GCRY_MD_SHA3_512) != sizeof(shared_secret_t)) {
    return false;
  }

  gcry_md_hd_t hd;
  if (gcry_md_open(&hd, GCRY_MD_SHA3_512, 0)) {
    return false;
  }

  gcry_md_write(hd, k_ecdh, sizeof(k_ecdh_t));
  gcry_md_write(hd, mix_key, sizeof(mix_key_t));
  memcpy(dst, gcry_md_read(hd, GCRY_MD_SHA3_512), sizeof(shared_secret_t));
  gcry_md_close(hd);

  return true;
}

