#include <stdlib.h>
#include <string.h>

#include "ed448.h"
#include "gcrypt.h"
#include "key_management.h"
#include "sha3.h"
#include "debug.h"

ratchet_t*
ratchet_new() {
  ratchet_t *ratchet = malloc(sizeof(ratchet_t));
  if (ratchet == NULL)
    return NULL;

  ratchet->id = 0;
  ratchet->chain_a->id = 0;
  ratchet->chain_a->next = NULL;
  ratchet->chain_b->id = 0;
  ratchet->chain_b->next = NULL;

  return ratchet;
}

void
ratchet_free(ratchet_t *ratchet) {
  //TODO: securely erase chain keys
  free(ratchet);
}

void
key_manager_init(key_manager_t manager){
  manager->i = 0;
  manager->j = 0;
  manager->current = NULL;
  manager->previous = NULL;
  manager->our_dh->pub = dh_mpi_new();
  manager->our_dh->priv = dh_mpi_new();
  manager->their_dh = dh_mpi_new();
}

void
key_manager_destroy(key_manager_t manager) {
  //TODO: should walk all the hierarchy and free.
  //TODO: Should call rat
  ratchet_free(manager->current);
  ratchet_free(manager->previous);

  dh_keypair_destroy(manager->our_dh);
  dh_mpi_release(manager->their_dh);
}

void
key_manager_generate_ephemeral_keys(key_manager_t manager) {
  ec_keypair_destroy(manager->our_ecdh);
  ec_keypair_generate(manager->our_ecdh);

  if (manager->i % 3 == 0) {
    dh_keypair_destroy(manager->our_dh);
    dh_keypair_generate(manager->our_dh);
  }
}

void
key_manager_set_their_keys(ec_public_key_t their_ecdh, dh_public_key_t their_dh, key_manager_t manager) {
  //TODO: Should we safely remove this?
  ec_public_key_copy(manager->their_ecdh, their_ecdh);
  dh_mpi_release(manager->their_dh);
  manager->their_dh = dh_mpi_copy(their_dh);
}

void
key_manager_prepare_to_ratchet(key_manager_t manager) {
  manager->j = 0;
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
key_manager_new_ratchet(key_manager_t manager, const shared_secret_t shared) {
  ratchet_t *ratchet = malloc(sizeof(ratchet_t));
  if (ratchet == NULL)
    return false;

  if (!derive_ratchet_keys(ratchet, shared))
    return false;

  ratchet_free(manager->previous);
  manager->previous = manager->current;

  ratchet->id = manager->i;
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

const chain_link_t*
chain_get_by_id(int message_id, const chain_link_t *head) {
  const chain_link_t *cursor = head;
  while (cursor->next && cursor->id != message_id)
    cursor = cursor->next;

  if (cursor->id == message_id) {
    return cursor;
  }

  return NULL;
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
  gcry_mpi_t their_mpi = gcry_mpi_new(nbits);

  if (gcry_mpi_scan(&our_mpi, GCRYMPI_FMT_USG, our, sizeof(ec_public_key_t), NULL)){
    gcry_mpi_release(our_mpi);
    gcry_mpi_release(their_mpi);
    return false;
  }

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
key_manager_get_sending_chain_key(chain_key_t sending, const key_manager_t manager) {
  message_chain_t *chain = decide_between_chain_keys(manager->current, manager->our_ecdh->pub, manager->their_ecdh);
  const chain_link_t *last = chain_get_last(chain->sending);
  memcpy(sending, last->key, sizeof(chain_key_t));
  free(chain);

  return last->id;
}

chain_link_t*
chain_link_new() {
  chain_link_t *l = malloc(sizeof(chain_link_t));
  if (l == NULL)
    return NULL;

  l->id = 0;
  l->next = NULL;

  return l;
}

chain_link_t*
derive_next_chain_link(chain_link_t *previous) {
  chain_link_t *l = chain_link_new();
  if (l == NULL)
    return NULL;

  if(!sha3_512(l->key, sizeof(chain_key_t), previous->key, sizeof(chain_key_t)))
    return NULL;

  //TODO: Securely delete previous->key

  l->id = previous->id+1;
  previous->next = l;
  return l;
}

bool
rebuild_chain_keys_up_to(int message_id, const chain_link_t *head) {
  chain_link_t* last = (chain_link_t*) chain_get_last(head);

  int j = 0;
  for (j = last->id; j <= message_id; j++) {
    last = derive_next_chain_link(last);
    if (last == NULL)
      return false;
  }

  return true;
}

bool
key_manager_get_receiving_chain_key_by_id(chain_key_t receiving, int ratchet_id, int message_id, const key_manager_t manager) {
  //TODO: Should we be able to receive messages from the previous ratchet?
  //TODO: This is a critical section to receiving messages out of order.
  ratchet_t *ratchet = NULL;
  if (manager->current != NULL && manager->current->id == ratchet_id) {
    ratchet = manager->current;
  } else if (manager->previous != NULL && manager->previous->id == ratchet_id) {
    ratchet = manager->previous;
  } else {
    return false; // ratchet id not found
  }

  message_chain_t *chain = decide_between_chain_keys(ratchet, manager->our_ecdh->pub, manager->their_ecdh);
  if (!rebuild_chain_keys_up_to(message_id, chain->receiving))
    return false;

  const chain_link_t *link = chain_get_by_id(message_id, chain->receiving);
  if (link == NULL) {
    //TODO: generate
    return false; //message id not found
  }
  memcpy(receiving, link->key, sizeof(chain_key_t));
  free(chain);

  return true;
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

bool
key_manager_derive_sending_chain_key(key_manager_t manager) {
  message_chain_t *chain = decide_between_chain_keys(manager->current, manager->our_ecdh->pub, manager->their_ecdh);
  chain_link_t *last = (chain_link_t*) chain_get_last(chain->sending);

  chain_link_t *l = derive_next_chain_link(last);
  if (l == NULL)
    return false;

  //TODO: assert l->id == manager->j

  return true;
}

bool
enter_new_ratchet(key_manager_t manager) {
  k_ecdh_t k_ecdh;
  if (!ecdh_shared_secret(k_ecdh, sizeof(k_ecdh_t), manager->our_ecdh, manager->their_ecdh)) {
    return false;
  }

  //TODO: Securely delete our_ecdh.secret.

  if (manager->i % 3 == 0) {
    k_dh_t k_dh;
    if (!dh_shared_secret(k_dh, sizeof(k_dh_t), manager->our_dh->priv, manager->their_dh)) {
      return false;
    }

    //TODO: Securely delete our_dh.secret

    if (!sha3_256(manager->mix_key, sizeof(mix_key_t), k_dh, sizeof(k_dh_t))) {
      return false;
    }
  } else {
    if (!sha3_256(manager->mix_key, sizeof(mix_key_t), manager->mix_key, sizeof(mix_key_t))) {
      return false;
    }
  }

#ifdef DEBUG
  printf("ENTERING NEW RATCHET\n");
  printf("K_ecdh = ");
  otrv4_memdump(k_ecdh, sizeof(k_ecdh_t));
  printf("mixed_key = ");
  otrv4_memdump(manager->mix_key, sizeof(mix_key_t));
#endif

  shared_secret_t shared;
  if (!calculate_shared_secret(shared, k_ecdh, manager->mix_key)) {
    return false;
  }

  // TODO: Securely delete the root key and all chain keys from the ratchet i-2.
  // TODO: Securely delete shared.
  return key_manager_new_ratchet(manager, shared);
}

bool
key_manager_ratchetting_init(int j, key_manager_t manager) {
  if (!enter_new_ratchet(manager))
    return false;

  manager->i = 0;
  manager->j = j;
  return true;
}

bool
key_manager_rotate_keys(key_manager_t manager) {
  manager->i++;
  manager->j = 0;

  key_manager_generate_ephemeral_keys(manager);
  return enter_new_ratchet(manager);
}

bool
key_manager_ensure_on_ratchet(int ratchet_id, key_manager_t manager) {
  if (manager->i == ratchet_id)
    return true;

  //TODO: FININISH
  manager->i = ratchet_id;
  if (!enter_new_ratchet(manager))
    return false;

  return true;
}

