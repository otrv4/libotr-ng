#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#include "key_management.h"
#include "random.h"
#include "shake.h"

#include "debug.h"

void chain_link_free(chain_link_t *head) {
  chain_link_t *current = head;
  chain_link_t *next = NULL;
  while (current) {
    next = current->next;

    sodium_memzero(current->key, sizeof(chain_key_t));
    free(current);

    current = next;
  }
}

ratchet_t *ratchet_new() {
  ratchet_t *ratchet = malloc(sizeof(ratchet_t));
  if (!ratchet)
    return NULL;

  memset(ratchet->root_key, 0, sizeof(root_key_t));

  ratchet->chain_a->id = 0;
  memset(ratchet->chain_a->key, 0, sizeof(chain_key_t));
  ratchet->chain_a->next = NULL;

  ratchet->chain_b->id = 0;
  memset(ratchet->chain_b->key, 0, sizeof(chain_key_t));
  ratchet->chain_b->next = NULL;

  return ratchet;
}

void ratchet_free(ratchet_t *ratchet) {
  if (!ratchet)
    return;

  sodium_memzero(ratchet->root_key, sizeof(root_key_t));

  chain_link_free(ratchet->chain_a->next);
  ratchet->chain_a->next = NULL;

  chain_link_free(ratchet->chain_b->next);
  ratchet->chain_b->next = NULL;

  free(ratchet);
  ratchet = NULL;
}

void key_manager_init(key_manager_t *manager) // make like ratchet_new?
{
  ec_bzero(manager->our_ecdh->pub, ED448_POINT_BYTES);
  manager->our_dh->pub = NULL;
  manager->our_dh->priv = NULL;

  ec_bzero(manager->their_ecdh, ED448_POINT_BYTES);
  manager->their_dh = NULL;

  ec_bzero(manager->their_shared_prekey, ED448_POINT_BYTES);
  ec_bzero(manager->our_shared_prekey, ED448_POINT_BYTES);

  manager->i = 0;
  manager->j = 0;

  manager->current = ratchet_new();

  memset(manager->brace_key, 0, sizeof(manager->brace_key));
  memset(manager->ssid, 0, sizeof(manager->ssid));
  memset(manager->extra_key, 0, sizeof(manager->extra_key));
  memset(manager->tmp_key, 0, sizeof(manager->tmp_key));

  manager->old_mac_keys = NULL;
}

void key_manager_destroy(key_manager_t *manager) {
  ecdh_keypair_destroy(manager->our_ecdh);
  dh_keypair_destroy(manager->our_dh);

  ec_point_destroy(manager->their_ecdh);

  gcry_mpi_release(manager->their_dh);
  manager->their_dh = NULL;

  ratchet_free(manager->current);
  manager->current = NULL;

  sodium_memzero(manager->their_shared_prekey, ED448_POINT_BYTES);
  sodium_memzero(manager->our_shared_prekey, ED448_POINT_BYTES);

  sodium_memzero(manager->brace_key, sizeof(manager->brace_key));
  sodium_memzero(manager->ssid, sizeof(manager->ssid));
  sodium_memzero(manager->extra_key, sizeof(manager->extra_key));
  sodium_memzero(manager->tmp_key, sizeof(manager->tmp_key));

  list_element_t *el;
  for (el = manager->old_mac_keys; el; el = el->next) {
    free((uint8_t *)el->data);
    el->data = NULL;
  }

  list_free_full(manager->old_mac_keys);
  manager->old_mac_keys = NULL;
}

otrv4_err_t key_manager_generate_ephemeral_keys(key_manager_t *manager) {
  uint8_t sym[ED448_PRIVATE_BYTES];
  memset(sym, 0, sizeof(sym));
  random_bytes(sym, ED448_PRIVATE_BYTES);

  ec_point_destroy(manager->our_ecdh->pub);
  ecdh_keypair_generate(manager->our_ecdh, sym);

  if (manager->i % 3 == 0) {
    dh_keypair_destroy(manager->our_dh);

    if (dh_keypair_generate(manager->our_dh)) {
      return OTR4_ERROR;
    }
  }

  return OTR4_SUCCESS;
}

void key_manager_set_their_keys(ec_point_t their_ecdh, dh_public_key_t their_dh,
                                key_manager_t *manager) {
  ec_point_destroy(manager->their_ecdh);
  ec_point_copy(manager->their_ecdh, their_ecdh);
  dh_mpi_release(manager->their_dh);
  manager->their_dh = dh_mpi_copy(their_dh);
}

void key_manager_prepare_to_ratchet(key_manager_t *manager) { manager->j = 0; }

void derive_key_from_shared_secret(uint8_t *key, size_t keylen,
                                   const uint8_t magic[1],
                                   const shared_secret_t shared) {
  shake_256_kdf(key, keylen, magic, shared, sizeof(shared_secret_t));
}

void derive_root_key(root_key_t root_key, const shared_secret_t shared) {
  uint8_t magic[1] = {0x1};
  derive_key_from_shared_secret(root_key, sizeof(root_key_t), magic, shared);
}

void derive_chain_key_a(chain_key_t chain_key, const shared_secret_t shared) {
  uint8_t magic[1] = {0x2};
  derive_key_from_shared_secret(chain_key, sizeof(chain_key_t), magic, shared);
}

void derive_chain_key_b(chain_key_t chain_key, const shared_secret_t shared) {
  uint8_t magic[1] = {0x3};
  derive_key_from_shared_secret(chain_key, sizeof(chain_key_t), magic, shared);
}

otrv4_err_t key_manager_new_ratchet(key_manager_t *manager,
                                    const shared_secret_t shared) {
  ratchet_t *ratchet = ratchet_new();
  if (ratchet == NULL) {
    return OTR4_ERROR;
  }
  if (manager->i == 0) {
    derive_root_key(ratchet->root_key, shared);
    derive_chain_key_a(ratchet->chain_a->key, shared);
    derive_chain_key_b(ratchet->chain_b->key, shared);
  } else {
    shared_secret_t root_shared;
    shake_kkdf(root_shared, sizeof(shared_secret_t), manager->current->root_key,
               sizeof(root_key_t), shared, sizeof(shared_secret_t));
    derive_root_key(ratchet->root_key, root_shared);
    derive_chain_key_a(ratchet->chain_a->key, root_shared);
    derive_chain_key_b(ratchet->chain_b->key, root_shared);
  }

  ratchet_free(manager->current);
  manager->current = ratchet;

  return OTR4_SUCCESS;
}

const chain_link_t *chain_get_last(const chain_link_t *head) {
  const chain_link_t *cursor = head;
  while (cursor->next)
    cursor = cursor->next;

  return cursor;
}

const chain_link_t *chain_get_by_id(int message_id, const chain_link_t *head) {
  const chain_link_t *cursor = head;
  while (cursor->next && cursor->id != message_id)
    cursor = cursor->next;

  if (cursor->id == message_id) {
    return cursor;
  }

  return NULL;
}

message_chain_t *decide_between_chain_keys(const ratchet_t *ratchet,
                                           const ec_point_t our,
                                           const ec_point_t their) {
  message_chain_t *ret = malloc(sizeof(message_chain_t));
  if (ret == NULL)
    return NULL;

  ret->sending = NULL;
  ret->receiving = NULL;

  gcry_mpi_t our_mpi = NULL;
  gcry_mpi_t their_mpi = NULL;
  if (gcry_mpi_scan(&our_mpi, GCRYMPI_FMT_USG, our, sizeof(ec_public_key_t),
                    NULL)) {
    gcry_mpi_release(our_mpi);
    gcry_mpi_release(their_mpi);
    return NULL;
  }

  if (gcry_mpi_scan(&their_mpi, GCRYMPI_FMT_USG, their, sizeof(ec_public_key_t),
                    NULL)) {
    gcry_mpi_release(our_mpi);
    gcry_mpi_release(their_mpi);
    return NULL;
  }

  int cmp = gcry_mpi_cmp(our_mpi, their_mpi);
  if (cmp > 0) {
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

int key_manager_get_sending_chain_key(chain_key_t sending,
                                      const key_manager_t *manager) {
  message_chain_t *chain = decide_between_chain_keys(
      manager->current, manager->our_ecdh->pub, manager->their_ecdh);
  const chain_link_t *last = chain_get_last(chain->sending);
  memcpy(sending, last->key, sizeof(chain_key_t));
  free(chain);
  chain = NULL;

  return last->id;
}

chain_link_t *chain_link_new() {
  chain_link_t *l = malloc(sizeof(chain_link_t));
  if (l == NULL)
    return NULL;

  l->id = 0;
  l->next = NULL;

  return l;
}

chain_link_t *derive_next_chain_link(chain_link_t *previous) {
  chain_link_t *l = chain_link_new();
  if (l == NULL)
    return NULL;

  hash_hash(l->key, sizeof(chain_key_t), previous->key, sizeof(chain_key_t));

  sodium_memzero(previous->key, CHAIN_KEY_BYTES);

  l->id = previous->id + 1;
  previous->next = l;
  return l;
}

otrv4_err_t rebuild_chain_keys_up_to(int message_id, const chain_link_t *head) {
  chain_link_t *last = (chain_link_t *)chain_get_last(head);

  int j = 0;
  for (j = last->id; j < message_id; j++) {
    last = derive_next_chain_link(last);
    if (last == NULL)
      return OTR4_ERROR;
  }

  return OTR4_SUCCESS;
}

otrv4_err_t key_manager_get_receiving_chain_key(chain_key_t receiving,
                                                int message_id,
                                                const key_manager_t *manager) {

  message_chain_t *chain = decide_between_chain_keys(
      manager->current, manager->our_ecdh->pub, manager->their_ecdh);
  if (rebuild_chain_keys_up_to(message_id, chain->receiving) == OTR4_ERROR) {
    free(chain);
    chain = NULL;
    return OTR4_ERROR;
  }

  const chain_link_t *link = chain_get_by_id(message_id, chain->receiving);
  free(chain);
  chain = NULL;

  if (link == NULL)
    return OTR4_ERROR; /* message id not found. Should have been generated at
                        rebuild_chain_keys_up_to */

  memcpy(receiving, link->key, sizeof(chain_key_t));

  return OTR4_SUCCESS;
}

void ecdh_shared_secret_from_prekey(uint8_t *shared,
                                    otrv4_shared_prekey_pair_t *shared_prekey,
                                    const ec_point_t their_pub) {
  decaf_448_point_t s;
  decaf_448_point_scalarmul(s, their_pub, shared_prekey->priv);

  ec_point_serialize(shared, s);
}

void ecdh_shared_secret_from_keypair(uint8_t *shared, otrv4_keypair_t *keypair,
                                     const ec_point_t their_pub) {
  decaf_448_point_t s;
  decaf_448_point_scalarmul(s, their_pub, keypair->priv);

  ec_point_serialize(shared, s);
}

void calculate_shared_secret(shared_secret_t dst, const k_ecdh_t k_ecdh,
                             const brace_key_t brace_key) {
  decaf_shake256_ctx_t hd;

  hash_init_with_dom(hd);
  hash_update(hd, k_ecdh, sizeof(k_ecdh_t));
  hash_update(hd, brace_key, sizeof(brace_key_t));

  hash_final(hd, dst, sizeof(shared_secret_t));
  hash_destroy(hd);
}

void calculate_shared_secret_from_tmp_key(shared_secret_t dst,
                                          const uint8_t *tmp_k) {
  decaf_shake256_ctx_t hd;

  hash_init_with_dom(hd);
  hash_update(hd, tmp_k, HASH_BYTES);

  hash_final(hd, dst, sizeof(shared_secret_t));
  hash_destroy(hd);
}

static otrv4_err_t derive_sending_chain_key(key_manager_t *manager) {
  message_chain_t *chain = decide_between_chain_keys(
      manager->current, manager->our_ecdh->pub, manager->their_ecdh);
  chain_link_t *last = (chain_link_t *)chain_get_last(chain->sending);
  free(chain);
  chain = NULL;

  chain_link_t *l = derive_next_chain_link(last);
  if (l == NULL)
    return OTR4_ERROR;

  // TODO: assert l->id == manager->j
  return OTR4_SUCCESS;
}

static void calculate_ssid(key_manager_t *manager,
                           const shared_secret_t shared) {
  uint8_t magic[1] = {0x00};
  uint8_t ssid_buff[32];

  shake_256_kdf(ssid_buff, sizeof ssid_buff, magic, shared,
                sizeof(shared_secret_t));

  memcpy(manager->ssid, ssid_buff, sizeof manager->ssid);
}

static void calculate_extra_key(key_manager_t *manager,
                                const chain_key_t chain_key) {
  uint8_t magic[1] = {0xFF};
  uint8_t extra_key_buff[HASH_BYTES];

  shake_256_kdf(extra_key_buff, HASH_BYTES, magic, chain_key,
                sizeof(chain_key_t));

  memcpy(manager->extra_key, extra_key_buff, sizeof manager->extra_key);
}

static otrv4_err_t calculate_brace_key(key_manager_t *manager) {
  k_dh_t k_dh;

  if (manager->i % 3 == 0) {
    if (dh_shared_secret(k_dh, sizeof(k_dh_t), manager->our_dh->priv,
                         manager->their_dh) == OTR4_ERROR)
      return OTR4_ERROR;

    hash_hash(manager->brace_key, sizeof(brace_key_t), k_dh, sizeof(k_dh_t));

  } else {
    hash_hash(manager->brace_key, sizeof(brace_key_t), manager->brace_key,
              sizeof(brace_key_t));
  }

  return OTR4_SUCCESS;
}

static otrv4_err_t enter_new_ratchet(key_manager_t *manager) {
  k_ecdh_t k_ecdh;
  shared_secret_t shared;

  ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);

  if (calculate_brace_key(manager) == OTR4_ERROR)
    return OTR4_ERROR;

  calculate_shared_secret(shared, k_ecdh, manager->brace_key);

#ifdef DEBUG
  printf("ENTERING NEW RATCHET\n");
  printf("K_ecdh = ");
  otrv4_memdump(k_ecdh, sizeof(k_ecdh_t));
  printf("brace_key = ");
  otrv4_memdump(manager->brace_key, sizeof(brace_key_t));
#endif

  if (key_manager_new_ratchet(manager, shared) == OTR4_ERROR) {
    sodium_memzero(shared, SHARED_SECRET_BYTES);
    sodium_memzero(manager->ssid, sizeof(manager->ssid));
    sodium_memzero(manager->extra_key, sizeof(manager->extra_key));
    return OTR4_ERROR;
  }

  sodium_memzero(shared, SHARED_SECRET_BYTES);
  return OTR4_SUCCESS;
}

static otrv4_err_t init_ratchet(key_manager_t *manager, bool interactive) {
  k_ecdh_t k_ecdh;
  shared_secret_t shared;

  ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);

  if (calculate_brace_key(manager) == OTR4_ERROR)
    return OTR4_ERROR;

  if (interactive)
    calculate_shared_secret(shared, k_ecdh, manager->brace_key);
  else
    calculate_shared_secret_from_tmp_key(shared, manager->tmp_key);

#ifdef DEBUG
  printf("ENTERING NEW RATCHET\n");
  printf("K_ecdh = ");
  otrv4_memdump(k_ecdh, sizeof(k_ecdh_t));
  printf("mixed_key = ");
  otrv4_memdump(manager->brace_key, sizeof(brace_key_t));
#endif

  calculate_ssid(manager, shared);

#ifdef DEBUG
  printf("THE SECURE SESSION ID\n");
  printf("ssid: \n");
  printf("the first 32 = ");
  for (unsigned int i = 0; i < 4; i++) {
    printf("0x%08x ", manager->ssid[i]);
  }
  printf("\n");
  printf("the last 32 = ");
  for (unsigned int i = 4; i < 8; i++) {
    printf("0x%08x ", manager->ssid[i]);
  }
  printf("\n");
#endif

  if (key_manager_new_ratchet(manager, shared) == OTR4_ERROR) {
    sodium_memzero(shared, SHARED_SECRET_BYTES);
    sodium_memzero(manager->ssid, sizeof(manager->ssid));
    sodium_memzero(manager->extra_key, sizeof(manager->extra_key));
    sodium_memzero(manager->tmp_key, sizeof(manager->tmp_key));
    return OTR4_ERROR;
  }

  sodium_memzero(shared, SHARED_SECRET_BYTES);
  /* tmp_k is no longer needed */
  sodium_memzero(manager->tmp_key, HASH_BYTES);

  return OTR4_SUCCESS;
}

otrv4_err_t key_manager_ratcheting_init(int j, bool interactive,
                                        key_manager_t *manager) {
  if (init_ratchet(manager, interactive))
    return OTR4_ERROR;

  manager->i = 0;
  manager->j = j;
  return OTR4_SUCCESS;
}

static otrv4_err_t rotate_keys(key_manager_t *manager) {
  manager->i++;
  manager->j = 0;

  if (key_manager_generate_ephemeral_keys(manager))
    return OTR4_ERROR;

  return enter_new_ratchet(manager);
}

otrv4_err_t key_manager_ensure_on_ratchet(key_manager_t *manager) {
  if (manager->j == 0)
    return OTR4_SUCCESS;

  manager->i++;
  if (enter_new_ratchet(manager))
    return OTR4_ERROR;

  // Securely delete priv keys as no longer needed
  ec_scalar_destroy(manager->our_ecdh->priv);
  if (manager->i % 3 == 0) {
    dh_priv_key_destroy(manager->our_dh);
  }

  return OTR4_SUCCESS;
}

static void derive_encryption_and_mac_keys(m_enc_key_t enc_key,
                                           m_mac_key_t mac_key,
                                           const chain_key_t chain_key) {
  uint8_t magic1[1] = {0x1};
  uint8_t magic2[1] = {0x2};

  shake_256_kdf(enc_key, sizeof(m_enc_key_t), magic1, chain_key,
                sizeof(chain_key_t));
  shake_256_kdf(mac_key, sizeof(m_mac_key_t), magic2, chain_key,
                sizeof(chain_key_t));
}

otrv4_err_t
key_manager_retrieve_receiving_message_keys(m_enc_key_t enc_key,
                                            m_mac_key_t mac_key, int message_id,
                                            key_manager_t *manager) {
  chain_key_t receiving;

  if (key_manager_get_receiving_chain_key(receiving, message_id, manager) ==
      OTR4_ERROR)
    return OTR4_ERROR;

  derive_encryption_and_mac_keys(enc_key, mac_key, receiving);
  calculate_extra_key(manager, receiving);

#ifdef DEBUG
  printf("GOT SENDING KEYS:\n");
  printf("receiving enc_key = ");
  otrv4_memdump(enc_key, sizeof(m_enc_key_t));
  printf("receiving mac_key = ");
  otrv4_memdump(mac_key, sizeof(m_mac_key_t));
#endif

  return OTR4_SUCCESS;
}

static otrv4_bool_t should_ratchet(const key_manager_t *manager) {
  if (manager->j == 0)
    return otrv4_true;

  return otrv4_false;
}

otrv4_err_t key_manager_prepare_next_chain_key(key_manager_t *manager) {
  if (should_ratchet(manager) == otrv4_true) {
    return rotate_keys(manager);
  }

  return derive_sending_chain_key(manager);
}

otrv4_err_t key_manager_retrieve_sending_message_keys(m_enc_key_t enc_key,
                                                      m_mac_key_t mac_key,
                                                      key_manager_t *manager) {
  chain_key_t sending;
  int message_id = key_manager_get_sending_chain_key(sending, manager);

  derive_encryption_and_mac_keys(enc_key, mac_key, sending);
  calculate_extra_key(manager, sending);

#ifdef DEBUG
  printf("GOT SENDING KEYS:\n");
  printf("sending enc_key = ");
  otrv4_memdump(enc_key, sizeof(m_enc_key_t));
  printf("sending mac_key = ");
  otrv4_memdump(mac_key, sizeof(m_mac_key_t));
#endif

  if (message_id == manager->j) {
    return OTR4_SUCCESS;
  }

  sodium_memzero(enc_key, sizeof(m_enc_key_t));
  sodium_memzero(mac_key, sizeof(m_mac_key_t));
  return OTR4_ERROR;
}

uint8_t *key_manager_old_mac_keys_serialize(list_element_t *old_mac_keys) {
  uint num_mac_keys = list_len(old_mac_keys);
  size_t serlen = num_mac_keys * MAC_KEY_BYTES;
  if (serlen == 0) {
    return NULL;
  }

  uint8_t *ser_mac_keys = malloc(serlen);
  if (!ser_mac_keys) {
    return NULL;
  }

  for (unsigned int i = 0; i < num_mac_keys; i++) {
    list_element_t *last = list_get_last(old_mac_keys);
    memcpy(ser_mac_keys + i * MAC_KEY_BYTES, last->data, MAC_KEY_BYTES);
    old_mac_keys = list_remove_element(last, old_mac_keys);
    list_free_full(last);
  }

  list_free_nodes(old_mac_keys);

  return ser_mac_keys;
}
