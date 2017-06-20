#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "debug.h"
#include "ed448.h"
#include "gcrypt.h"
#include "key_management.h"
#include "random.h"
#include "sha3.h"

ratchet_t *ratchet_new() {
  ratchet_t *ratchet = malloc(sizeof(ratchet_t));
  if (!ratchet)
    return NULL;

  ratchet->id = 0;
  ratchet->chain_a->id = 0;
  ratchet->chain_a->next = NULL;
  ratchet->chain_b->id = 0;
  ratchet->chain_b->next = NULL;

  return ratchet;
}

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

void ratchet_free(ratchet_t *ratchet) {
  if (!ratchet)
    return;

  sodium_memzero(ratchet->root_key, sizeof(root_key_t));

  chain_link_free(ratchet->chain_a->next);
  ratchet->chain_a->next = NULL;

  chain_link_free(ratchet->chain_b->next);
  ratchet->chain_b->next = NULL;

  free(ratchet);
}

void key_manager_init(key_manager_t *manager) // make like ratchet_new?
{
  manager->i = 0;
  manager->j = 0;
  manager->current = NULL;
  manager->previous = NULL;
  manager->our_dh->pub = NULL;
  manager->our_dh->priv = NULL;
  manager->their_dh = NULL;
  manager->old_mac_keys = NULL;
}

void key_manager_destroy(key_manager_t *manager) {
  list_element_t *el;
  for (el = manager->old_mac_keys; el; el = el->next) {
    free((uint8_t *)el->data);
    el->data = NULL;
  }

  ratchet_free(manager->previous);
  manager->previous = NULL;

  ratchet_free(manager->current);
  manager->current = NULL;

  dh_keypair_destroy(manager->our_dh);

  dh_mpi_release(manager->their_dh);
  manager->their_dh = NULL;

  ecdh_keypair_destroy(manager->our_ecdh);
  ec_point_destroy(manager->their_ecdh);

  list_free_full(manager->old_mac_keys);
  manager->old_mac_keys = NULL;
}

otr4_err_t key_manager_generate_ephemeral_keys(key_manager_t *manager) {
  // TODO: securely erase memory
  uint8_t sym[ED448_PRIVATE_BYTES];
  random_bytes(sym, ED448_PRIVATE_BYTES);

  ecdh_keypair_destroy(manager->our_ecdh);
  ecdh_keypair_generate(manager->our_ecdh, sym);

  if (manager->i % 3 == 0) {
    dh_pub_key_destroy(manager->our_dh);
    if (dh_keypair_generate(manager->our_dh))
      return OTR4_ERROR;

    return OTR4_SUCCESS;
  }
  return OTR4_SUCCESS;
}

void key_manager_set_their_keys(ec_point_t their_ecdh, dh_public_key_t their_dh,
                                key_manager_t *manager) {
  // TODO: Should we safely remove the previous point?
  ec_point_copy(manager->their_ecdh, their_ecdh);
  dh_mpi_release(manager->their_dh);
  manager->their_dh = dh_mpi_copy(their_dh);
}

void key_manager_prepare_to_ratchet(key_manager_t *manager) { manager->j = 0; }

bool derive_key_from_shared_secret(uint8_t *key, size_t keylen,
                                   const uint8_t magic[1],
                                   const shared_secret_t shared) {
  return sha3_512_kdf(key, keylen, magic, shared, sizeof(shared_secret_t));
}

bool derive_root_key(root_key_t root_key, const shared_secret_t shared) {
  uint8_t magic[1] = {0x1};
  return derive_key_from_shared_secret(root_key, sizeof(root_key_t), magic,
                                       shared);
}

bool derive_chain_key_a(chain_key_t chain_key, const shared_secret_t shared) {
  uint8_t magic[1] = {0x2};
  return derive_key_from_shared_secret(chain_key, sizeof(chain_key_t), magic,
                                       shared);
}

bool derive_chain_key_b(chain_key_t chain_key, const shared_secret_t shared) {
  uint8_t magic[1] = {0x3};
  return derive_key_from_shared_secret(chain_key, sizeof(chain_key_t), magic,
                                       shared);
}

otr4_err_t derive_ratchet_keys(ratchet_t *ratchet,
                               const shared_secret_t shared) {
  if (!derive_root_key(ratchet->root_key, shared)) {
    return OTR4_ERROR;
  }

  if (!derive_chain_key_a(ratchet->chain_a->key, shared)) {
    return OTR4_ERROR;
  }

  if (!derive_chain_key_b(ratchet->chain_b->key, shared)) {
    return OTR4_ERROR;
  }
  return OTR4_SUCCESS;
}

otr4_err_t key_manager_new_ratchet(key_manager_t *manager,
                                   const shared_secret_t shared) {
  ratchet_t *ratchet = ratchet_new();
  if (ratchet == NULL)
    return OTR4_ERROR;

  if (derive_ratchet_keys(ratchet, shared))
    return OTR4_ERROR;

  ratchet_free(manager->previous);
  manager->previous = manager->current;

  ratchet->id = manager->i;
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
    return false;
  }

  if (gcry_mpi_scan(&their_mpi, GCRYMPI_FMT_USG, their, sizeof(ec_public_key_t),
                    NULL)) {
    gcry_mpi_release(our_mpi);
    gcry_mpi_release(their_mpi);
    return false;
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

  if (!sha3_512(l->key, sizeof(chain_key_t), previous->key,
                sizeof(chain_key_t)))
    return NULL;

  // TODO: Securely delete previous->key

  l->id = previous->id + 1;
  previous->next = l;
  return l;
}

bool rebuild_chain_keys_up_to(int message_id, const chain_link_t *head) {
  chain_link_t *last = (chain_link_t *)chain_get_last(head);

  int j = 0;
  for (j = last->id; j < message_id; j++) {
    last = derive_next_chain_link(last);
    if (last == NULL)
      return false;
  }

  return true;
}

otr4_err_t
key_manager_get_receiving_chain_key_by_id(chain_key_t receiving, int ratchet_id,
                                          int message_id,
                                          const key_manager_t *manager) {
  // TODO: Should we be able to receive messages from the previous ratchet?
  // TODO: This is a critical section to receiving messages out of order.
  ratchet_t *ratchet = NULL;
  if (manager->current != NULL && manager->current->id == ratchet_id) {
    ratchet = manager->current;
  } else if (manager->previous != NULL && manager->previous->id == ratchet_id) {
    ratchet = manager->previous;
  } else {
    return OTR4_ERROR; // ratchet id not found
  }

  message_chain_t *chain = decide_between_chain_keys(
      ratchet, manager->our_ecdh->pub, manager->their_ecdh);
  if (!rebuild_chain_keys_up_to(message_id, chain->receiving)) {
    free(chain);
    return OTR4_ERROR;
  }

  const chain_link_t *link = chain_get_by_id(message_id, chain->receiving);
  free(chain);
  if (link == NULL)
    return OTR4_ERROR; // message id not found. Should have been generated at
                       // rebuild_chain_keys_up_to

  memcpy(receiving, link->key, sizeof(chain_key_t));

  return OTR4_SUCCESS;
}

otr4_err_t calculate_shared_secret(shared_secret_t dst, const k_ecdh_t k_ecdh,
                                   const mix_key_t mix_key) {
  if (gcry_md_get_algo_dlen(GCRY_MD_SHA3_512) != sizeof(shared_secret_t)) {
    return OTR4_ERROR;
  }

  gcry_md_hd_t hd;
  if (gcry_md_open(&hd, GCRY_MD_SHA3_512, 0)) {
    return OTR4_ERROR;
  }

  gcry_md_write(hd, k_ecdh, sizeof(k_ecdh_t));
  gcry_md_write(hd, mix_key, sizeof(mix_key_t));
  memcpy(dst, gcry_md_read(hd, GCRY_MD_SHA3_512), sizeof(shared_secret_t));
  gcry_md_close(hd);

  return OTR4_SUCCESS;
}

static otr4_err_t derive_sending_chain_key(key_manager_t *manager) {
  message_chain_t *chain = decide_between_chain_keys(
      manager->current, manager->our_ecdh->pub, manager->their_ecdh);
  chain_link_t *last = (chain_link_t *)chain_get_last(chain->sending);
  free(chain);

  chain_link_t *l = derive_next_chain_link(last);
  if (l == NULL)
    return OTR4_ERROR;

  // TODO: assert l->id == manager->j
  return OTR4_SUCCESS;
}

static otr4_err_t calculate_ssid(const shared_secret_t shared,
                                 key_manager_t *manager) {
  uint8_t ssid_buff[32];
  if (!sha3_256(ssid_buff, sizeof(ssid_buff), shared, sizeof(shared_secret_t)))
    return OTR4_ERROR;

  memcpy(manager->ssid, ssid_buff, sizeof(manager->ssid));

  return OTR4_SUCCESS;
}

static otr4_err_t calculate_mix_key(key_manager_t *manager) {
  k_dh_t k_dh;

  if (manager->i % 3 == 0) {
    otr4_err_t err = dh_shared_secret(k_dh, sizeof(k_dh_t),
                                      manager->our_dh->priv, manager->their_dh);

    if (err)
      return err;

    // TODO: Securely delete our_dh.secret

    if (!sha3_256(manager->mix_key, sizeof(mix_key_t), k_dh, sizeof(k_dh_t)))
      return OTR4_ERROR;

  } else {
    if (!sha3_256(manager->mix_key, sizeof(mix_key_t), manager->mix_key,
                  sizeof(mix_key_t)))
      return OTR4_ERROR;
  }

  return OTR4_SUCCESS;
}

static otr4_err_t enter_new_ratchet(key_manager_t *manager) {
  k_ecdh_t k_ecdh;
  shared_secret_t shared;

  if (ecdh_shared_secret(k_ecdh, sizeof(k_ecdh_t), manager->our_ecdh,
                         manager->their_ecdh))
    return OTR4_ERROR;
  // TODO: Securely delete our_ecdh.secret.

  otr4_err_t err = calculate_mix_key(manager);
  if (err)
    return err;

  err = calculate_shared_secret(shared, k_ecdh, manager->mix_key);
  if (err)
    return err;

#ifdef DEBUG
  printf("ENTERING NEW RATCHET\n");
  printf("K_ecdh = ");
  otrv4_memdump(k_ecdh, sizeof(k_ecdh_t));
  printf("mixed_key = ");
  otrv4_memdump(manager->mix_key, sizeof(mix_key_t));
#endif

  // TODO: Securely delete shared.
  err = calculate_ssid(shared, manager);
  if (err)
    return err;

  return key_manager_new_ratchet(manager, shared);
}

otr4_err_t key_manager_ratchetting_init(int j, key_manager_t *manager) {
  if (enter_new_ratchet(manager))
    return OTR4_ERROR;

  manager->i = 0;
  manager->j = j;
  return OTR4_SUCCESS;
}

static otr4_err_t rotate_keys(key_manager_t *manager) {
  manager->i++;
  manager->j = 0;

  if (key_manager_generate_ephemeral_keys(manager))
    return OTR4_ERROR;

  return enter_new_ratchet(manager);
}

bool key_manager_ensure_on_ratchet(int ratchet_id, key_manager_t *manager) {
  if (manager->i == ratchet_id)
    return true;

  manager->i = ratchet_id;
  if (enter_new_ratchet(manager))
    return false;

  if (manager->i % 3 == 0) {
    dh_priv_key_destroy(manager->our_dh);
  }

  return true;
}

static bool derive_encription_and_mac_keys(m_enc_key_t enc_key,
                                           m_mac_key_t mac_key,
                                           const chain_key_t chain_key) {
  bool ok1 = false, ok2 = false;
  uint8_t magic1[1] = {0x1};
  uint8_t magic2[1] = {0x2};

  ok1 = sha3_256_kdf(enc_key, sizeof(m_enc_key_t), magic1, chain_key,
                     sizeof(chain_key_t));
  ok2 = sha3_512_kdf(mac_key, sizeof(m_mac_key_t), magic2, chain_key,
                     sizeof(chain_key_t));

  return ok1 && ok2;
}

otr4_err_t key_manager_retrieve_receiving_message_keys(
    m_enc_key_t enc_key, m_mac_key_t mac_key, int ratchet_id, int message_id,
    const key_manager_t *manager) {
  chain_key_t receiving;

  if (key_manager_get_receiving_chain_key_by_id(receiving, ratchet_id,
                                                message_id, manager))
    return OTR4_ERROR;

  if (!derive_encription_and_mac_keys(enc_key, mac_key, receiving)) {
    return OTR4_ERROR;
  }
  return OTR4_SUCCESS;
}

static bool should_ratchet(const key_manager_t *manager) {
  return manager->j == 0;
}

otr4_err_t key_manager_prepare_next_chain_key(key_manager_t *manager) {
  if (should_ratchet(manager)) {
    return rotate_keys(manager);
  }

  return derive_sending_chain_key(manager);
}

otr4_err_t key_manager_retrieve_sending_message_keys(
    m_enc_key_t enc_key, m_mac_key_t mac_key, const key_manager_t *manager) {
  chain_key_t sending;
  int message_id = key_manager_get_sending_chain_key(sending, manager);

  if (!derive_encription_and_mac_keys(enc_key, mac_key, sending))
    return OTR4_ERROR;

#ifdef DEBUG
  printf("GOT SENDING KEYS:\n");
  printf("enc_key = ");
  otrv4_memdump(enc_key, sizeof(m_enc_key_t));
  printf("mac_key = ");
  otrv4_memdump(mac_key, sizeof(m_mac_key_t));
#endif

  if (message_id == manager->j)
    return OTR4_SUCCESS;
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

  for (int i = 0; i < num_mac_keys; i++) {
    list_element_t *last = list_get_last(old_mac_keys);
    memcpy(ser_mac_keys + i * MAC_KEY_BYTES, last->data, MAC_KEY_BYTES);
    old_mac_keys = list_remove_element(last, old_mac_keys);
    list_free_full(last);
  }

  list_free_nodes(old_mac_keys);

  return ser_mac_keys;
}
