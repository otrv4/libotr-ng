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

#include <sodium.h>
#include <stdlib.h>
#include <time.h>

#define OTRNG_KEY_MANAGEMENT_PRIVATE

#include "key_management.h"
#include "random.h"
#include "serialize.h"
#include "shake.h"

#include "debug.h"

tstatic void chain_link_free(chain_link_s *head) {
  chain_link_s *current = head;
  chain_link_s *next = NULL;
  while (current) {
    next = current->next;

    sodium_memzero(current->key, sizeof(chain_key_p));
    free(current);

    current = next;
  }
}

tstatic ratchet_s *ratchet_new() {
  ratchet_s *ratchet = malloc(sizeof(ratchet_s));
  if (!ratchet)
    return NULL;

  memset(ratchet->root_key, 0, sizeof(ratchet->root_key));

  ratchet->chain_a->id = 0;
  memset(ratchet->chain_a->key, 0, sizeof(ratchet->chain_a->key));
  ratchet->chain_a->next = NULL;

  ratchet->chain_b->id = 0;
  memset(ratchet->chain_b->key, 0, sizeof(ratchet->chain_b->key));
  ratchet->chain_b->next = NULL;

  return ratchet;
}

tstatic void ratchet_free(ratchet_s *ratchet) {
  if (!ratchet)
    return;

  sodium_memzero(ratchet->root_key, sizeof(root_key_p));

  chain_link_free(ratchet->chain_a->next);
  ratchet->chain_a->next = NULL;

  chain_link_free(ratchet->chain_b->next);
  ratchet->chain_b->next = NULL;

  free(ratchet);
  ratchet = NULL;
}

INTERNAL void
otrng_key_manager_init(key_manager_s *manager) // make like ratchet_new?
{
  otrng_ec_bzero(manager->our_ecdh->pub, ED448_POINT_BYTES);
  manager->our_dh->pub = NULL;
  manager->our_dh->priv = NULL;

  otrng_ec_bzero(manager->their_ecdh, ED448_POINT_BYTES);
  manager->their_dh = NULL;

  otrng_ec_bzero(manager->their_shared_prekey, ED448_POINT_BYTES);
  otrng_ec_bzero(manager->our_shared_prekey, ED448_POINT_BYTES);

  manager->i = 0;
  manager->j = 0;

  manager->current = ratchet_new();

  memset(manager->brace_key, 0, sizeof(manager->brace_key));
  memset(manager->ssid, 0, sizeof(manager->ssid));
  manager->ssid_half = 0;
  memset(manager->extra_key, 0, sizeof(manager->extra_key));
  memset(manager->tmp_key, 0, sizeof(manager->tmp_key));

  manager->old_mac_keys = NULL;
}

INTERNAL void otrng_key_manager_destroy(key_manager_s *manager) {
  otrng_ecdh_keypair_destroy(manager->our_ecdh);
  otrng_dh_keypair_destroy(manager->our_dh);

  otrng_ec_point_destroy(manager->their_ecdh);

  gcry_mpi_release(manager->their_dh);
  manager->their_dh = NULL;

  ratchet_free(manager->current);
  manager->current = NULL;

  // TODO: once ake is finished should be wiped out
  sodium_memzero(manager->their_shared_prekey, ED448_POINT_BYTES);
  sodium_memzero(manager->our_shared_prekey, ED448_POINT_BYTES);

  sodium_memzero(manager->brace_key, sizeof(manager->brace_key));
  sodium_memzero(manager->ssid, sizeof(manager->ssid));
  manager->ssid_half = 0;
  sodium_memzero(manager->extra_key, sizeof(manager->extra_key));
  // TODO: once ake is finished should be wiped out
  sodium_memzero(manager->tmp_key, sizeof(manager->tmp_key));

  list_element_s *el;
  for (el = manager->old_mac_keys; el; el = el->next) {
    free((uint8_t *)el->data);
    el->data = NULL;
  }

  otrng_list_free_full(manager->old_mac_keys);
  manager->old_mac_keys = NULL;
}

INTERNAL otrng_err
otrng_key_manager_generate_ephemeral_keys(key_manager_s *manager) {
  time_t now;
  uint8_t sym[ED448_PRIVATE_BYTES];
  memset(sym, 0, sizeof(sym));
  random_bytes(sym, ED448_PRIVATE_BYTES);

  now = time(NULL);
  otrng_ec_point_destroy(manager->our_ecdh->pub);
  otrng_ecdh_keypair_generate(manager->our_ecdh, sym);
  manager->lastgenerated = now;

  if (manager->i % 3 == 0) {
    otrng_dh_keypair_destroy(manager->our_dh);

    if (otrng_dh_keypair_generate(manager->our_dh))
      return ERROR;
  }

  return SUCCESS;
}

INTERNAL void otrng_key_manager_set_their_keys(ec_point_p their_ecdh,
                                               dh_public_key_p their_dh,
                                               key_manager_s *manager) {
  otrng_ec_point_destroy(manager->their_ecdh);
  otrng_ec_point_copy(manager->their_ecdh, their_ecdh);
  otrng_dh_mpi_release(manager->their_dh);
  manager->their_dh = otrng_dh_mpi_copy(their_dh);
}

INTERNAL void otrng_key_manager_prepare_to_ratchet(key_manager_s *manager) {
  manager->j = 0;
}

tstatic void
derive_key_from_shared_secret(uint8_t *key, size_t keylen,
                              const uint8_t magic[1],
                              const shared_secret_p shared_secret) {
  shake_256_kdf(key, keylen, magic, shared_secret, sizeof(shared_secret_p));
}

tstatic void derive_root_key(root_key_p root_key,
                             const shared_secret_p shared_secret) {
  uint8_t magic[1] = {0x1};
  derive_key_from_shared_secret(root_key, sizeof(root_key_p), magic,
                                shared_secret);
}

tstatic void derive_chain_key_a(chain_key_p chain_key,
                                const shared_secret_p shared_secret) {
  uint8_t magic[1] = {0x2};
  derive_key_from_shared_secret(chain_key, sizeof(chain_key_p), magic,
                                shared_secret);
}

tstatic void derive_chain_key_b(chain_key_p chain_key,
                                const shared_secret_p shared_secret) {
  uint8_t magic[1] = {0x3};
  derive_key_from_shared_secret(chain_key, sizeof(chain_key_p), magic,
                                shared_secret);
}

tstatic otrng_err key_manager_new_ratchet(key_manager_s *manager,
                                          const shared_secret_p shared_secret) {
  ratchet_s *ratchet = ratchet_new();
  if (ratchet == NULL) {
    return ERROR;
  }
  if (manager->i == 0) {
    derive_root_key(ratchet->root_key, shared_secret);
    derive_chain_key_a(ratchet->chain_a->key, shared_secret);
    derive_chain_key_b(ratchet->chain_b->key, shared_secret);
  } else {
    shared_secret_p root_shared;
    shake_kkdf(root_shared, sizeof(shared_secret_p), manager->current->root_key,
               sizeof(root_key_p), shared_secret, sizeof(shared_secret_p));
    derive_root_key(ratchet->root_key, root_shared);
    derive_chain_key_a(ratchet->chain_a->key, root_shared);
    derive_chain_key_b(ratchet->chain_b->key, root_shared);
  }

  ratchet_free(manager->current);
  manager->current = ratchet;

  return SUCCESS;
}

tstatic const chain_link_s *chain_get_last(const chain_link_s *head) {
  const chain_link_s *cursor = head;
  while (cursor->next)
    cursor = cursor->next;

  return cursor;
}

tstatic const chain_link_s *chain_get_by_id(int message_id,
                                            const chain_link_s *head) {
  const chain_link_s *cursor = head;
  while (cursor->next && cursor->id != message_id)
    cursor = cursor->next;

  if (cursor->id == message_id) {
    return cursor;
  }

  return NULL;
}

tstatic message_chain_s *decide_between_chain_keys(const ratchet_s *ratchet,
                                                   const ec_point_p our,
                                                   const ec_point_p their) {
  message_chain_s *ret = malloc(sizeof(message_chain_s));
  if (ret == NULL)
    return NULL;

  ret->sending = NULL;
  ret->receiving = NULL;

  // TODO: this conversion from point to mpi might be checked.
  gcry_mpi_t our_mpi = NULL;
  gcry_mpi_t their_mpi = NULL;
  if (gcry_mpi_scan(&our_mpi, GCRYMPI_FMT_USG, our, ED448_POINT_BYTES, NULL)) {
    gcry_mpi_release(our_mpi);
    gcry_mpi_release(their_mpi);
    return NULL;
  }

  if (gcry_mpi_scan(&their_mpi, GCRYMPI_FMT_USG, their, ED448_POINT_BYTES,
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

tstatic int key_manager_get_sending_chain_key(chain_key_p sending,
                                              const key_manager_s *manager) {
  message_chain_s *chain = decide_between_chain_keys(
      manager->current, manager->our_ecdh->pub, manager->their_ecdh);
  const chain_link_s *last = chain_get_last(chain->sending);
  memcpy(sending, last->key, sizeof(chain_key_p));
  free(chain);
  chain = NULL;

  return last->id;
}

tstatic chain_link_s *chain_link_new() {
  chain_link_s *l = malloc(sizeof(chain_link_s));
  if (l == NULL)
    return NULL;

  l->id = 0;
  l->next = NULL;

  return l;
}

tstatic chain_link_s *derive_next_chain_link(chain_link_s *previous) {
  chain_link_s *l = chain_link_new();
  if (l == NULL)
    return NULL;

  // KDF_1(0x23 || chain_key_s[i-1][j], 64).
  shake_256_kdf1(l->key, sizeof(chain_key_p), 0x23, previous->key,
                 sizeof(chain_key_p));

  // TODO: the previous is still needed for the MK
  sodium_memzero(previous->key, CHAIN_KEY_BYTES);

  l->id = previous->id + 1;
  previous->next = l;
  return l;
}

tstatic otrng_err rebuild_chain_keys_up_to(int message_id,
                                           const chain_link_s *head) {
  chain_link_s *last = (chain_link_s *)chain_get_last(head);

  int j = 0;
  for (j = last->id; j < message_id; j++) {
    last = derive_next_chain_link(last);
    if (last == NULL)
      return ERROR;
  }

  return SUCCESS;
}

tstatic otrng_err key_manager_get_receiving_chain_key(
    chain_key_p receiving, int message_id, const key_manager_s *manager) {

  message_chain_s *chain = decide_between_chain_keys(
      manager->current, manager->our_ecdh->pub, manager->their_ecdh);
  if (rebuild_chain_keys_up_to(message_id, chain->receiving) == ERROR) {
    free(chain);
    chain = NULL;
    return ERROR;
  }

  const chain_link_s *link = chain_get_by_id(message_id, chain->receiving);
  free(chain);
  chain = NULL;

  if (link == NULL)
    return ERROR; /* message id not found. Should have been generated at
                        rebuild_chain_keys_up_to */

  memcpy(receiving, link->key, sizeof(chain_key_p));

  return SUCCESS;
}

INTERNAL void
otrng_ecdh_shared_secret_from_prekey(uint8_t *shared_secret,
                                     otrng_shared_prekey_pair_s *shared_prekey,
                                     const ec_point_p their_pub) {
  goldilocks_448_point_p p;
  goldilocks_448_point_scalarmul(p, their_pub, shared_prekey->priv);

  otrng_ec_point_valid(p);
  otrng_serialize_ec_point(shared_secret, p);
}

INTERNAL void
otrng_ecdh_shared_secret_from_keypair(uint8_t *shared_secret,
                                      otrng_keypair_s *keypair,
                                      const ec_point_p their_pub) {
  goldilocks_448_point_p p;
  goldilocks_448_point_scalarmul(p, their_pub, keypair->priv);

  otrng_ec_point_valid(p);
  otrng_serialize_ec_point(shared_secret, p);
}

tstatic void calculate_shared_secret(shared_secret_p dst, const k_ecdh_p k_ecdh,
                                     const brace_key_p brace_key) {
  goldilocks_shake256_ctx_p hd;

  hash_init_with_usage(hd, 0x04);
  hash_update(hd, k_ecdh, sizeof(k_ecdh_p));
  hash_update(hd, brace_key, sizeof(brace_key_p));

  hash_final(hd, dst, sizeof(shared_secret_p));
  hash_destroy(hd);
}

tstatic void calculate_shared_secret_from_tmp_key(shared_secret_p dst,
                                                  const uint8_t tmp_k[HASH_BYTES],
                                                  const brace_key_p brace_key) {
  goldilocks_shake256_ctx_p hd;

  hash_init_with_usage(hd, 0x04);
  hash_update(hd, tmp_k, HASH_BYTES);
  hash_update(hd, brace_key, sizeof(brace_key_p));

  hash_final(hd, dst, sizeof(shared_secret_p));
  hash_destroy(hd);
}

tstatic otrng_err derive_sending_chain_key(key_manager_s *manager) {
  message_chain_s *chain = decide_between_chain_keys(
      manager->current, manager->our_ecdh->pub, manager->their_ecdh);
  chain_link_s *last = (chain_link_s *)chain_get_last(chain->sending);
  free(chain);
  chain = NULL;
  (void)last;

  // TODO: seems to be wrong
  chain_link_s *l = derive_next_chain_link(last);
  if (l == NULL)
    return ERROR;

  // TODO: assert l->id == manager->j
  return SUCCESS;
}

tstatic void calculate_ssid(key_manager_s *manager,
                            const shared_secret_p shared_secret) {
  shake_256_kdf1(manager->ssid, 8, 0x05, shared_secret,
                 sizeof(shared_secret_p));
}

tstatic void calculate_extra_key(key_manager_s *manager,
                                 const chain_key_p chain_key) {
  uint8_t magic[1] = {0xFF};
  uint8_t extra_key_buff[HASH_BYTES];

  shake_256_kdf(extra_key_buff, HASH_BYTES, magic, chain_key,
                sizeof(chain_key_p));

  memcpy(manager->extra_key, extra_key_buff, sizeof manager->extra_key);
}

tstatic otrng_err calculate_brace_key(key_manager_s *manager) {
  k_dh_p k_dh;

  if (manager->i % 3 == 0) {
    if (otrng_dh_shared_secret(k_dh, sizeof(k_dh_p), manager->our_dh->priv,
                               manager->their_dh) == ERROR)
      return ERROR;

    // Although k_dh has variable length (bc it is mod p), it is considered to
    // have 384 bytes because otrng_dh_shared_secret adds leading zeroes to the
    // serialized secret. Note that DH(a, B) (in the spec) does not mandate
    // doing so.
    // Also note that OTRv3 serializes DH values in MPI (no leading zeroes).
    shake_256_kdf1(manager->brace_key, BRACE_KEY_BYTES, 0x02, k_dh,
                   sizeof(k_dh_p));

  } else {
    shake_256_kdf1(manager->brace_key, BRACE_KEY_BYTES, 0x03,
                   manager->brace_key, sizeof(brace_key_p));
  }

  return SUCCESS;
}

tstatic otrng_err enter_new_ratchet(key_manager_s *manager) {
  k_ecdh_p k_ecdh;
  shared_secret_p shared_secret;

  otrng_ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);

  if (otrng_ecdh_valid_secret(k_ecdh))
    return ERROR;

  if (calculate_brace_key(manager) == ERROR)
    return ERROR;

  calculate_shared_secret(shared_secret, k_ecdh, manager->brace_key);

#ifdef DEBUG
  printf("ENTERING NEW RATCHET\n");
  printf("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_p));
  printf("brace_key = ");
  otrng_memdump(manager->brace_key, sizeof(brace_key_p));
#endif

  if (key_manager_new_ratchet(manager, shared_secret) == ERROR) {
    sodium_memzero(shared_secret, SHARED_SECRET_BYTES);
    sodium_memzero(manager->ssid, sizeof(manager->ssid));
    sodium_memzero(manager->extra_key, sizeof(manager->extra_key));
    return ERROR;
  }

  sodium_memzero(shared_secret, SHARED_SECRET_BYTES);
  return SUCCESS;
}

tstatic otrng_err init_ratchet(key_manager_s *manager, bool interactive) {
  k_ecdh_p k_ecdh;
  shared_secret_p shared_secret;

  otrng_ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);

  if (otrng_ecdh_valid_secret(k_ecdh))
    return ERROR;

  if (calculate_brace_key(manager))
    return ERROR;

  if (interactive)
    calculate_shared_secret(shared_secret, k_ecdh, manager->brace_key);
  else
    calculate_shared_secret_from_tmp_key(shared_secret, manager->tmp_key,
                                         manager->brace_key);

#ifdef DEBUG
  printf("ENTERING NEW RATCHET\n");
  printf("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_p));
  printf("mixed_key = ");
  otrng_memdump(manager->brace_key, sizeof(brace_key_p));
#endif

  calculate_ssid(manager, shared_secret);
  if (gcry_mpi_cmp(manager->our_dh->pub, manager->their_dh) > 0) {
    manager->ssid_half = SESSION_ID_SECOND_HALF_BOLD;
  } else {
    manager->ssid_half = SESSION_ID_FIRST_HALF_BOLD;
  }

#ifdef DEBUG
  printf("THE SECURE SESSION ID\n");
  printf("ssid: \n");
  if (manager->ssid_half == SESSION_ID_FIRST_HALF_BOLD) {
    printf("the first 4 bytes = ");
    printf("0x");
    for (unsigned int i = 0; i < 4; i++) {
      printf("%x", manager->ssid[i]);
    }
  } else {
    printf("the last 4 bytes = ");
    printf("0x");
    for (unsigned int i = 4; i < 8; i++) {
      printf("%x", manager->ssid[i]);
    }
    printf("\n");
  }
#endif

  if (key_manager_new_ratchet(manager, shared_secret) == ERROR) {
    sodium_memzero(shared_secret, SHARED_SECRET_BYTES);
    sodium_memzero(manager->ssid, sizeof(manager->ssid));
    sodium_memzero(manager->extra_key, sizeof(manager->extra_key));
    sodium_memzero(manager->tmp_key, sizeof(manager->tmp_key));
    return ERROR;
  }

  sodium_memzero(shared_secret, SHARED_SECRET_BYTES);
  /* tmp_k is no longer needed */
  sodium_memzero(manager->tmp_key, HASH_BYTES);

  return SUCCESS;
}

INTERNAL otrng_err otrng_key_manager_ratcheting_init(int j, bool interactive,
                                                     key_manager_s *manager) {
  if (init_ratchet(manager, interactive))
    return ERROR;

  manager->i = 0;
  manager->j = j;
  return SUCCESS;
}

tstatic otrng_err rotate_keys(key_manager_s *manager) {
  manager->i++;
  manager->j = 0;

  if (otrng_key_manager_generate_ephemeral_keys(manager))
    return ERROR;

  return enter_new_ratchet(manager);
}

INTERNAL otrng_err otrng_key_manager_ensure_on_ratchet(key_manager_s *manager) {
  if (manager->j == 0)
    return SUCCESS;

  manager->i++;
  if (enter_new_ratchet(manager))
    return ERROR;

  // Securely delete priv keys as no longer needed
  otrng_ec_scalar_destroy(manager->our_ecdh->priv);
  if (manager->i % 3 == 0) {
    otrng_dh_priv_key_destroy(manager->our_dh);
  }

  return SUCCESS;
}

tstatic void derive_encryption_and_mac_keys(m_enc_key_p enc_key,
                                            m_mac_key_p mac_key,
                                            const chain_key_p chain_key) {
  uint8_t magic1[1] = {0x1};
  uint8_t magic2[1] = {0x2};

  shake_256_kdf(enc_key, sizeof(m_enc_key_p), magic1, chain_key,
                sizeof(chain_key_p));
  shake_256_kdf(mac_key, sizeof(m_mac_key_p), magic2, enc_key,
                sizeof(m_enc_key_p));
}

INTERNAL otrng_err otrng_key_manager_retrieve_receiving_message_keys(
    m_enc_key_p enc_key, m_mac_key_p mac_key, int message_id,
    key_manager_s *manager) {
  chain_key_p receiving;

  if (key_manager_get_receiving_chain_key(receiving, message_id, manager) ==
      ERROR)
    return ERROR;

  derive_encryption_and_mac_keys(enc_key, mac_key, receiving);
  calculate_extra_key(manager, receiving);

#ifdef DEBUG
  printf("GOT SENDING KEYS:\n");
  printf("receiving enc_key = ");
  otrng_memdump(enc_key, sizeof(m_enc_key_p));
  printf("receiving mac_key = ");
  otrng_memdump(mac_key, sizeof(m_mac_key_p));
#endif

  return SUCCESS;
}

tstatic otrng_bool should_ratchet(const key_manager_s *manager) {
  if (manager->j == 0)
    return otrng_true;

  return otrng_false;
}

INTERNAL otrng_err
otrng_key_manager_prepare_next_chain_key(key_manager_s *manager) {
  if (should_ratchet(manager) == otrng_true) {
    return rotate_keys(manager);
  }

  return derive_sending_chain_key(manager);
}

INTERNAL otrng_err otrng_key_manager_retrieve_sending_message_keys(
    m_enc_key_p enc_key, m_mac_key_p mac_key, key_manager_s *manager) {
  chain_key_p sending;
  int message_id = key_manager_get_sending_chain_key(sending, manager);

  derive_encryption_and_mac_keys(enc_key, mac_key, sending);
  calculate_extra_key(manager, sending);

#ifdef DEBUG
  printf("GOT SENDING KEYS:\n");
  printf("sending enc_key = ");
  otrng_memdump(enc_key, sizeof(m_enc_key_p));
  printf("sending mac_key = ");
  otrng_memdump(mac_key, sizeof(m_mac_key_p));
#endif

  if (message_id == manager->j) {
    return SUCCESS;
  }

  sodium_memzero(enc_key, sizeof(m_enc_key_p));
  sodium_memzero(mac_key, sizeof(m_mac_key_p));
  return ERROR;
}

INTERNAL uint8_t *
otrng_key_manager_old_mac_keys_serialize(list_element_s *old_mac_keys) {
  uint num_mac_keys = otrng_list_len(old_mac_keys);
  size_t serlen = num_mac_keys * MAC_KEY_BYTES;
  if (serlen == 0) {
    return NULL;
  }

  uint8_t *ser_mac_keys = malloc(serlen);
  if (!ser_mac_keys) {
    return NULL;
  }

  for (unsigned int i = 0; i < num_mac_keys; i++) {
    list_element_s *last = otrng_list_get_last(old_mac_keys);
    memcpy(ser_mac_keys + i * MAC_KEY_BYTES, last->data, MAC_KEY_BYTES);
    old_mac_keys = otrng_list_remove_element(last, old_mac_keys);
    otrng_list_free_full(last);
  }

  otrng_list_free_nodes(old_mac_keys);

  return ser_mac_keys;
}

INTERNAL void otrng_key_manager_set_their_ecdh(ec_point_p their,
                                               key_manager_s *manager) {
  otrng_ec_point_copy(manager->their_ecdh, their);
}

INTERNAL void otrng_key_manager_set_their_dh(dh_public_key_p their,
                                             key_manager_s *manager) {
  otrng_dh_mpi_release(manager->their_dh);
  manager->their_dh = otrng_dh_mpi_copy(their);
}
