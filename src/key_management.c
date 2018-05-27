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

tstatic ratchet_s *ratchet_new() {
  ratchet_s *ratchet = malloc(sizeof(ratchet_s));
  if (!ratchet)
    return NULL;

  memset(ratchet->root_key, 0, sizeof(ratchet->root_key));
  memset(ratchet->chain_s, 0, sizeof(ratchet->chain_s));
  memset(ratchet->chain_r, 0, sizeof(ratchet->chain_r));

  return ratchet;
}

tstatic void ratchet_free(ratchet_s *ratchet) {
  if (!ratchet)
    return;

  sodium_memzero(ratchet->root_key, sizeof(root_key_p));
  sodium_memzero(ratchet->chain_s, sizeof(sending_chain_key_p));
  sodium_memzero(ratchet->chain_r, sizeof(receiving_chain_key_p));

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
  manager->k = 0;
  manager->pn = 0;
  manager->current = ratchet_new();

  memset(manager->brace_key, 0, sizeof(manager->brace_key));
  memset(manager->shared_secret, 0, sizeof(manager->shared_secret));

  memset(manager->ssid, 0, sizeof(manager->ssid));
  manager->ssid_half = 0;
  memset(manager->extra_symetric_key, 0, sizeof(manager->extra_symetric_key));
  memset(manager->tmp_key, 0, sizeof(manager->tmp_key));

  manager->skipped_keys = NULL;
  manager->old_mac_keys = NULL;
}

INTERNAL void otrng_key_manager_destroy(key_manager_s *manager) {
  otrng_ecdh_keypair_destroy(manager->our_ecdh);
  otrng_dh_keypair_destroy(manager->our_dh);

  otrng_ec_point_destroy(manager->their_ecdh);

  gcry_mpi_release(manager->their_dh);
  manager->their_dh = NULL;

  manager->i = 0;
  manager->j = 0;
  manager->k = 0;
  manager->pn = 0;

  ratchet_free(manager->current);
  manager->current = NULL;

  // TODO: once dake is finished should be wiped out
  sodium_memzero(manager->their_shared_prekey, ED448_POINT_BYTES);
  sodium_memzero(manager->our_shared_prekey, ED448_POINT_BYTES);

  sodium_memzero(manager->brace_key, sizeof(manager->brace_key));
  sodium_memzero(manager->shared_secret, sizeof(manager->shared_secret));
  sodium_memzero(manager->ssid, sizeof(manager->ssid));
  manager->ssid_half = 0;
  sodium_memzero(manager->extra_symetric_key,
                 sizeof(manager->extra_symetric_key));
  // TODO: once dake is finished should be wiped out
  sodium_memzero(manager->tmp_key, sizeof(manager->tmp_key));

  list_element_s *el;
  for (el = manager->skipped_keys; el; el = el->next) {
    free((skipped_keys_s *)el->data);
    el->data = NULL;
  }

  otrng_list_free_full(manager->skipped_keys);
  manager->skipped_keys = NULL;

  list_element_s *el_2;
  for (el_2 = manager->old_mac_keys; el_2; el_2 = el_2->next) {
    free((uint8_t *)el_2->data);
    el_2->data = NULL;
  }

  otrng_list_free_full(manager->old_mac_keys);
  manager->old_mac_keys = NULL;
}

INTERNAL void otrng_key_manager_set_their_keys(ec_point_p their_ecdh,
                                               dh_public_key_p their_dh,
                                               key_manager_s *manager) {
  otrng_ec_point_destroy(manager->their_ecdh);
  otrng_ec_point_copy(manager->their_ecdh, their_ecdh);
  otrng_dh_mpi_release(manager->their_dh);
  manager->their_dh = otrng_dh_mpi_copy(their_dh);
}

INTERNAL void otrng_key_manager_set_their_ecdh(ec_point_p their_ecdh,
                                               key_manager_s *manager) {
  otrng_ec_point_copy(manager->their_ecdh, their_ecdh);
}

INTERNAL void otrng_key_manager_set_their_dh(dh_public_key_p their_dh,
                                             key_manager_s *manager) {
  otrng_dh_mpi_release(manager->their_dh);
  manager->their_dh = otrng_dh_mpi_copy(their_dh);
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

    if (!otrng_dh_keypair_generate(manager->our_dh))
      return ERROR;
  }

  return SUCCESS;
}

// Generate the ephemeral keys just as the DAKE is finished
tstatic otrng_err generate_first_ephemeral_keys(key_manager_s *manager,
                                                otrng_participant participant) {
  uint8_t random[ED448_PRIVATE_BYTES];

  if (participant == OTRNG_OURS) {
    shake_256_kdf1(random, sizeof random, 0x13, manager->shared_secret,
                   sizeof(shared_secret_p));

    otrng_ec_point_destroy(manager->our_ecdh->pub);
    otrng_ecdh_keypair_generate(manager->our_ecdh, random);

    otrng_dh_keypair_destroy(manager->our_dh);
    if (!otrng_dh_keypair_generate_from_shared_secret(
            manager->shared_secret, manager->our_dh, participant))
      return ERROR;
  } else if (participant == OTRNG_THEIR) {
    shake_256_kdf1(random, sizeof random, 0x13, manager->shared_secret,
                   sizeof(shared_secret_p));

    otrng_ec_point_destroy(manager->their_ecdh);
    otrng_ecdh_keypair_generate_their(manager->their_ecdh, random);

    gcry_mpi_release(manager->their_dh);
    manager->their_dh = NULL;
    dh_keypair_p tmp_their_dh;

    if (!otrng_dh_keypair_generate_from_shared_secret(
            manager->shared_secret, tmp_their_dh, participant))
      return ERROR;

    manager->their_dh = tmp_their_dh->pub;
  }
  return SUCCESS;
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

  sodium_memzero(k_dh, sizeof(k_dh_p));

  return SUCCESS;
}

tstatic void calculate_shared_secret(key_manager_s *manager, k_ecdh_p k_ecdh) {
  goldilocks_shake256_ctx_p hd;

  hash_init_with_usage(hd, 0x04);
  hash_update(hd, k_ecdh, sizeof(k_ecdh_p));
  hash_update(hd, manager->brace_key, sizeof(brace_key_p));
  hash_final(hd, manager->shared_secret, sizeof(shared_secret_p));
  hash_destroy(hd);

  sodium_memzero(k_ecdh, sizeof(k_ecdh_p));
}

INTERNAL otrng_err otrng_key_manager_generate_shared_secret(
    key_manager_s *manager, otrng_information_flow flow) {
  if (flow == OTRNG_INTERACTIVE) {
    k_ecdh_p k_ecdh;

    otrng_ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);
    otrng_ec_bzero(manager->our_ecdh->priv, sizeof(ec_scalar_p));

    if (!otrng_ecdh_valid_secret(k_ecdh))
      return ERROR;

    if (calculate_brace_key(manager) == ERROR)
      return ERROR;

    // TODO: why is this passing the whole struct?
    otrng_dh_priv_key_destroy(manager->our_dh);

    calculate_shared_secret(manager, k_ecdh);
  } else if (flow == OTRNG_NON_INTERACTIVE) {
    shake_256_kdf1(manager->shared_secret, sizeof(shared_secret_p), 0x04,
                   manager->tmp_key, sizeof(manager->tmp_key));
  }

  calculate_ssid(manager);

#ifdef DEBUG
  printf("THE SHARED SECRET\n");
  otrng_memdump(manager->shared_secret, sizeof(manager->shared_secret));
  printf("THE SSID\n");
  otrng_memdump(manager->ssid, sizeof(manager->ssid));
#endif

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

  return SUCCESS;
}

// TODO: perhaps this only needs the manager
INTERNAL otrng_err otrng_ecdh_shared_secret_from_prekey(
    uint8_t *shared_secret, otrng_shared_prekey_pair_s *shared_prekey,
    const ec_point_p their_pub) {
  goldilocks_448_point_p p;
  goldilocks_448_point_scalarmul(p, their_pub, shared_prekey->priv);

  if (!otrng_ec_point_valid(p))
    return ERROR;

  otrng_serialize_ec_point(shared_secret, p);

  if (!otrng_ecdh_valid_secret(shared_secret))
    return ERROR;

  return SUCCESS;
}

// TODO: perhaps this only needs the manager
INTERNAL otrng_err otrng_ecdh_shared_secret_from_keypair(
    uint8_t *shared_secret, otrng_keypair_s *keypair,
    const ec_point_p their_pub) {
  goldilocks_448_point_p p;
  goldilocks_448_point_scalarmul(p, their_pub, keypair->priv);

  if (!otrng_ec_point_valid(p))
    return ERROR;

  otrng_serialize_ec_point(shared_secret, p);

  if (!otrng_ecdh_valid_secret(shared_secret))
    return ERROR;

  return SUCCESS;
}

tstatic void calculate_ssid(key_manager_s *manager) {
  shake_256_kdf1(manager->ssid, sizeof(manager->ssid), 0x05,
                 manager->shared_secret, sizeof(shared_secret_p));
}

INTERNAL otrng_err otrng_key_manager_ratcheting_init(
    key_manager_s *manager, otrng_participant participant) {
  if (!generate_first_ephemeral_keys(manager, participant))
    return ERROR;

  manager->i = 0;
  manager->j = 0;
  manager->k = 0;
  manager->pn = 0;
  // TODO: we can assing directly to the root key
  memcpy(manager->current->root_key, manager->shared_secret, 64);
  sodium_memzero(manager->shared_secret, 64);

  return SUCCESS;
}

tstatic otrng_err enter_new_ratchet(key_manager_s *manager,
                                    otrng_participant_action action) {
  k_ecdh_p k_ecdh;

  // K_ecdh = ECDH(our_ecdh.secret, their_ecdh)
  otrng_ecdh_shared_secret(k_ecdh, manager->our_ecdh, manager->their_ecdh);

  // if i % 3 == 0 : brace_key = KDF_1(0x02 || k_dh, 32)
  // else brace_key = KDF_1(0x03 || brace_key, 32)
  if (calculate_brace_key(manager) == ERROR)
    return ERROR;

  // K = KDF_1(0x04 || K_ecdh || brace_key, 64)
  calculate_shared_secret(manager, k_ecdh);

#ifdef DEBUG
  printf("ENTERING NEW RATCHET\n");
  printf("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_p));
  printf("brace_key = ");
  otrng_memdump(manager->brace_key, sizeof(brace_key_p));
  printf("THE SHARED SECRET\n");
  otrng_memdump(manager->shared_secret, sizeof(manager->shared_secret));
#endif

  if (key_manager_derive_ratchet_keys(manager, action) == ERROR) {
    sodium_memzero(manager->shared_secret, SHARED_SECRET_BYTES);
    return ERROR;
  }

  sodium_memzero(manager->shared_secret, SHARED_SECRET_BYTES);
  return SUCCESS;
}

// TODO: not sure about this always return SUCCESS.. maybe some other logic will
// work
tstatic otrng_err rotate_keys(key_manager_s *manager,
                              otrng_participant_action action) {
  manager->k = 0;
  if (action == OTRNG_SENDING) {
    // our_ecdh = generateECDH()
    // if i % 3 == 0, our_dh = generateDH()
    if (!otrng_key_manager_generate_ephemeral_keys(manager))
      return ERROR;

    if (!enter_new_ratchet(manager, action))
      return ERROR;
  } else if (action == OTRNG_RECEIVING) {
    if (!enter_new_ratchet(manager, action))
      return ERROR;

    otrng_ec_scalar_destroy(manager->our_ecdh->priv);
    if (manager->i % 3 == 0)
      otrng_dh_priv_key_destroy(manager->our_dh);
  }

  manager->i++;

  return SUCCESS;
}

tstatic otrng_err key_manager_derive_ratchet_keys(
    key_manager_s *manager, otrng_participant_action action) {
  ratchet_s *ratchet = ratchet_new();
  if (!ratchet)
    return ERROR;

  // root_key[i], chain_key_s[i][j] = derive_ratchet_keys(sending,
  // root_key[i-1], K) root_key[i] = KDF_1(0x15 || root_key[i-1] || K, 64)

  goldilocks_shake256_ctx_p hd;
  hash_init_with_usage(hd, 0x15);
  hash_update(hd, manager->current->root_key, sizeof(root_key_p));
  hash_update(hd, manager->shared_secret, sizeof(shared_secret_p));
  hash_final(hd, ratchet->root_key, sizeof(root_key_p));
  hash_destroy(hd);

  // chain_key_purpose[i][j] = KDF_1(0x16 || root_key[i-1] || K, 64)
  if (action == OTRNG_SENDING) {
    hash_init_with_usage(hd, 0x16);
    hash_update(hd, manager->current->root_key, sizeof(root_key_p));
    hash_update(hd, manager->shared_secret, sizeof(shared_secret_p));
    hash_final(hd, ratchet->chain_s, sizeof(sending_chain_key_p));
    hash_destroy(hd);
  } else if (action == OTRNG_RECEIVING) {
    hash_init_with_usage(hd, 0x16);
    hash_update(hd, manager->current->root_key, sizeof(root_key_p));
    hash_update(hd, manager->shared_secret, sizeof(shared_secret_p));
    hash_final(hd, ratchet->chain_r, sizeof(receiving_chain_key_p));
    hash_destroy(hd);
  }
  ratchet_free(manager->current);
  manager->current = ratchet;

#ifdef DEBUG
  printf("ROOT KEY = ");
  otrng_memdump(manager->current->root, sizeof(manager->current->root_key));
  printf("CHAIN_S = ");
  otrng_memdump(manager->chain_s, sizeof(manager->chain_s));
  printf("CHAIN_R = ");
  otrng_memdump(manager->chain_r, sizeof(manager->chain_r));
#endif

  return SUCCESS;
}

tstatic void derive_next_chain_key(key_manager_s *manager,
                                   otrng_participant_action action) {
  // chain_key_s[i-1][j+1] = KDF_1(0x17 || chain_key_s[i-1][j], 64)
  if (action == OTRNG_SENDING) {
    shake_256_kdf1(manager->current->chain_s, sizeof(sending_chain_key_p), 0x17,
                   manager->current->chain_s, sizeof(sending_chain_key_p));

  } else if (action == OTRNG_RECEIVING) {
    shake_256_kdf1(manager->current->chain_r, sizeof(receiving_chain_key_p),
                   0x17, manager->current->chain_r,
                   sizeof(receiving_chain_key_p));
  }
}

tstatic void derive_encryption_and_mac_keys(m_enc_key_p enc_key,
                                            m_mac_key_p mac_key,
                                            key_manager_s *manager,
                                            otrng_participant_action action) {
  // MKenc, MKmac = derive_enc_mac_keys(chain_key_s[i-1][j])
  // MKenc = KDF_1(0x18 || chain_key, 32)
  // MKmac = KDF_1(0x19 || MKenc, 64)
  if (action == OTRNG_SENDING) {
    shake_256_kdf1(enc_key, sizeof(m_enc_key_p), 0x18,
                   manager->current->chain_s, sizeof(sending_chain_key_p));

  } else if (action == OTRNG_RECEIVING) {
    shake_256_kdf1(enc_key, sizeof(m_enc_key_p), 0x18,
                   manager->current->chain_r, sizeof(receiving_chain_key_p));
  }
  shake_256_kdf1(mac_key, sizeof(m_mac_key_p), 0x19, enc_key,
                 sizeof(m_enc_key_p));
}

// TODO: this seems untested
tstatic void calculate_extra_key(key_manager_s *manager,
                                 otrng_participant_action action) {
  goldilocks_shake256_ctx_p hd;
  uint8_t extra_key_buff[EXTRA_SYMMETRIC_KEY_BYTES];
  uint8_t magic[1] = {0xFF};

  hash_init_with_usage(hd, 0x1A);
  hash_update(hd, magic, 1);

  // extra_symm_key = KDF_1(0x1A || 0xFF || chain_key_s[i-1][j], 32)
  if (action == OTRNG_SENDING) {
    hash_update(hd, manager->current->chain_s, sizeof(sending_chain_key_p));
  } else if (action == OTRNG_SENDING) {
    hash_update(hd, manager->current->chain_r, sizeof(receiving_chain_key_p));
  }
  hash_final(hd, extra_key_buff, EXTRA_SYMMETRIC_KEY_BYTES);
  hash_destroy(hd);

  memcpy(manager->extra_symetric_key, extra_key_buff,
         sizeof(manager->extra_symetric_key));

#ifdef DEBUG
  printf("EXTRA KEY = ");
  otrng_memdump(manager->extra_symetric->key,
                sizeof(manager->extra_symetric_key));
#endif
}

tstatic otrng_err store_enc_keys(m_enc_key_p enc_key, key_manager_s *manager,
                                 int max_skip, int until) {
  uint8_t zero_buff[CHAIN_KEY_BYTES] = {};

  if ((manager->k + max_skip) < until) {
    // TODO: should we send an error message?
    return ERROR;
  }

  if (!(memcmp(manager->current->chain_r, zero_buff,
               sizeof(manager->current->chain_r)) == 0)) {
    while (manager->k < until) {
      shake_256_kdf1(enc_key, sizeof(m_enc_key_p), 0x18,
                     manager->current->chain_r, sizeof(receiving_chain_key_p));

      goldilocks_shake256_ctx_p hd;
      uint8_t extra_key[EXTRA_SYMMETRIC_KEY_BYTES];
      uint8_t magic[1] = {0xFF};

      hash_init_with_usage(hd, 0x1A);
      hash_update(hd, magic, 1);

      hash_update(hd, manager->current->chain_r, sizeof(receiving_chain_key_p));
      hash_final(hd, extra_key, EXTRA_SYMMETRIC_KEY_BYTES);
      hash_destroy(hd);

      shake_256_kdf1(manager->current->chain_r, sizeof(receiving_chain_key_p),
                     0x17, manager->current->chain_r,
                     sizeof(receiving_chain_key_p));

      skipped_keys_s *skipped_m_enc_key = malloc(sizeof(skipped_keys_s));
      if (!skipped_m_enc_key)
        return ERROR;

      skipped_m_enc_key->i = manager->i;
      skipped_m_enc_key->j = manager->k;

      memcpy(skipped_m_enc_key->extra_symetric_key, extra_key,
             EXTRA_SYMMETRIC_KEY_BYTES);
      memcpy(skipped_m_enc_key->m_enc_key, enc_key, ENC_KEY_BYTES);

      manager->skipped_keys =
          otrng_list_add(skipped_m_enc_key, manager->skipped_keys);

      sodium_memzero(enc_key, sizeof(m_enc_key_p));
      manager->k++;
    }
  }

  derive_encryption_and_mac_keys(enc_key, mac_key, manager, action);
  calculate_extra_key(manager, action);
  derive_next_chain_key(manager, action);

#ifdef DEBUG
  printf("GOT SENDING KEYS:\n");
  printf("enc_key = ");
  otrng_memdump(enc_key, sizeof(m_enc_key_p));
  printf("mac_key = ");
  otrng_memdump(mac_key, sizeof(m_mac_key_p));
#endif

  return SUCCESS;
}

INTERNAL otrng_err otrng_key_manager_derive_dh_ratchet_keys(
    key_manager_s *manager, otrng_participant_action action) {
  // Derive new ECDH and DH keys
  if (manager->j == 0)
    return rotate_keys(manager, action);

  return SUCCESS;
}
