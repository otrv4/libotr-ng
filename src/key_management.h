#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include "dh.h"
#include "ed448.h"
#include "list.h"

typedef uint8_t k_dh_t[384];
typedef uint8_t mix_key_t[32];
typedef uint8_t k_ecdh_t[ED448_POINT_BYTES];
typedef uint8_t shared_secret_t[64];

typedef uint8_t root_key_t[64];
typedef uint8_t chain_key_t[64];
typedef uint8_t m_enc_key_t[32];
typedef uint8_t m_mac_key_t[64];

typedef struct _chain_link {
  int id;
  chain_key_t key;
  struct _chain_link *next;
} chain_link_t;

typedef struct {
  root_key_t root_key;
  chain_link_t chain_a[1];
  chain_link_t chain_b[1];
} ratchet_t;

typedef struct {
  // AKE context
  ecdh_keypair_t our_ecdh[1];
  dh_keypair_t our_dh;

  ec_point_t their_ecdh;
  dh_public_key_t their_dh;

  // Data messages context
  int i, j; // TODO: We need to add k (maybe), but why dont we need to add a
            // receiving_ratchet_id
  ratchet_t *current;

  mix_key_t mix_key;

  uint8_t ssid[8];

  list_element_t *old_mac_keys;
} key_manager_t;

typedef struct { const chain_link_t *sending, *receiving; } message_chain_t;

void key_manager_init(key_manager_t *manager);

void key_manager_destroy(key_manager_t *manager);

static inline void key_manager_set_their_ecdh(ec_point_t their,
                                              key_manager_t *manager) {
  ec_point_copy(manager->their_ecdh, their);
}

static inline void key_manager_set_their_dh(dh_public_key_t their,
                                            key_manager_t *manager) {
  dh_mpi_release(manager->their_dh);
  manager->their_dh = dh_mpi_copy(their);
}

otr4_err_t key_manager_generate_ephemeral_keys(key_manager_t *manager);

otr4_err_t key_manager_ratchetting_init(int j, key_manager_t *manager);

void key_manager_set_their_keys(ec_point_t their_ecdh, dh_public_key_t their_dh,
                                key_manager_t *manager);

void key_manager_prepare_to_ratchet(key_manager_t *manager);

otr4_err_t key_manager_new_ratchet(key_manager_t *manager,
                                   const shared_secret_t shared);

bool key_manager_ensure_on_ratchet(int ratchet_id, key_manager_t *manager);

// PRIVATE
otr4_err_t derive_ratchet_keys(ratchet_t *ratchet,
                               const shared_secret_t shared);

void derive_chain_keys(key_manager_t *manager, int i, int j);

void retrive_chain_keys(chain_key_t ck, key_manager_t *manager, int i, int j);

void derive_message_keys(m_enc_key_t enc_key, m_mac_key_t mac_key,
                         chain_key_t ck);

int key_manager_get_sending_chain_key(chain_key_t sending,
                                      const key_manager_t *manager);

otr4_err_t
key_manager_get_receiving_chain_key_by_id(chain_key_t receiving, int message_id,
                                          const key_manager_t *manager);

otr4_err_t calculate_shared_secret(shared_secret_t dst, const k_ecdh_t k_ecdh,
                                   const mix_key_t mix_key);

otr4_err_t
key_manager_retrieve_receiving_message_keys(m_enc_key_t enc_key,
                                            m_mac_key_t mac_key, int message_id,
                                            const key_manager_t *manager);

otr4_err_t key_manager_prepare_next_chain_key(key_manager_t *manager);

otr4_err_t key_manager_retrieve_sending_message_keys(
    m_enc_key_t enc_key, m_mac_key_t mac_key, const key_manager_t *manager);
uint8_t *key_manager_old_mac_keys_serialize(list_element_t *old_mac_keys);

#endif
