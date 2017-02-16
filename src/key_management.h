#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

typedef uint8_t k_dh_t[384];
typedef uint8_t mix_key_t[32];
typedef uint8_t k_ecdh_t[56];
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
  int id;
  root_key_t  root_key;
  chain_link_t chain_a[1];
  chain_link_t chain_b[1];
} ratchet_t;

typedef struct {
  int i, j;
  ratchet_t *current;
  ratchet_t *previous;
} key_manager_t[1];

typedef struct {
  const chain_link_t *sending, *receiving;
} message_chain_t;

void
key_manager_init(key_manager_t manager);

void
key_manager_destroy(key_manager_t manager);

void
key_manager_free(key_manager_t manager);

bool
derive_ratchet_keys(ratchet_t *ratchet, const shared_secret_t shared);

bool
key_manager_init_ratchet(key_manager_t manager, const shared_secret_t shared);

void
derive_chain_keys(key_manager_t manager, int i, int j);

void
retrive_chain_keys(chain_key_t ck, key_manager_t manager, int i, int j);

void
derive_message_keys(m_enc_key_t enc_key, m_mac_key_t mac_key, chain_key_t ck);

int
key_manager_get_sending_chain_key(chain_key_t sending, const key_manager_t manager, const ec_public_key_t our_ecdh, const ec_public_key_t their_ecdh);

bool
key_manager_get_receiving_chain_key_by_id(chain_key_t receiving, int ratchet_id, int message_id, const ec_public_key_t our_ecdh, const ec_public_key_t their_ecdh, const key_manager_t manager);

bool
calculate_shared_secret(shared_secret_t dst, const k_ecdh_t k_ecdh, const mix_key_t mix_key);

bool
sha3_512_mac(uint8_t *dst, size_t dstlen, const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen);

bool
sha3_256_kdf(uint8_t *key, size_t keylen, const uint8_t magic[1], const uint8_t *secret, size_t secretlen);

bool
sha3_512_kdf(uint8_t *key, size_t keylen, const uint8_t magic[1], const uint8_t *secret, size_t secretlen);

#endif
