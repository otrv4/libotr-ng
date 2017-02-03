#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

typedef uint8_t root_key_t[64];
typedef uint8_t chain_key_t[64];
typedef uint8_t m_enc_key_t[32];
typedef uint8_t m_mac_key_t[64];

typedef struct ratchet_s {
    chain_key_t *chain_keys_a;
    chain_key_t *chain_keys_b;
    root_key_t  root_key;
    struct ratchet_s *next;
} ratchet_t[1];

typedef struct key_manager_s {
    struct ratchet_s *head;
    struct ratchet_s *current;
} key_manager_t[1];

void
derive_ratchet_keys(key_manager_t manager, const uint8_t *shared, size_t size);
void
derive_chain_keys(key_manager_t manager, int i, int j);
void
retrive_chain_keys(chain_key_t ck, key_manager_t manager, int i, int j);

void
init_key_manager(key_manager_t manager);

void
derive_message_keys(m_enc_key_t *enc_key, m_mac_key_t *mac_key, chain_key_t ck);
#endif
