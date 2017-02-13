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

typedef struct _ratchet {
  chain_key_t chain_key_a;
  chain_key_t chain_key_b;
  root_key_t  root_key;
  struct _ratchet *next;
} ratchet_s, ratchet_t[1];

typedef struct {
  int i, j;
  ratchet_s *head;
  ratchet_s *current;
} key_manager_t[1];

void
key_manager_init(key_manager_t manager);

void
key_manager_destroy(key_manager_t manager);

bool
derive_ratchet_keys(ratchet_s *ratchet, const shared_secret_t shared);

bool
key_manager_init_ratchet(key_manager_t manager, const shared_secret_t shared);

void
derive_chain_keys(key_manager_t manager, int i, int j);


void
retrive_chain_keys(chain_key_t ck, key_manager_t manager, int i, int j);

void
derive_message_keys(m_enc_key_t enc_key, m_mac_key_t mac_key, chain_key_t ck);

static inline bool
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

#endif
