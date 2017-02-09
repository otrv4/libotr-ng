#include <stdbool.h>
#include <stdint.h>
#include <gcrypt.h>

#ifndef DH_H
#define DH_H

#define DH_KEY_SIZE 80
#define DH3072_MOD_LEN_BITS 3072
#define DH3072_MOD_LEN_BYTES 384

typedef gcry_mpi_t dh_mpi_t;
typedef dh_mpi_t dh_private_key_t, dh_public_key_t;

typedef struct {
  dh_mpi_t priv, pub;
} dh_keypair_t[1];

void
dh_init(void);

bool
dh_gen_keypair(dh_keypair_t keypair);

void
dh_keypair_destroy(dh_keypair_t keypair);

size_t
dh_mpi_serialize(uint8_t *dst, size_t dst_len, const dh_mpi_t src);

bool
dh_mpi_deserialize(dh_mpi_t *dst, const uint8_t *buffer, size_t buflen, size_t *nread);

bool
dh_shared_secret(
    uint8_t *shared,
    size_t shared_bytes,
    const dh_private_key_t our_priv,
    const dh_public_key_t their_pub
);

static inline int
dh_mpi_cmp(const dh_mpi_t m1, const dh_mpi_t m2) {
  return gcry_mpi_cmp(m1, m2);
}

bool
dh_mpi_valid(dh_mpi_t mpi);

static inline dh_mpi_t
dh_mpi_copy(const dh_mpi_t src) {
  return gcry_mpi_copy(src);
}

static inline void
dh_mpi_release(dh_mpi_t mpi) {
  gcry_mpi_release(mpi);
}

#endif
