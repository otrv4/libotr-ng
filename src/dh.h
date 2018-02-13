#ifndef OTRV4_DH_H
#define OTRV4_DH_H

#include <gcrypt.h>
#include <stdint.h>

#include "shared.h"
#include "error.h"

#define DH_KEY_SIZE 80
#define DH3072_MOD_LEN_BITS 3072
#define DH3072_MOD_LEN_BYTES 384
#define DH_MPI_BYTES (4 + DH3072_MOD_LEN_BYTES)

typedef gcry_mpi_t dh_mpi_t;
typedef dh_mpi_t dh_private_key_t, dh_public_key_t;

typedef struct {
  dh_public_key_t pub;
  dh_private_key_t priv;
} dh_keypair_t[1];

INTERNAL void otrv4_dh_init(void);

INTERNAL void otrv4_dh_free(void);

INTERNAL otrv4_err_t otrv4_dh_keypair_generate(dh_keypair_t keypair);

INTERNAL void otrv4_dh_priv_key_destroy(dh_keypair_t keypair);

INTERNAL void otrv4_dh_keypair_destroy(dh_keypair_t keypair);

INTERNAL otrv4_err_t otrv4_dh_shared_secret(uint8_t *shared, size_t shared_bytes,
                             const dh_private_key_t our_priv,
                             const dh_public_key_t their_pub);

INTERNAL otrv4_err_t otrv4_dh_mpi_serialize(uint8_t *dst, size_t dst_len, size_t *written,
                             const dh_mpi_t src);

INTERNAL otrv4_err_t otrv4_dh_mpi_deserialize(dh_mpi_t *dst, const uint8_t *buffer,
                               size_t buflen, size_t *nread);

INTERNAL otrv4_bool_t otrv4_dh_mpi_valid(dh_mpi_t mpi);

INTERNAL dh_mpi_t otrv4_dh_mpi_copy(const dh_mpi_t src);

INTERNAL void otrv4_dh_mpi_release(dh_mpi_t mpi);

#ifdef OTRV4_DH_PRIVATE

tstatic void dh_pub_key_destroy(dh_keypair_t keypair);

#endif

#endif
