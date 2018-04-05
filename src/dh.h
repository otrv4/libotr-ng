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

#ifndef OTRNG_DH_H
#define OTRNG_DH_H

#include <gcrypt.h>
#include <stdint.h>

#include "error.h"
#include "shared.h"

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

INTERNAL void otrng_dh_init(void);

INTERNAL void otrng_dh_free(void);

INTERNAL otrng_err_t otrng_dh_keypair_generate(dh_keypair_t keypair);

INTERNAL void otrng_dh_priv_key_destroy(dh_keypair_t keypair);

INTERNAL void otrng_dh_keypair_destroy(dh_keypair_t keypair);

INTERNAL otrng_err_t otrng_dh_shared_secret(uint8_t *shared,
                                            size_t shared_bytes,
                                            const dh_private_key_t our_priv,
                                            const dh_public_key_t their_pub);

INTERNAL otrng_err_t otrng_dh_mpi_serialize(uint8_t *dst, size_t dst_len,
                                            size_t *written,
                                            const dh_mpi_t src);

INTERNAL otrng_err_t otrng_dh_mpi_deserialize(dh_mpi_t *dst,
                                              const uint8_t *buffer,
                                              size_t buflen, size_t *nread);

INTERNAL otrng_bool_t otrng_dh_mpi_valid(dh_mpi_t mpi);

INTERNAL dh_mpi_t otrng_dh_mpi_copy(const dh_mpi_t src);

INTERNAL void otrng_dh_mpi_release(dh_mpi_t mpi);

#ifdef OTRNG_DH_PRIVATE

tstatic void dh_pub_key_destroy(dh_keypair_t keypair);

#endif

#endif
