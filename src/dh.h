/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
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

#ifndef S_SPLINT_S
#include <gcrypt.h>
#endif

#include <stdint.h>

#include "constants.h"
#include "error.h"
#include "shared.h"

#define DH_KEY_SIZE 80
#define DH3072_MOD_LEN_BYTES 384
#define DH3072_MOD_LEN_BITS (DH3072_MOD_LEN_BYTES * 8)
#define DH_MPI_MAX_BYTES (4 + DH3072_MOD_LEN_BYTES)

typedef gcry_mpi_t dh_mpi;
typedef dh_mpi dh_private_key, dh_public_key;
typedef uint8_t dh_shared_secret[DH3072_MOD_LEN_BYTES];

typedef struct dh_keypair_s {
  dh_public_key pub;
  dh_private_key priv;
} dh_keypair_s;

INTERNAL otrng_result otrng_dh_init(otrng_bool die);
INTERNAL void otrng_dh_free(void);

INTERNAL void otrng_dh_calculate_public_key(dh_public_key pub,
                                            const dh_private_key priv);

INTERNAL otrng_result otrng_dh_keypair_generate(dh_keypair_s *keypair);

/**
 * @param [participant]   If this corresponds to our or their key manager. 'u'
 * for us, 't' for them
 */
INTERNAL otrng_result otrng_dh_keypair_generate_from_shared_secret(
    uint8_t shared_secret[SHARED_SECRET_BYTES], dh_keypair_s *keypair,
    const char participant);

INTERNAL void otrng_dh_priv_key_destroy(dh_keypair_s *keypair);

INTERNAL void otrng_dh_keypair_destroy(dh_keypair_s *keypair);

INTERNAL otrng_result otrng_dh_shared_secret(dh_shared_secret buffer,
                                             size_t *written,
                                             const dh_private_key our_priv,
                                             const dh_public_key their_pub);

INTERNAL otrng_result otrng_dh_mpi_serialize(uint8_t *dst, size_t dst_len,
                                             size_t *written, const dh_mpi src);

INTERNAL otrng_result otrng_dh_mpi_deserialize(dh_mpi *dst,
                                               const uint8_t *buffer,
                                               size_t buf_len, size_t *nread);

INTERNAL otrng_bool otrng_dh_mpi_valid(dh_mpi mpi);

INTERNAL dh_mpi otrng_dh_mpi_copy(const dh_mpi src);

INTERNAL void otrng_dh_mpi_release(dh_mpi mpi);

INTERNAL /*@null@*/ dh_mpi otrng_dh_modulus_q(void);
INTERNAL /*@null@*/ dh_mpi otrng_dh_modulus_p(void);

#ifdef DEBUG_API
API void otrng_dh_keypair_debug_print(FILE *, int, dh_keypair_s *);
API void otrng_dh_public_key_debug_print(FILE *, dh_public_key);
API void otrng_dh_private_key_debug_print(FILE *, dh_private_key);
#endif

#ifdef OTRNG_DH_PRIVATE

INTERNAL /*@null@*/ dh_mpi otrng_dh_mpi_generator(void);

#endif

#endif
