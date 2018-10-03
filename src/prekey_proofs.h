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

#ifndef OTRNG_PREKEY_PROOFS_H
#define OTRNG_PREKEY_PROOFS_H

#include <stdint.h>

#include "dh.h"
#include "ed448.h"
#include "random.h"

#define PROOF_C_SIZE 64

typedef struct ecdh_proof_s {
  uint8_t c[PROOF_C_SIZE];
  ec_scalar v;
} ecdh_proof_s;

typedef struct dh_proof_s {
  uint8_t c[PROOF_C_SIZE];
  dh_mpi v;
} dh_proof_s;

INTERNAL otrng_result otrng_ecdh_proof_generate(ecdh_proof_s *destination,
                                                const ec_scalar *values_priv,
                                                const ec_point *values_pub,
                                                const size_t values_len,
                                                const uint8_t *m,
                                                const uint8_t usage);

INTERNAL otrng_bool otrng_ecdh_proof_verify(ecdh_proof_s *px,
                                            const ec_point *values_pub,
                                            const size_t values_len,
                                            const uint8_t *m,
                                            const uint8_t usage);

INTERNAL otrng_result otrng_dh_proof_generate(
    dh_proof_s *destination, const dh_mpi *values_priv,
    const dh_mpi *values_pub, const size_t values_len, const uint8_t *m,
    const uint8_t usage, random_generator gen);

INTERNAL otrng_bool otrng_dh_proof_verify(dh_proof_s *px,
                                          const dh_mpi *values_pub,
                                          const size_t values_len,
                                          const uint8_t *m,
                                          const uint8_t usage);

INTERNAL size_t otrng_ecdh_proof_serialize(uint8_t *destination,
                                           const ecdh_proof_s *px);
INTERNAL size_t otrng_dh_proof_serialize(uint8_t *destination,
                                         const dh_proof_s *px);
INTERNAL otrng_result otrng_ecdh_proof_deserialize(ecdh_proof_s *px,
                                                   const uint8_t *serialized,
                                                   size_t ser_len,
                                                   size_t *read);
INTERNAL otrng_result otrng_dh_proof_deserialize(dh_proof_s *px,
                                                 const uint8_t *serialized,
                                                 size_t ser_len, size_t *read);

#ifdef OTRNG_PREKEY_PROOFS_PRIVATE
#endif

#endif // OTRNG_PREKEY_PROOFS_H
