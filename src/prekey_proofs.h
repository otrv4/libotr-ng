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

#define PROOF_C_SIZE 64

typedef struct ecdh_proof_s {
  uint8_t c[PROOF_C_SIZE];
  ec_scalar_p v;
} ecdh_proof_s, ecdh_proof_p[1];

typedef struct dh_proof_s {
  uint8_t c[PROOF_C_SIZE];
  dh_mpi_p v;
} dh_proof_s, dh_proof_p[1];

INTERNAL otrng_result ecdh_proof_generate(ecdh_proof_p dst,
                                          const ec_scalar_p *values_priv,
                                          const ec_point_p *values_pub,
                                          const size_t values_len,
                                          const uint8_t *m,
                                          const uint8_t usage);

INTERNAL otrng_bool ecdh_proof_verify(ecdh_proof_p px,
                                      const ec_point_p *values_pub,
                                      const size_t values_len, const uint8_t *m,
                                      const uint8_t usage);

INTERNAL otrng_result dh_proof_generate(dh_proof_p dst,
                                        const dh_mpi_p *values_priv,
                                        const dh_mpi_p *values_pub,
                                        const size_t values_len,
                                        const uint8_t *m, const uint8_t usage);

INTERNAL otrng_bool dh_proof_verify(dh_proof_p px, const dh_mpi_p *values_pub,
                                    const size_t values_len, const uint8_t *m,
                                    const uint8_t usage);

#ifdef OTRNG_PREKEY_PROOFS_PRIVATE
#endif

#endif // OTRNG_PREKEY_PROOFS_H