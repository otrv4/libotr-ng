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

#ifndef OTRNG_AUTH_H
#define OTRNG_AUTH_H

#include <stddef.h>

#include "ed448.h"
#include "keys.h"
#include "shared.h"

#define SNIZKPK_BYTES 6 * ED448_SCALAR_BYTES

typedef ec_scalar_t snizkpk_privkey_t;
typedef ec_point_t snizkpk_pubkey_t;
typedef otrng_keypair_t snizkpk_keypair_t;

typedef struct {
  ec_scalar_t c1;
  ec_scalar_t r1;
  ec_scalar_t c2;
  ec_scalar_t r2;
  ec_scalar_t c3;
  ec_scalar_t r3;
} snizkpk_proof_t;

INTERNAL void otrng_snizkpk_keypair_generate(snizkpk_keypair_t *pair);

INTERNAL void
otrng_snizkpk_authenticate(snizkpk_proof_t *dst, const snizkpk_keypair_t *pair1,
                           const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3,
                           const unsigned char *msg, size_t msglen);

INTERNAL otrng_bool_t otrng_snizkpk_verify(const snizkpk_proof_t *src,
                                           const snizkpk_pubkey_t A1,
                                           const snizkpk_pubkey_t A2,
                                           const snizkpk_pubkey_t A3,
                                           const unsigned char *msg,
                                           size_t msglen);

INTERNAL void otrng_generate_keypair(snizkpk_pubkey_t pub,
                                     snizkpk_privkey_t priv);

INTERNAL void otrng_snizkpk_proof_destroy(snizkpk_proof_t *src);

#ifdef OTRNG_AUTH_PRIVATE
#endif

#endif
