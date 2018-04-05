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

#ifndef OTRNG_ED448_H
#define OTRNG_ED448_H

#include <goldilocks.h>
#include <goldilocks/ed448.h>
#include <stdint.h>

#include "error.h"
#include "shared.h"

/* goldilocks_448_point_t is in the twisted ed448-goldilocks. */
typedef goldilocks_448_scalar_t ec_scalar_t;
typedef goldilocks_448_point_t ec_point_t;

/* Serialize points and scalars using EdDSA wire format. */
#define ED448_PRIVATE_BYTES GOLDILOCKS_EDDSA_448_PRIVATE_BYTES
#define ED448_POINT_BYTES GOLDILOCKS_EDDSA_448_PUBLIC_BYTES
#define ED448_SIGNATURE_BYTES GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES
#define ED448_SCALAR_BYTES GOLDILOCKS_448_SCALAR_BYTES

typedef uint8_t goldilocks_448_public_key_t[ED448_POINT_BYTES];
typedef uint8_t eddsa_signature_t[ED448_SIGNATURE_BYTES];

/* ECDH keypair */
typedef struct {
  ec_scalar_t priv;
  ec_point_t pub;
} ecdh_keypair_t;

typedef goldilocks_448_public_key_t ec_public_key_t;

INTERNAL void otrng_ec_bzero(void *data, size_t size);

INTERNAL otrng_bool_t otrng_ec_scalar_eq(const ec_scalar_t a,
                                         const ec_scalar_t b);

INTERNAL otrng_err_t otrng_ec_scalar_serialize(uint8_t *dst, size_t dst_len,
                                               const ec_scalar_t scalar);

INTERNAL void
otrng_ec_scalar_deserialize(ec_scalar_t scalar,
                            const uint8_t serialized[ED448_SCALAR_BYTES]);

INTERNAL void otrng_ec_scalar_copy(ec_scalar_t dst, const ec_scalar_t src);

INTERNAL void otrng_ec_scalar_destroy(ec_scalar_t dst);

INTERNAL void otrng_ec_point_copy(ec_point_t dst, const ec_point_t src);

INTERNAL void otrng_ec_point_destroy(ec_point_t dst);

INTERNAL otrng_bool_t otrng_ec_point_valid(const ec_point_t point);

INTERNAL otrng_bool_t otrng_ec_point_eq(const ec_point_t, const ec_point_t);

INTERNAL void otrng_ec_point_serialize(uint8_t *dst, const ec_point_t point);

INTERNAL otrng_err_t otrng_ec_point_deserialize(
    ec_point_t point, const uint8_t serialized[ED448_POINT_BYTES]);

/* This is ed448 crypto */
INTERNAL void
otrng_ec_scalar_derive_from_secret(ec_scalar_t priv,
                                   uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL void
otrng_ec_derive_public_key(uint8_t pub[ED448_POINT_BYTES],
                           const uint8_t priv[ED448_PRIVATE_BYTES]);

INTERNAL void otrng_ecdh_keypair_generate(ecdh_keypair_t *keypair,
                                          uint8_t sym[ED448_PRIVATE_BYTES]);
INTERNAL void otrng_ecdh_keypair_destroy(ecdh_keypair_t *keypair);

INTERNAL void otrng_ecdh_shared_secret(uint8_t *shared,
                                       const ecdh_keypair_t *our_keypair,
                                       const ec_point_t their_pub);

/* void ec_public_key_copy(ec_public_key_t dst, const ec_public_key_t src); */

INTERNAL void otrng_ec_sign(eddsa_signature_t dst,
                            uint8_t sym[ED448_PRIVATE_BYTES],
                            uint8_t pubkey[ED448_POINT_BYTES],
                            const uint8_t *msg, size_t msg_len);

INTERNAL otrng_bool_t otrng_ec_verify(
    const uint8_t sig[GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t pub[ED448_POINT_BYTES], const uint8_t *msg, size_t msg_len);

#ifdef OTRNG_ED448_PRIVATE
#endif

#endif
