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

/* goldilocks_448_point_t is in the twisted ed448-goldilocks,
   following the decaf technique. */
typedef goldilocks_448_scalar_t ec_scalar_t;
typedef goldilocks_448_point_t ec_point_t;

/** Number of bytes in an EdDSA private key. */
#define ED448_PRIVATE_BYTES GOLDILOCKS_EDDSA_448_PRIVATE_BYTES

/** Number of bytes in an EdDSA public key. */
#define ED448_POINT_BYTES GOLDILOCKS_EDDSA_448_PUBLIC_BYTES

/** Number of bytes in an EdDSA signature. */
#define ED448_SIGNATURE_BYTES GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES

/** Number of bytes in an non-secret scalar. */
#define ED448_SCALAR_BYTES GOLDILOCKS_448_SCALAR_BYTES

typedef uint8_t goldilocks_448_public_key_t[ED448_POINT_BYTES];
typedef uint8_t eddsa_signature_t[ED448_SIGNATURE_BYTES];

/* ECDH keypair */
typedef struct {
  ec_scalar_t priv;
  ec_point_t pub;
} ecdh_keypair_t;

typedef goldilocks_448_public_key_t ec_public_key_t;

/**
 * @brief Overwrite data with zeros.  Uses memset_s if available.
 *
 * @param data The data to be zeroed.
 * @param size The size of the data.
 */
INTERNAL void otrng_ec_bzero(void *data, size_t size);

/**
 * @brief Copy a scalar.  The scalars may use the same memory, in which
 * case this function does nothing.
 * @param [in] a A scalar.
 * @param [out] out Will become a copy of a.
 */
INTERNAL void otrng_ec_scalar_copy(ec_scalar_t dst, const ec_scalar_t a);

/**
 * @brief Compare two scalars.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @retval otrng_true The scalars are equal.
 * @retval otrng_false The scalars are not equal.
 */
INTERNAL otrng_bool_t otrng_ec_scalar_eq(const ec_scalar_t a,
                                         const ec_scalar_t b);
/**
 * @brief Encode a scalar to wire format.
 *
 * @param [out] enc Encoded form of a scalar.
 * @param [in] s Deserialized scalar.
 */
INTERNAL void otrng_ec_scalar_encode(uint8_t *enc, const ec_scalar_t s);

/**
 * @brief Read a scalar from wire format or from bytes.  Reduces mod
 * scalar prime.
 *
 * @param [in] enc Encoded form of a scalar.
 * @param [out] s Deserialized form.
 */
INTERNAL void otrng_ec_scalar_decode(ec_scalar_t s,
                                     const uint8_t enc[ED448_SCALAR_BYTES]);

/** Securely erase a scalar. */
INTERNAL void otrng_ec_scalar_destroy(ec_scalar_t s);

INTERNAL void otrng_ec_point_destroy(ec_point_t dst);

INTERNAL otrng_bool_t otrng_ec_point_valid(const ec_point_t p);

INTERNAL otrng_bool_t otrng_ec_point_eq(const ec_point_t, const ec_point_t);

/**
 * @brief EdDSA point encoding.
 * Multiplies by the cofactor first.
 *
 * The multiplication is required because the EdDSA encoding represents
 * the cofactor information, but the Decaf encoding ignores it (which
 * is the whole point).  So if you decode from EdDSA and re-encode to
 * EdDSA, the cofactor info must get cleared, because the intermediate
 * representation doesn't track it.
 *
 * @param [out] enc The encoded point.
 * @param [in] p The point.
 */
INTERNAL void otrng_ec_point_encode(uint8_t *enc, const ec_point_t p);

/**
 * @brief EdDSA point decoding.
 *
 * @param [out] enc The encoded point.
 * @param [in] p The point.
 */
INTERNAL otrng_err_t
otrng_ec_point_decode(ec_point_t p, const uint8_t enc[ED448_POINT_BYTES]);

INTERNAL void otrng_ec_point_copy(ec_point_t dst, const ec_point_t src);

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
