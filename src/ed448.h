/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

/**
 * The functions in this file only operate on their arguments, and doesn't touch
 * any global state. It is safe to call these functions concurrently from
 * different threads, as long as arguments pointing to the same memory areas are
 * not used from different threads.
 */

#ifndef OTRNG_ED448_H
#define OTRNG_ED448_H

#include <goldilocks.h>
#include <goldilocks/ed448.h>
#include <stdint.h>
#include <stdio.h>

#include "error.h"
#include "shared.h"

/* ec_scalar represents a scalar. */
typedef goldilocks_448_scalar_p ec_scalar;
/* ec_point represents a ed488 point. It is in the twisted ed448-goldilocks,
   curve representation following the decaf technique. */
typedef goldilocks_448_point_p ec_point;

/** Number of bytes in an EdDSA private key: 57 */
#define ED448_PRIVATE_BYTES GOLDILOCKS_EDDSA_448_PRIVATE_BYTES

/** Number of bytes in an EdDSA public key: 57 */
#define ED448_POINT_BYTES GOLDILOCKS_EDDSA_448_PUBLIC_BYTES

/** Number of bytes in an EdDSA signature: 114 */
#define ED448_SIGNATURE_BYTES GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES

/** Number of bytes in an non-secret scalar: 56 */
#define ED448_SCALAR_BYTES GOLDILOCKS_448_SCALAR_BYTES

typedef uint8_t eddsa_signature[ED448_SIGNATURE_BYTES];

/**
 * @brief The ecdh_keypair_s structure represents an ECDH keypair.
 *
 *  [priv] the private key
 *  [pub]  the public key
 */
typedef struct ecdh_keypair_s {
  ec_scalar priv;
  ec_point pub;
} ecdh_keypair_s;

/**
 * @brief Copy a scalar.  The scalars may use the same memory, in which
 *    case this function does nothing.
 *
 * @param [a]   A scalar.
 * @param [out] Will become a copy of a.
 */
INTERNAL void otrng_ec_scalar_copy(ec_scalar dst, const ec_scalar a);

/**
 * @brief Compare two scalars.
 *
 * @param [a] One scalar.
 * @param [b] Another scalar.
 *
 * @retval otrng_true The scalars are equal.
 * @retval otrng_false The scalars are not equal.
 */
INTERNAL otrng_bool otrng_ec_scalar_eq(const ec_scalar a, const ec_scalar b);
/**
 * @brief Encode a scalar to wire format.
 *
 * @param [enc] Encoded form of a scalar.
 * @param [s] Deserialized scalar.
 */
INTERNAL void otrng_ec_scalar_encode(uint8_t *enc, const ec_scalar s);

/**
 * @brief Read a scalar from wire format or from bytes.  Reduces mod
 * scalar prime.
 *
 * @param [enc] Encoded form of a scalar.
 * @param [s] Deserialized form.
 */
INTERNAL void otrng_ec_scalar_decode(ec_scalar s,
                                     const uint8_t enc[ED448_SCALAR_BYTES]);

/** Securely erase a scalar. */
INTERNAL void otrng_ec_scalar_destroy(ec_scalar s);

/**
 * @brief Copy a point.  The input and output may alias,
 *    in which case this function does nothing.
 *
 * @param [dst] A copy of the point.
 * @param [p] Any point.
 */
INTERNAL void otrng_ec_point_copy(ec_point dst, const ec_point p);

/**
 * @brief Check whether two points are equal.  If yes, return
 *    otrng_true, else return otrng_false.
 *
 * @param [p] A point.
 * @param [q] Another point.
 *
 * @retval otrng_true The points are equal.
 * @retval otrng_false The points are not equal.
 */
INTERNAL otrng_bool otrng_ec_point_eq(const ec_point p, const ec_point q);

/**
 * @brief Check that a point is valid.
 *
 * @param [p] The point to check.
 *
 * @retval otrng_true The point is valid.
 * @retval otrng_false The point is invalid.
 */
INTERNAL otrng_bool otrng_ec_point_valid(const ec_point p);

/**
 * @brief EdDSA point encoding.
 *    Multiplies by the cofactor first.
 *
 * The multiplication is required because the EdDSA encoding represents
 * the cofactor information, but the Decaf encoding ignores it (which
 * is the whole point).  So if you decode from EdDSA and re-encode to
 * EdDSA, the cofactor info must get cleared, because the intermediate
 * representation doesn't track it.
 *
 * @param [enc] The encoded point.
 * @param [enc] The lenght of the encoded point.
 * @param [p]   The point.
 */
INTERNAL otrng_result otrng_ec_point_encode(uint8_t *enc, size_t len,
                                            const ec_point p);

/**
 * @brief EdDSA point decoding.
 *
 * @param [enc] The encoded point.
 * @param [p]   The point.
 */
INTERNAL otrng_result
otrng_ec_point_decode(ec_point p, const uint8_t enc[ED448_POINT_BYTES]);

/** Securely erase a point by overwriting it with zeros.
 * @warning This causes the point object to become invalid.
 */
INTERNAL void otrng_ec_point_destroy(ec_point p);

/**
 * @brief EdDSA key secret key generation.
 *
 * @param [priv] The private key.
 * @param [sym]  The symmetric key.
 */
INTERNAL void
otrng_ec_scalar_derive_from_secret(ec_scalar priv,
                                   const uint8_t sym[ED448_PRIVATE_BYTES]);

/**
 * @brief EdDSA key generation.
 *
 * @param [pub] The public key.
 * @param [sym] The private key.
 */
INTERNAL void
otrng_ec_derive_public_key(uint8_t pub[ED448_POINT_BYTES],
                           const uint8_t sym[ED448_PRIVATE_BYTES]);

INTERNAL void otrng_ec_calculate_public_key(ec_point pub, const ec_scalar priv);

/**
 * @brief Keypair generation.
 *
 * @param [keypair] The keypair.
 * @param [sym]     The private key.
 *
 * @warning The symmetric key is stored as the priv part
 */
INTERNAL otrng_result otrng_ecdh_keypair_generate(
    ecdh_keypair_s *keypair, const uint8_t sym[ED448_PRIVATE_BYTES]);

/**
 * @brief Securely destroy the keypair.
 *
 * @param [keypair] The keypair.
 *
 */
INTERNAL void otrng_ecdh_keypair_destroy(ecdh_keypair_s *keypair);

/**
 * @brief ECDH shared secret generation.
 *
 * @param [shared_secret] The shared secret.
 * @param [our_priv]      Our private key.
 * @param [their_pub]     The other party's public key.
 *
 * @warning The symmetric key is stored as the priv part
 */
INTERNAL otrng_result otrng_ecdh_shared_secret(uint8_t *shared_secret,
                                               size_t shared_secret_len,
                                               const ec_scalar our_priv,
                                               const ec_point their_pub);

/**
 * @brief EdDSA signing.
 *
 * @param [sig]     The signature.
 * @param [sym]     The symmetric key.
 * @param [msg]     The message to sign.
 * @param [msg_len] The length of the message.
 *
 * @warning It is not prehashed. The context is always an empty string
 */
INTERNAL void otrng_ec_sign_simple(eddsa_signature sig,
                                   const uint8_t sym[ED448_PRIVATE_BYTES],
                                   const uint8_t *msg, size_t msg_len);

/**
 * @brief EdDSA signature verification.
 *
 * @param [sig]     The signature.
 * @param [pub]     The public key.
 * @param [msg]     The message to verify.
 * @param [msg_len] The length of the message.
 *
 * @warning It is not prehashed. The context is always an empty string
 */
INTERNAL otrng_bool otrng_ec_verify(
    const uint8_t sig[GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t pub[ED448_POINT_BYTES], const uint8_t *msg, size_t msg_len);

INTERNAL otrng_result otrng_ecdh_keypair_generate_their(
    ec_point keypair, const uint8_t sym[ED448_PRIVATE_BYTES]);

#ifdef DEBUG_API
API void otrng_ecdh_keypair_debug_print(FILE *, int, ecdh_keypair_s *);
#endif

#ifdef OTRNG_ED448_PRIVATE

/**
 * @brief EdDSA signing.
 *
 * @param [sig]     The signature.
 * @param [sym]     The symmetric key.
 * @param [pub]     The public key.
 * @param [msg]     The message to sign.
 * @param [msg_len] The length of the message.
 *
 * @warning It is not prehashed. The context is always an empty string
 */
tstatic void otrng_ec_sign(eddsa_signature sig,
                           const uint8_t sym[ED448_PRIVATE_BYTES],
                           const uint8_t pub[ED448_POINT_BYTES],
                           const uint8_t *msg, size_t msg_len);

#endif

#endif
