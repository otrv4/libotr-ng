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

/* ec_scalar_p represents a scalar. */
typedef goldilocks_448_scalar_p ec_scalar_p;
/* ec_point_p represents a ed488 point. It is in the twisted ed448-goldilocks,
   curve representation following the decaf technique. */
typedef goldilocks_448_point_p ec_point_p;

/** Number of bytes in an EdDSA private key: 57 */
#define ED448_PRIVATE_BYTES GOLDILOCKS_EDDSA_448_PRIVATE_BYTES

/** Number of bytes in an EdDSA public key: 57 */
#define ED448_POINT_BYTES GOLDILOCKS_EDDSA_448_PUBLIC_BYTES

/** Number of bytes in an EdDSA signature: 114 */
#define ED448_SIGNATURE_BYTES GOLDILOCKS_EDDSA_448_SIGNATURE_BYTES

/** Number of bytes in an non-secret scalar: 56 */
#define ED448_SCALAR_BYTES GOLDILOCKS_448_SCALAR_BYTES

typedef uint8_t goldilocks_448_public_key_p[ED448_POINT_BYTES];
typedef uint8_t eddsa_signature_p[ED448_SIGNATURE_BYTES];

/**
 * @brief The ecdh_keypair_s structure represents an ECDH keypair.
 *
 *  [priv] the private key
 *  [pub]  the public key
 */
typedef struct ecdh_keypair_s {
  ec_scalar_p priv;
  ec_point_p pub;
} ecdh_keypair_s, ecdh_keypair_p[1];

/**
 * @brief Overwrite data with zeros.  Uses memset_s if available.
 *
 * @param [data] The data to be zeroed.
 * @param [size] The size of the data.
 */
INTERNAL void otrng_ec_bzero(void *data, size_t size);

/**
 * @brief Copy a scalar.  The scalars may use the same memory, in which
 *    case this function does nothing.
 *
 * @param [a]   A scalar.
 * @param [out] Will become a copy of a.
 */
INTERNAL void otrng_ec_scalar_copy(ec_scalar_p dst, const ec_scalar_p a);

/**
 * @brief Compare two scalars.
 *
 * @param [a] One scalar.
 * @param [b] Another scalar.
 *
 * @retval otrng_true The scalars are equal.
 * @retval otrng_false The scalars are not equal.
 */
INTERNAL otrng_bool otrng_ec_scalar_eq(const ec_scalar_p a,
                                       const ec_scalar_p b);
/**
 * @brief Encode a scalar to wire format.
 *
 * @param [enc] Encoded form of a scalar.
 * @param [s] Deserialized scalar.
 */
INTERNAL void otrng_ec_scalar_encode(uint8_t *enc, const ec_scalar_p s);

/**
 * @brief Read a scalar from wire format or from bytes.  Reduces mod
 * scalar prime.
 *
 * @param [enc] Encoded form of a scalar.
 * @param [s] Deserialized form.
 */
INTERNAL void otrng_ec_scalar_decode(ec_scalar_p s,
                                     const uint8_t enc[ED448_SCALAR_BYTES]);

/** Securely erase a scalar. */
INTERNAL void otrng_ec_scalar_destroy(ec_scalar_p s);

/**
 * @brief Copy a point.  The input and output may alias,
 *    in which case this function does nothing.
 *
 * @param [dst] A copy of the point.
 * @param [p] Any point.
 */
INTERNAL void otrng_ec_point_copy(ec_point_p dst, const ec_point_p p);

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
INTERNAL otrng_bool otrng_ec_point_eq(const ec_point_p p, const ec_point_p q);

/**
 * @brief Check that a point is valid.
 *
 * @param [p] The point to check.
 *
 * @retval otrng_true The point is valid.
 * @retval otrng_false The point is invalid.
 */
INTERNAL otrng_bool otrng_ec_point_valid(const ec_point_p p);

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
                                         const ec_point_p p);

/**
 * @brief EdDSA point decoding.
 *
 * @param [enc] The encoded point.
 * @param [p]   The point.
 */
INTERNAL otrng_result otrng_ec_point_decode(ec_point_p p,
                                         const uint8_t enc[ED448_POINT_BYTES]);

/** Securely erase a point by overwriting it with zeros.
 * @warning This causes the point object to become invalid.
 */
INTERNAL void otrng_ec_point_destroy(ec_point_p p);

/**
 * @brief EdDSA key secret key generation.
 *
 * @param [priv] The private key.
 * @param [sym]  The symmetric key.
 */
INTERNAL void
otrng_ec_scalar_derive_from_secret(ec_scalar_p priv,
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

INTERNAL void otrng_ec_calculate_public_key(ec_point_p pub,
                                            const ec_scalar_p priv);

/**
 * @brief Keypair generation.
 *
 * @param [keypair] The keypair.
 * @param [sym]     The private key.
 *
 * @warning The symmetric key is stored as the priv part
 */
INTERNAL void
otrng_ecdh_keypair_generate(ecdh_keypair_s *keypair,
                            const uint8_t sym[ED448_PRIVATE_BYTES]);

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
                                            const ec_scalar_p our_priv,
                                            const ec_point_p their_pub);

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
INTERNAL void otrng_ec_sign(eddsa_signature_p sig,
                            const uint8_t sym[ED448_PRIVATE_BYTES],
                            const uint8_t pub[ED448_POINT_BYTES],
                            const uint8_t *msg, size_t msg_len);

INTERNAL void otrng_ec_sign_simple(eddsa_signature_p sig,
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

INTERNAL void
otrng_ecdh_keypair_generate_their(ec_point_p keypair,
                                  const uint8_t sym[ED448_PRIVATE_BYTES]);

#ifdef OTRNG_ED448_PRIVATE
#endif

#endif
