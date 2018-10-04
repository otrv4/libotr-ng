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

#include <goldilocks/common.h>
#include <goldilocks/point_448.h>
#include <string.h>

#define OTRNG_ED448_PRIVATE

#include "alloc.h"
#include "ed448.h"
#include "shake.h"

INTERNAL void otrng_ec_scalar_copy(ec_scalar dst, const ec_scalar a) {
  goldilocks_448_scalar_copy(dst, a);
}

INTERNAL otrng_bool otrng_ec_scalar_eq(const ec_scalar a, const ec_scalar b) {
  if (goldilocks_448_scalar_eq(a, b)) {
    return otrng_true;
  }

  return otrng_false;
}

INTERNAL void otrng_ec_scalar_encode(uint8_t *enc, const ec_scalar s) {
  goldilocks_448_scalar_encode(enc, s);
}

INTERNAL void otrng_ec_scalar_decode(ec_scalar s,
                                     const uint8_t enc[ED448_SCALAR_BYTES]) {
  goldilocks_448_scalar_decode_long(s, enc, ED448_SCALAR_BYTES);
}

INTERNAL void otrng_ec_scalar_destroy(ec_scalar s) {
  goldilocks_448_scalar_destroy(s);
}

INTERNAL void otrng_ec_point_copy(ec_point dst, const ec_point p) {
  goldilocks_448_point_copy(dst, p);
}

INTERNAL otrng_bool otrng_ec_point_eq(const ec_point p, const ec_point q) {
  if (goldilocks_448_point_eq(p, q)) {
    return otrng_true;
  }

  return otrng_false;
}

INTERNAL otrng_bool otrng_ec_point_valid(const ec_point p) {
  if (goldilocks_448_point_valid(p)) {
    return otrng_true;
  }

  return otrng_false;
}

API otrng_result otrng_ec_point_encode(uint8_t *enc, size_t len,
                                       const ec_point p) {
  if (len < ED448_POINT_BYTES) {
    return OTRNG_ERROR;
  }

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(enc, p);

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result
otrng_ec_point_decode(ec_point p, const uint8_t enc[ED448_POINT_BYTES]) {
  goldilocks_448_point_p tmp_p;
  goldilocks_448_scalar_p r;

  if (!goldilocks_succeed_if(
          goldilocks_448_point_decode_like_eddsa_and_mul_by_ratio(tmp_p,
                                                                  enc))) {
    return OTRNG_ERROR;
  }

  // The decoded point is equal to the original point * 2^2
  goldilocks_448_scalar_copy(r, goldilocks_448_scalar_one);
  goldilocks_448_scalar_halve(r, r);
  goldilocks_448_scalar_halve(r, r);

  goldilocks_448_point_scalarmul(p, tmp_p, r);

  return OTRNG_SUCCESS;
}

INTERNAL void otrng_ec_point_destroy(ec_point p) {
  goldilocks_448_point_destroy(p);
}

INTERNAL void
otrng_ec_scalar_derive_from_secret(ec_scalar priv,
                                   const uint8_t sym[ED448_PRIVATE_BYTES]) {
  /* Hash and clamp the secret into a scalar as per RFC 8032 */
  goldilocks_ed448_derive_secret_scalar(priv, sym);
}

INTERNAL void
otrng_ec_derive_public_key(uint8_t pub[ED448_POINT_BYTES],
                           const uint8_t sym[ED448_PRIVATE_BYTES]) {
  /* Hash and clamp the secret into a scalar and multiplies by our generator */
  goldilocks_ed448_derive_public_key(pub, sym);
}

INTERNAL void otrng_ec_calculate_public_key(ec_point pub,
                                            const ec_scalar priv) {
  goldilocks_448_precomputed_scalarmul(pub, goldilocks_448_precomputed_base,
                                       priv);
}

INTERNAL void
otrng_ecdh_keypair_generate(ecdh_keypair_s *keypair,
                            const uint8_t sym[ED448_PRIVATE_BYTES]) {
  /*
   * The spec requires:

   1. r = rand(57)
   2. s = little-endian-decode(clamp(r))

   3. secret = s
   4. public = G * s
  */
  uint8_t pub[ED448_POINT_BYTES];

  otrng_ec_scalar_derive_from_secret(keypair->priv, sym);

  otrng_ec_derive_public_key(pub, sym);
  otrng_ec_point_decode(keypair->pub, pub);

  otrng_secure_wipe(pub, ED448_POINT_BYTES);
}

INTERNAL void
otrng_ecdh_keypair_generate_their(ec_point keypair,
                                  const uint8_t sym[ED448_PRIVATE_BYTES]) {
  /*
   * The spec requires, in `generateECDH()`:

   1. r = rand(57)
   2. s = little-endian-decode(clamp(r))

   3. public = G * s

  */

  uint8_t pub[ED448_POINT_BYTES];
  otrng_ec_derive_public_key(pub, sym);
  otrng_ec_point_decode(keypair, pub);

  otrng_secure_wipe(pub, ED448_POINT_BYTES);
}

INTERNAL void otrng_ecdh_keypair_destroy(ecdh_keypair_s *keypair) {
  otrng_ec_scalar_destroy(keypair->priv);
  otrng_ec_point_destroy(keypair->pub);
}

static otrng_bool otrng_ecdh_valid_secret(uint8_t *shared_secret,
                                          size_t shared_secret_len) {
  uint8_t zero_buffer[ED448_POINT_BYTES];

  memset(zero_buffer, 0, ED448_POINT_BYTES);

  if (shared_secret_len < ED448_POINT_BYTES) {
    return otrng_false;
  }

  // TODO: I think this is a horrible way to check for zero values
  if (memcmp(shared_secret, zero_buffer, ED448_POINT_BYTES) == 0) {
    return otrng_false;
  }

  return otrng_true;
}

INTERNAL otrng_result otrng_ecdh_shared_secret(uint8_t *shared_secret,
                                               size_t shared_secret_len,
                                               const ec_scalar our_priv,
                                               const ec_point their_pub) {
  goldilocks_448_point_p p;
  goldilocks_448_point_scalarmul(p, their_pub, our_priv);

  if (!otrng_ec_point_valid(p)) {
    return OTRNG_ERROR;
  }

  if (!otrng_ec_point_encode(shared_secret, shared_secret_len, p)) {
    return OTRNG_ERROR;
  }

  if (!otrng_ecdh_valid_secret(shared_secret, shared_secret_len)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

tstatic void otrng_ec_sign(eddsa_signature sig,
                           const uint8_t sym[ED448_PRIVATE_BYTES],
                           const uint8_t pub[ED448_POINT_BYTES],
                           const uint8_t *msg, size_t msg_len) {
  goldilocks_ed448_sign(sig, sym, pub, msg, msg_len, 0, NULL, 0);
}

INTERNAL void otrng_ec_sign_simple(eddsa_signature sig,
                                   const uint8_t sym[ED448_PRIVATE_BYTES],
                                   const uint8_t *msg, size_t msg_len) {
  uint8_t pub[ED448_POINT_BYTES];

  memset(pub, 0, ED448_POINT_BYTES);
  otrng_ec_derive_public_key(pub, sym);
  otrng_ec_sign(sig, sym, pub, msg, msg_len);
}

INTERNAL otrng_bool otrng_ec_verify(const uint8_t sig[ED448_SIGNATURE_BYTES],
                                    const uint8_t pub[ED448_POINT_BYTES],
                                    const uint8_t *msg, size_t msg_len) {
  if (goldilocks_ed448_verify(sig, pub, msg, msg_len, 0, NULL, 0)) {
    return otrng_true;
  }

  return otrng_false;
}

#ifdef DEBUG_API

#include "debug.h"
#include "keys.h"

API void otrng_ecdh_keypair_debug_print(FILE *f, int indent,
                                        ecdh_keypair_s *k) {
  if (otrng_debug_print_should_ignore("ecdh_keypair")) {
    return;
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "ecdh_keypair {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("ecdh_keypair->pub")) {
    debug_api_print(f, "pub = IGNORED\n");
  } else {
    debug_api_print(f, "pub = ");
    otrng_public_key_debug_print(f, k->pub);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("ecdh_keypair->priv")) {
    debug_api_print(f, "priv = IGNORED\n");
  } else {
    debug_api_print(f, "priv = ");
    otrng_private_key_debug_print(f, k->priv);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // ecdh_keypair\n");
}

#endif /* DEBUG */
