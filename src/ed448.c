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

#include <gcrypt.h>
#include <sodium.h>

#define OTRNG_ED448_PRIVATE

#include "ed448.h"

INTERNAL void otrng_ec_bzero(void *data, size_t size) {
  goldilocks_bzero(data, size);
}

INTERNAL void otrng_ec_scalar_copy(ec_scalar_t dst, const ec_scalar_t a) {
  goldilocks_448_scalar_copy(dst, a);
}

INTERNAL otrng_bool_t otrng_ec_scalar_eq(const ec_scalar_t a,
                                         const ec_scalar_t b) {
  if (goldilocks_448_scalar_eq(a, b))
    return otrng_true;

  return otrng_false;
}

INTERNAL void otrng_ec_scalar_encode(uint8_t *enc, const ec_scalar_t s) {
  goldilocks_448_scalar_encode(enc, s);
}

INTERNAL void otrng_ec_scalar_decode(ec_scalar_t s,
                                     const uint8_t enc[ED448_SCALAR_BYTES]) {
  goldilocks_448_scalar_decode_long(s, enc, ED448_SCALAR_BYTES);
}

INTERNAL void otrng_ec_scalar_destroy(ec_scalar_t s) {
  goldilocks_448_scalar_destroy(s);
}

INTERNAL void otrng_ec_point_copy(ec_point_t dst, const ec_point_t src) {
  goldilocks_448_point_copy(dst, src);
}

INTERNAL otrng_bool_t otrng_ec_point_eq(const ec_point_t p,
                                        const ec_point_t q) {
  if (goldilocks_448_point_eq(p, q))
    return otrng_true;

  return otrng_false;
}

INTERNAL otrng_bool_t otrng_ec_point_valid(const ec_point_t p) {
  if (goldilocks_448_point_valid(p))
    return otrng_true;

  return otrng_false;
}

INTERNAL void otrng_ec_point_encode(uint8_t *enc, const ec_point_t p) {
  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(enc, p);
}

INTERNAL otrng_err_t
otrng_ec_point_decode(ec_point_t p, const uint8_t enc[ED448_POINT_BYTES]) {
  goldilocks_448_point_t tmp_p;
  goldilocks_error_t err =
      goldilocks_448_point_decode_like_eddsa_and_mul_by_ratio(tmp_p, enc);
  if (GOLDILOCKS_SUCCESS != err)
    return ERROR;

  // The decoded point is equal to the original point * 2^2
  goldilocks_448_scalar_t r;
  goldilocks_448_scalar_copy(r, goldilocks_448_scalar_one);
  goldilocks_448_scalar_halve(r, r);
  goldilocks_448_scalar_halve(r, r);

  goldilocks_448_point_scalarmul(p, tmp_p, r);

  return SUCCESS;
}

INTERNAL void otrng_ec_point_destroy(ec_point_t p) {
  goldilocks_448_point_destroy(p);
}

INTERNAL void
otrng_ec_scalar_derive_from_secret(ec_scalar_t priv,
                                   uint8_t sym[ED448_PRIVATE_BYTES]) {
  /* Hash and clamp the secret into a scalar */
  goldilocks_ed448_derive_secret_scalar(priv, sym);
}

INTERNAL void
otrng_ec_derive_public_key(uint8_t pub[ED448_POINT_BYTES],
                           const uint8_t sym[ED448_PRIVATE_BYTES]) {
  goldilocks_ed448_derive_public_key(pub, sym);
}

INTERNAL void otrng_ecdh_keypair_generate(ecdh_keypair_t *keypair,
                                          uint8_t sym[ED448_PRIVATE_BYTES]) {
  otrng_ec_scalar_derive_from_secret(keypair->priv, sym);

  uint8_t pub[ED448_POINT_BYTES];
  otrng_ec_derive_public_key(pub, sym);
  otrng_ec_point_decode(keypair->pub, pub);

  goldilocks_bzero(sym, ED448_POINT_BYTES);
  goldilocks_bzero(pub, ED448_POINT_BYTES);
}

INTERNAL void otrng_ecdh_keypair_destroy(ecdh_keypair_t *keypair) {
  otrng_ec_scalar_destroy(keypair->priv);
  otrng_ec_point_destroy(keypair->pub);
}

INTERNAL void otrng_ecdh_shared_secret(uint8_t *shared,
                                       const ecdh_keypair_t *our_keypair,
                                       const ec_point_t their_pub) {
  goldilocks_448_point_t s;
  goldilocks_448_point_scalarmul(s, their_pub, our_keypair->priv);

  otrng_ec_point_encode(shared, s);
}

/* void ec_public_key_copy(ec_public_key_t dst, const ec_public_key_t src) { */
/*   memcpy(dst, src, sizeof(ec_public_key_t)); */
/* } */

static const char *ctx = "";

INTERNAL void otrng_ec_sign(eddsa_signature_t dst,
                            uint8_t sym[ED448_PRIVATE_BYTES],
                            uint8_t pubkey[ED448_POINT_BYTES],
                            const uint8_t *msg, size_t msg_len) {
  goldilocks_ed448_sign(dst, sym, pubkey, msg, msg_len, 0, (uint8_t *)ctx,
                        strlen(ctx));
}

INTERNAL otrng_bool_t otrng_ec_verify(const uint8_t sig[ED448_SIGNATURE_BYTES],
                                      const uint8_t pubkey[ED448_POINT_BYTES],
                                      const uint8_t *msg, size_t msg_len) {
  if (goldilocks_ed448_verify(sig, pubkey, msg, msg_len, 0, (uint8_t *)ctx,
                              strlen(ctx)))
    return otrng_true;

  return otrng_false;
}
