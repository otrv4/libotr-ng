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

#include "test_helpers.h"

#include "ed448.h"
#include "goldilocks.h"
#include "goldilocks/ed448.h"
#include "random.h"

static void test_ed448_eddsa_serialization() {
  ec_scalar_t s;
  uint8_t random_buff[ED448_SCALAR_BYTES];
  random_bytes(random_buff, ED448_SCALAR_BYTES);
  goldilocks_448_scalar_decode_long(s, random_buff, ED448_SCALAR_BYTES);

  // 1. Create a point p
  ec_point p;
  goldilocks_448_point_scalarmul(p, goldilocks_448_point_base, s);

  // 2. Encode like EdDSA
  uint8_t enc[GOLDILOCKS_EDDSA_448_PUBLIC_BYTES];
  otrng_assert(otrng_ec_point_encode(enc, ED448_POINT_BYTES, p));

  // 3. Decode like EdDSA
  ec_point dec;
  otrng_assert_is_success(otrng_ec_point_decode(dec, enc));

  otrng_assert(otrng_ec_point_eq(p, dec) == otrng_true);
}

static void test_ed448_eddsa_keygen() {
  uint8_t pub[ED448_POINT_BYTES];
  uint8_t sym[ED448_PRIVATE_BYTES];
  random_bytes(sym, ED448_PRIVATE_BYTES);

  ec_scalar_t secret_scalar;
  ec_point p;
  otrng_ec_scalar_derive_from_secret(secret_scalar, sym);
  otrng_ec_derive_public_key(pub, sym);

  otrng_assert_is_success(otrng_ec_point_decode(p, pub));

  // Is G * scalar == p?
  ec_point expected;
  goldilocks_448_point_scalarmul(expected, goldilocks_448_point_base,
                                 secret_scalar);

  otrng_assert(otrng_ec_point_eq(expected, p) == otrng_true);
}

static void test_ed448_scalar_serialization() {
  ec_scalar_t s;

  uint8_t buff[ED448_SCALAR_BYTES];
  otrng_ec_scalar_encode(buff, goldilocks_448_scalar_one);

  otrng_ec_scalar_decode(s, buff);
  otrng_assert(otrng_ec_scalar_eq(s, goldilocks_448_scalar_one) == otrng_true);
}

static void test_ed448_signature() {
  uint8_t sym[ED448_PRIVATE_BYTES] = {0x3f};
  uint8_t pub[ED448_PUBKEY_BYTES] = {0};
  otrng_keypair_s *pair = otrng_keypair_new();
  otrng_keypair_generate(pair, sym);

  uint8_t message[3] = {0x0A, 0x0C, 0x0B};
  otrng_assert(otrng_ec_point_encode(pub, ED448_POINT_BYTES, pair->pub));

  eddsa_signature_t sig;
  otrng_ec_sign(sig, sym, pub, message, sizeof(message));
  otrng_assert(otrng_ec_verify(sig, pub, message, sizeof(message)) ==
               otrng_true);

  otrng_keypair_free(pair);
}

void units_ed448_add_tests(void) {
  g_test_add_func("/edwards448/eddsa_serialization",
                  test_ed448_eddsa_serialization);
  g_test_add_func("/edwards448/eddsa_keygen", test_ed448_eddsa_keygen);
  g_test_add_func("/edwards448/scalar_serialization",
                  test_ed448_scalar_serialization);
  g_test_add_func("/edwards448/signature", test_ed448_signature);
}
