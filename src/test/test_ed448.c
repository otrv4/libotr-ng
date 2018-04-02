#include <goldilocks.h>
#include <goldilocks/ed448.h>

#include "../ed448.h"
#include "../random.h"

void ed448_test_ecdh() {
  uint8_t alice_pub[GOLDILOCKS_X448_PUBLIC_BYTES];
  uint8_t alice_priv[GOLDILOCKS_X448_PRIVATE_BYTES];

  uint8_t bob_pub[GOLDILOCKS_X448_PUBLIC_BYTES];
  uint8_t bob_priv[GOLDILOCKS_X448_PRIVATE_BYTES];

  random_bytes(alice_priv, GOLDILOCKS_X448_PRIVATE_BYTES);
  goldilocks_x448_derive_public_key(alice_pub, alice_priv);

  random_bytes(bob_priv, GOLDILOCKS_X448_PRIVATE_BYTES);
  goldilocks_x448_derive_public_key(bob_pub, bob_priv);

  uint8_t shared1[GOLDILOCKS_X448_PUBLIC_BYTES],
      shared2[GOLDILOCKS_X448_PUBLIC_BYTES];

  goldilocks_error_t err = goldilocks_x448(shared1, alice_pub, bob_priv);
  err = goldilocks_x448(shared2, bob_pub, alice_priv);
  otrv4_assert(GOLDILOCKS_SUCCESS == err);

  otrv4_assert_cmpmem(shared1, shared2, GOLDILOCKS_X448_PUBLIC_BYTES);
}

void ed448_test_eddsa_serialization() {
  ec_scalar_t s;
  uint8_t rand[ED448_SCALAR_BYTES];
  random_bytes(rand, ED448_SCALAR_BYTES);
  goldilocks_448_scalar_decode_long(s, rand, ED448_SCALAR_BYTES);

  // 1. Create a point P
  ec_point_t p;
  goldilocks_448_point_scalarmul(p, goldilocks_448_point_base, s);

  // 2. Serialize using EdDSA
  uint8_t enc[GOLDILOCKS_EDDSA_448_PUBLIC_BYTES];
  otrv4_ec_point_serialize(enc, p);

  // 3. Deserialize
  ec_point_t dec;
  otrv4_assert(otrv4_ec_point_deserialize(dec, enc) == SUCCESS);

  otrv4_assert(otrv4_ec_point_eq(p, dec) == otrv4_true);
}

void ed448_test_eddsa_keygen() {
  uint8_t pub[ED448_POINT_BYTES];
  uint8_t sym[ED448_PRIVATE_BYTES];
  random_bytes(sym, ED448_PRIVATE_BYTES);

  ec_scalar_t secret_scalar;
  ec_point_t public_point;
  otrv4_ec_scalar_derive_from_secret(secret_scalar, sym);
  otrv4_ec_derive_public_key(pub, sym);

  otrv4_assert(otrv4_ec_point_deserialize(public_point, pub) == SUCCESS);

  // Is G * scalar == P?
  ec_point_t expected;
  goldilocks_448_point_scalarmul(expected, goldilocks_448_point_base,
                                 secret_scalar);

  otrv4_assert(otrv4_ec_point_eq(expected, public_point) == otrv4_true);
}

void ed448_test_scalar_serialization() {
  ec_scalar_t scalar;

  uint8_t buff[ED448_SCALAR_BYTES];
  otrv4_assert(otrv4_ec_scalar_serialize(buff, sizeof(buff),
                                         goldilocks_448_scalar_one) == SUCCESS);

  otrv4_ec_scalar_deserialize(scalar, buff);
  otrv4_assert(otrv4_ec_scalar_eq(scalar, goldilocks_448_scalar_one) ==
               otrv4_true);
}
