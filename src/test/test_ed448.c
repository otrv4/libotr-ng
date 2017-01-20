#include "../ed448.h"

void
ed448_test_ecdh() {
  ec_keypair_t alice, bob; 
  ec_gen_keypair(alice);
  ec_gen_keypair(bob);

  uint8_t shared1[1234],shared2[1234];

  int ok = ecdh_shared_secret(shared1, sizeof(shared1), alice, bob->pub);
  g_assert_cmpint(ok, ==, 0);

  ok = ecdh_shared_secret(shared2, sizeof(shared2), bob, alice->pub);
  g_assert_cmpint(ok, ==, 0);

  ok = memcmp(shared1, shared2, sizeof(shared1));
  g_assert_cmpint(ok, ==, 0);

  ec_keypair_destroy(alice);
  ec_keypair_destroy(bob);
}
