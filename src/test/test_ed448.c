#include "../ed448.h"

void
ed448_test_ecdh() {
  ec_keypair_t alice, bob; 
  ec_keypair_generate(alice);
  ec_keypair_generate(bob);

  uint8_t shared1[1234],shared2[1234];

  otrv4_assert(ecdh_shared_secret(shared1, sizeof(shared1), alice, bob->pub));
  otrv4_assert(ecdh_shared_secret(shared2, sizeof(shared2), bob, alice->pub));

  otrv4_assert_cmpmem(shared1, shared2, sizeof(shared1));

  ec_keypair_destroy(alice);
  ec_keypair_destroy(bob);
}
