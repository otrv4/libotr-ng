#include "../dh.h"

void
dh_test_api() {
  dh_init();

  dh_keypair_t alice, bob; 
  dh_gen_keypair(alice);
  dh_gen_keypair(bob);

  uint8_t shared1[DH3072_MOD_LEN_BYTES], shared2[DH3072_MOD_LEN_BYTES];

  int ok = dh_shared_secret(shared1, sizeof(shared1), alice->priv, bob->pub);
  g_assert_cmpint(ok, ==, 0);

  ok = dh_shared_secret(shared2, sizeof(shared2), bob->priv, alice->pub);
  g_assert_cmpint(ok, ==, 0);

  ok = memcmp(shared1, shared2, sizeof(shared1));
  g_assert_cmpint(ok, ==, 0);

  dh_keypair_destroy(alice);
  dh_keypair_destroy(bob);
}
