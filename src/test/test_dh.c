#include "../dh.h"

void
dh_test_api() {
  dh_init();

  dh_keypair_t alice, bob; 
  dh_gen_keypair(alice);
  dh_gen_keypair(bob);

  uint8_t shared1[DH3072_MOD_LEN_BYTES], shared2[DH3072_MOD_LEN_BYTES];

  otrv4_assert(dh_shared_secret(shared1, sizeof(shared1), alice->priv, bob->pub));
  otrv4_assert(dh_shared_secret(shared2, sizeof(shared2), bob->priv, alice->pub));

  int ok = memcmp(shared1, shared2, sizeof(shared1));
  g_assert_cmpint(ok, ==, 0);

  dh_keypair_destroy(alice);
  dh_keypair_destroy(bob);
}

void
dh_test_serialize() {
  uint8_t buf[DH3072_MOD_LEN_BYTES] = {0};
  dh_mpi_t mpi = gcry_mpi_new(DH3072_MOD_LEN_BITS);

  size_t len = dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, mpi);
  g_assert_cmpint(len, ==, 0);

  gcry_mpi_set_ui(mpi, 1);
  len = dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, mpi);

  g_assert_cmpint(len, ==, 1);

  gcry_mpi_set_ui(mpi, 0xffffffff);
  len = dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, mpi);

  g_assert_cmpint(len, ==, 4);

  gcry_mpi_release(mpi);
}

