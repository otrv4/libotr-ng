#include "../dh.h"

void dh_test_api() {
  OTRNG_INIT;

  dh_keypair_t alice, bob;
  otrng_dh_keypair_generate(alice);
  otrng_dh_keypair_generate(bob);

  uint8_t shared1[DH3072_MOD_LEN_BYTES], shared2[DH3072_MOD_LEN_BYTES];

  memset(shared1, 0, sizeof shared1);
  memset(shared2, 0, sizeof shared2);

  otrng_assert(otrng_dh_shared_secret(shared1, sizeof(shared1), alice->priv,
                                      bob->pub) == SUCCESS);
  otrng_assert(otrng_dh_shared_secret(shared2, sizeof(shared2), bob->priv,
                                      alice->pub) == SUCCESS);

  otrng_assert_cmpmem(shared1, shared2, sizeof(shared1));

  otrng_dh_keypair_destroy(alice);
  otrng_dh_keypair_destroy(bob);
  otrng_dh_free();
}

void dh_test_serialize() {
  uint8_t buf[DH3072_MOD_LEN_BYTES] = {0};
  dh_mpi_t mpi = gcry_mpi_new(DH3072_MOD_LEN_BITS);

  size_t mpi_len = 0;
  otrng_err_t err =
      otrng_dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, &mpi_len, mpi);
  otrng_assert(!err);
  g_assert_cmpint(mpi_len, ==, 0);

  gcry_mpi_set_ui(mpi, 1);
  err = otrng_dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, &mpi_len, mpi);
  otrng_assert(!err);
  g_assert_cmpint(mpi_len, ==, 1);

  gcry_mpi_set_ui(mpi, 0xffffffff);
  err = otrng_dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, &mpi_len, mpi);
  otrng_assert(!err);
  g_assert_cmpint(mpi_len, ==, 4);

  gcry_mpi_release(mpi);
}

void dh_test_keypair_destroy() {
  OTRNG_INIT;
  dh_keypair_t alice;

  otrng_dh_keypair_generate(alice);

  otrng_assert(alice->priv);
  otrng_assert(alice->pub);

  otrng_dh_keypair_destroy(alice);

  otrng_assert(!alice->priv);
  otrng_assert(!alice->pub);

  otrng_dh_free();
}
