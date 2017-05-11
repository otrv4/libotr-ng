#include "../dh.h"

void dh_test_api()
{
	dh_init();

	dh_keypair_t alice, bob;
	dh_keypair_generate(alice);
	dh_keypair_generate(bob);

	uint8_t shared1[DH3072_MOD_LEN_BYTES], shared2[DH3072_MOD_LEN_BYTES];

	memset(shared1, 0, DH3072_MOD_LEN_BYTES);
	memset(shared2, 0, DH3072_MOD_LEN_BYTES);

	otrv4_assert(dh_shared_secret
		     (shared1, sizeof(shared1), alice->priv, bob->pub));
	otrv4_assert(dh_shared_secret
		     (shared2, sizeof(shared2), bob->priv, alice->pub));

	otrv4_assert_cmpmem(shared1, shared2, sizeof(shared1));

	dh_keypair_destroy(alice);
	dh_keypair_destroy(bob);
	dh_free();
}

void dh_test_serialize()
{
	uint8_t buf[DH3072_MOD_LEN_BYTES] = { 0 };
	dh_mpi_t mpi = gcry_mpi_new(DH3072_MOD_LEN_BITS);

	size_t mpi_len = 0;
	gcry_error_t err =
	    dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, &mpi_len, mpi);
	otrv4_assert(err == gcry_error(GPG_ERR_NO_ERROR));
	g_assert_cmpint(mpi_len, ==, 0);

	gcry_mpi_set_ui(mpi, 1);
	err = dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, &mpi_len, mpi);
	otrv4_assert(err == gcry_error(GPG_ERR_NO_ERROR));
	g_assert_cmpint(mpi_len, ==, 1);

	gcry_mpi_set_ui(mpi, 0xffffffff);
	err = dh_mpi_serialize(buf, DH3072_MOD_LEN_BYTES, &mpi_len, mpi);
	otrv4_assert(err == gcry_error(GPG_ERR_NO_ERROR));
	g_assert_cmpint(mpi_len, ==, 4);

	gcry_mpi_release(mpi);
}
