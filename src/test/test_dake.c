#include <glib.h>
#include <string.h>

#include "../dake.h"
#include "../serialize.h"
#include "../str.h"

void test_dake_protocol()
{
	//TODO
}

#include "../dread.h"

void test_dread()
{
	if (sodium_init() == -1) {
		return;
	}

	dread_cipher_t dst;
	dread_keypair_t pair1, pair2;

	dread_keypair_generate(pair1);
	dread_keypair_generate(pair2);

	const char *msg = "hi";
	const char *data = "session state";

	int err = dread_encrypt(dst, pair1->pub, pair2->pub,
				(unsigned char *)msg, strlen(msg),
				(unsigned char *)data, strlen(data));
	g_assert_cmpint(err, ==, 0);

	unsigned char decripted[2];
	unsigned long long decripted_len = 0;
	err =
	    dread_decrypt(decripted, &decripted_len, pair1, pair2->pub, dst,
			  (unsigned char *)data, strlen(data));
	g_assert_cmpint(err, ==, 0);

	g_assert_cmpint(decripted_len, ==, 2);
	otrv4_assert_cmpmem(msg, decripted, 2);

	free(dst->cipher);
}

#include "../auth.h"

void test_snizkpk_auth()
{
	snizkpk_proof_t dst[1];
	snizkpk_keypair_t pair1[1], pair2[1], pair3[1];
	const char *msg = "hi";

	snizkpk_keypair_generate(pair1);
	snizkpk_keypair_generate(pair2);
	snizkpk_keypair_generate(pair3);

	int err = snizkpk_authenticate(dst, pair1, pair2->pub, pair3->pub,
				       (unsigned char *)msg, strlen(msg));
	g_assert_cmpint(err, ==, 0);

	err =
	    snizkpk_verify(dst, pair1->pub, pair2->pub, pair3->pub,
			   (unsigned char *)msg, strlen(msg));
	g_assert_cmpint(err, ==, 0);

	//Now lets serialize and deserialize things.
	otrv4_keypair_t p1[1], p2[1], p3[1];
	uint8_t sym1[ED448_PRIVATE_BYTES] = { 1 }, sym2[ED448_PRIVATE_BYTES] = {
	2}, sym3[ED448_PRIVATE_BYTES] = {
	3};

	otrv4_keypair_generate(p1, sym1);
	otrv4_keypair_generate(p2, sym2);
	otrv4_keypair_generate(p3, sym3);

	snizkpk_proof_t dst2[1];
	err = snizkpk_authenticate(dst2, p1, p2->pub, p3->pub,
				   (unsigned char *)msg, strlen(msg));
	g_assert_cmpint(err, ==, 0);

	err =
	    snizkpk_verify(dst2, p1->pub, p2->pub, p3->pub,
			   (unsigned char *)msg, strlen(msg));
	g_assert_cmpint(err, ==, 0);

}
