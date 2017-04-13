#include <glib.h>
#include <string.h>

#include "../dake.h"
#include "../serialize.h"
#include "../str.h"

void test_dake_protocol()
{
	dh_init();

        otrv4_keypair_t alice_keypair[1], bob_keypair[1];
	ec_keypair_t alice_ecdh, bob_ecdh;
	dh_keypair_t alice_dh, bob_dh;

	// Alice
        otrv4_keypair_generate(alice_keypair);
	ec_keypair_generate(alice_ecdh);
	dh_keypair_generate(alice_dh);

	// Bob
        otrv4_keypair_generate(bob_keypair);
	ec_keypair_generate(bob_ecdh);
	dh_keypair_generate(bob_dh);

	// Alice send pre key
	user_profile_t *alice_profile = user_profile_new("4");
	alice_profile->expires = time(NULL) + 60 * 60;
	user_profile_sign(alice_profile, alice_keypair);
	dake_identity_message_t *identity_message =
	    dake_identity_message_new(alice_profile);

	ec_public_key_copy(identity_message->Y, alice_ecdh->pub);
	identity_message->B = dh_mpi_copy(alice_dh->pub);

	//dake_identity_message_serialize()

	//TODO: continue
	// Bob receives pre key
	// dake_identity_message_deserialize()

	// Bob sends DRE-auth
	// Alice receives DRE-auth

	dake_identity_message_free(identity_message);
	dh_keypair_destroy(bob_dh);
	ec_keypair_destroy(bob_ecdh);
	user_profile_free(alice_profile);
	dh_keypair_destroy(alice_dh);
	ec_keypair_destroy(alice_ecdh);
	dh_free();
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
        (unsigned char*) msg, strlen(msg),
        (unsigned char*) data, strlen(data));
    g_assert_cmpint(err, ==, 0);

    unsigned char decripted[2];
    unsigned long long decripted_len = 0;
    err = dread_decrypt(decripted, &decripted_len, pair1, pair2->pub, dst, (unsigned char*) data, strlen(data));
    g_assert_cmpint(err, ==, 0);

    g_assert_cmpint(decripted_len, ==, 2);
    otrv4_assert_cmpmem(msg, decripted, 2);

    free(dst->cipher);
}

#include "../auth.h"

void test_snizkpk_auth()
{
    snizkpk_proof_t dst;
    snizkpk_keypair_t pair1[1], pair2[1], pair3[1];
    const char *msg = "hi";

    snizkpk_keypair_generate(pair1);
    snizkpk_keypair_generate(pair2);
    snizkpk_keypair_generate(pair3);

    int err = snizkpk_authenticate(dst, pair1, pair2->pub, pair3->pub, (unsigned char*) msg, strlen(msg));
    g_assert_cmpint(err, ==, 0);

    err = snizkpk_verify(dst, pair1->pub, pair2->pub, pair3->pub, (unsigned char*) msg, strlen(msg));
    g_assert_cmpint(err, ==, 0);
}
