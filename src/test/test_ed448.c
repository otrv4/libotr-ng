#include "../ed448.h"
#include "../random.h"

#include <decaf/ed448.h>

void ed448_test_ecdh()
{
	uint8_t alice_pub[DECAF_X448_PUBLIC_BYTES];
	uint8_t alice_priv[DECAF_X448_PRIVATE_BYTES];

	uint8_t bob_pub[DECAF_X448_PUBLIC_BYTES];
	uint8_t bob_priv[DECAF_X448_PRIVATE_BYTES];

	random_bytes(alice_priv, DECAF_X448_PRIVATE_BYTES);
	decaf_x448_generate_key(alice_pub, alice_priv);

	random_bytes(bob_priv, DECAF_X448_PRIVATE_BYTES);
	decaf_x448_generate_key(bob_pub, bob_priv);

	uint8_t shared1[DECAF_X448_PUBLIC_BYTES],
	    shared2[DECAF_X448_PUBLIC_BYTES];

	decaf_error_t err = decaf_x448(shared1, alice_pub, bob_priv);
	err = decaf_x448(shared2, bob_pub, alice_priv);
	otrv4_assert(DECAF_SUCCESS == err);

	otrv4_assert_cmpmem(shared1, shared2, DECAF_X448_PUBLIC_BYTES);

	ec_scalar_t s;
	uint8_t rand[ED448_SCALAR_BYTES];
	random_bytes(rand, ED448_SCALAR_BYTES);
	decaf_448_scalar_decode_long(s, rand, ED448_SCALAR_BYTES);

	//1. Create a point P
	ec_point_t p;
	decaf_448_point_scalarmul(p, decaf_448_point_base, s);

	//2. Serialize using EdDSA
	uint8_t enc[DECAF_EDDSA_448_PUBLIC_BYTES];
	bool enc_ok = ec_point_serialize(enc, DECAF_EDDSA_448_PUBLIC_BYTES, p);
	otrv4_assert(enc_ok);

	//3. Deserialize
	ec_point_t dec;
	bool dec_ok = ec_point_deserialize(dec, enc);
	otrv4_assert(dec_ok);

	otrv4_assert(ec_point_eq(p, dec));
}
