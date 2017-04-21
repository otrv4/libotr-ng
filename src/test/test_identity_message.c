#include "../dake.h"
#include "../str.h"
#include "../constants.h"

#define PREKEY_BEFORE_PROFILE_BYTES 2+1+4+4

void
test_dake_identity_message_new(identity_message_fixture_t * f,
			       gconstpointer data)
{
	dake_identity_message_t *identity_message =
	    dake_identity_message_new(f->profile);
	dake_identity_message_free(identity_message);
	identity_message = NULL;
}

void
test_dake_identity_message_serializes(identity_message_fixture_t * f,
				      gconstpointer data)
{
	dh_init();

	ecdh_keypair_t ecdh[1];
	dh_keypair_t dh;

	uint8_t sym[ED448_SCALAR_BYTES] = { 0 };
	ecdh_keypair_generate(ecdh, sym);
	dh_keypair_generate(dh);

	dake_identity_message_t *identity_message =
	    dake_identity_message_new(f->profile);
	identity_message->sender_instance_tag = 1;
	ec_point_copy(identity_message->Y, ecdh->pub);
	identity_message->B = dh_mpi_copy(dh->pub);

	uint8_t *serialized = NULL;
	otrv4_assert(dake_identity_message_aprint
		     (&serialized, NULL, identity_message));

	char expected[] = {
		0x0, 0x04,	// version
		OTR_IDENTITY_MSG_TYPE,	//message type
		0x0, 0x0, 0x0, 0x1,	// sender instance tag
		0x0, 0x0, 0x0, 0x0,	// receiver instance tag
	};

	uint8_t *cursor = serialized;
	otrv4_assert_cmpmem(cursor, expected, 11);	//sizeof(expected));
	cursor += 11;

	size_t user_profile_len = 0;
	uint8_t *user_profile_serialized = NULL;
	otrv4_assert(user_profile_aprint
		     (&user_profile_serialized, &user_profile_len,
		      identity_message->profile));
	otrv4_assert_cmpmem(cursor, user_profile_serialized, user_profile_len);
	free(user_profile_serialized);
	cursor += user_profile_len;

	uint8_t serialized_y[ED448_POINT_BYTES + 2] = { 0 };
	ec_point_serialize(serialized_y, ED448_POINT_BYTES,
			   identity_message->Y);
	otrv4_assert_cmpmem(cursor, serialized_y, sizeof(ec_public_key_t));
	cursor += sizeof(ec_public_key_t);

	uint8_t serialized_b[DH3072_MOD_LEN_BYTES] = { 0 };
	size_t mpi_len = dh_mpi_serialize(serialized_b, DH3072_MOD_LEN_BYTES,
					  identity_message->B);
	//Skip first 4 because they are the size (mpi_len)
	otrv4_assert_cmpmem(cursor + 4, serialized_b, mpi_len);

	dh_keypair_destroy(dh);
	ecdh_keypair_destroy(ecdh);
	dake_identity_message_free(identity_message);
	free(serialized);
	dh_free();
}

void
test_dake_identity_message_deserializes(identity_message_fixture_t * f,
					gconstpointer data)
{
	dh_init();

	ecdh_keypair_t ecdh[1];
	dh_keypair_t dh;

	uint8_t sym[ED448_PRIVATE_BYTES] = { 1 };
	ecdh_keypair_generate(ecdh, sym);
	dh_keypair_generate(dh);

	dake_identity_message_t *identity_message =
	    dake_identity_message_new(f->profile);
	ec_point_copy(identity_message->Y, ecdh->pub);
	identity_message->B = dh_mpi_copy(dh->pub);

	size_t serialized_len = 0;
	uint8_t *serialized = NULL;
	otrv4_assert(dake_identity_message_aprint
		     (&serialized, &serialized_len, identity_message));

	dake_identity_message_t *deserialized =
	    malloc(sizeof(dake_identity_message_t));
	memset(deserialized, 0, sizeof(dake_identity_message_t));
	otrv4_assert(dake_identity_message_deserialize
		     (deserialized, serialized, serialized_len));

	//assert prekey eq
	g_assert_cmpuint(deserialized->sender_instance_tag, ==,
			 identity_message->sender_instance_tag);
	g_assert_cmpuint(deserialized->receiver_instance_tag, ==,
			 identity_message->receiver_instance_tag);
	otrv4_assert_user_profile_eq(deserialized->profile,
				     identity_message->profile);
	otrv4_assert_ec_public_key_eq(deserialized->Y, identity_message->Y);
	otrv4_assert_dh_public_key_eq(deserialized->B, identity_message->B);

	dh_keypair_destroy(dh);
	ecdh_keypair_destroy(ecdh);
	dake_identity_message_free(identity_message);
	dake_identity_message_free(deserialized);
	free(serialized);
	dh_free();
}

void
test_dake_identity_message_valid(identity_message_fixture_t * f,
				 gconstpointer data)
{
	dh_init();

	ecdh_keypair_t ecdh[1];
	dh_keypair_t dh;

	uint8_t sym[ED448_PRIVATE_BYTES] = { 1 };
	ecdh_keypair_generate(ecdh, sym);
	dh_keypair_generate(dh);

	dake_identity_message_t *identity_message =
	    dake_identity_message_new(f->profile);
	otrv4_assert(identity_message != NULL);

	ec_point_copy(identity_message->Y, ecdh->pub);
	identity_message->B = dh_mpi_copy(dh->pub);

	otrv4_assert(dake_identity_message_validate(identity_message));

	ecdh_keypair_destroy(ecdh);
	dh_keypair_destroy(dh);
	dake_identity_message_free(identity_message);
	dh_free();
}

void
 test_dake_identity_message_Y_doesnt_belong_to_curve
    (identity_message_fixture_t * f, gconstpointer data) {
	dake_identity_message_t *identity_message =
	    dake_identity_message_new(f->profile);
	otrv4_assert(identity_message != NULL);

	otrv4_assert(dake_identity_message_validate(identity_message));	//TODO: boolean?
	dake_identity_message_free(identity_message);
}
