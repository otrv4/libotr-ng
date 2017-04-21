#include "../serialize.h"
#include "../deserialize.h"

void test_ser_deser_uint()
{
	const uint8_t ser[8] =
	    { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

	size_t read = 0;
	uint8_t buf[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	serialize_uint8(buf, 0x12);
	otrv4_assert_cmpmem(buf, ser, 1);

	uint8_t uint8_des = 0;
	otrv4_assert(deserialize_uint8(&uint8_des, ser, sizeof(ser), &read));
	g_assert_cmpuint(uint8_des, ==, 0x12);
	g_assert_cmpint(read, ==, sizeof(uint8_t));

	memset(buf, 0, sizeof(buf));
	serialize_uint16(buf, 0x1234);
	otrv4_assert_cmpmem(buf, ser, 2);

	uint16_t uint16_des = 0;
	otrv4_assert(deserialize_uint16(&uint16_des, ser, sizeof(ser), &read));
	g_assert_cmpuint(uint16_des, ==, 0x1234);
	g_assert_cmpint(read, ==, sizeof(uint16_t));

	memset(buf, 0, sizeof(buf));
	serialize_uint32(buf, 0x12345678);
	otrv4_assert_cmpmem(buf, ser, 4);

	uint32_t uint32_des = 0;
	otrv4_assert(deserialize_uint32(&uint32_des, ser, sizeof(ser), &read));
	g_assert_cmpuint(uint32_des, ==, 0x12345678);
	g_assert_cmpint(read, ==, sizeof(uint32_t));

	memset(buf, 0, sizeof(buf));
	serialize_uint64(buf, 0x123456789ABCDEF0);
	otrv4_assert_cmpmem(buf, ser, 8);

	uint64_t uint64_des = 0;
	otrv4_assert(deserialize_uint64(&uint64_des, ser, sizeof(ser), &read));
	g_assert_cmpuint(uint64_des, ==, 0x123456789ABCDEF0);
	g_assert_cmpint(read, ==, sizeof(uint64_t));
}

void test_serialize_deserialize_data()
{
	uint8_t src[5] = { 1, 2, 3, 4, 5 };
	uint8_t *dst = malloc(9);
	otrv4_assert(dst);
	g_assert_cmpint(9, ==, serialize_data(dst, src, 5));
	free(dst);
}

void test_ser_des_otrv4_public_key()
{
	otrv4_keypair_t keypair[1];
	otrv4_public_key_t deserialized;
        uint8_t sym[ED448_PRIVATE_BYTES] = {1};
	otrv4_keypair_generate(keypair, sym);

	uint8_t serialized[ED448_PUBKEY_BYTES] = {0};
	g_assert_cmpint(serialize_otrv4_public_key(serialized, keypair->pub),
			==, ED448_PUBKEY_BYTES);
	g_assert_cmpint(deserialize_otrv4_public_key
			(deserialized, serialized, ED448_PUBKEY_BYTES, NULL),
			==, 1);

	otrv4_assert(DECAF_TRUE == decaf_448_point_valid(deserialized));

	otrv4_assert(decaf_448_point_eq(deserialized, keypair->pub)
		     == DECAF_TRUE);
}
