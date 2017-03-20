#include "../b64.h"

void cramershoup_test_serialize_private_key(void)
{
	cs_keypair_t key_pair;
	cs_keypair_generate(key_pair);

	char *buff = NULL;
	size_t bufflen = 0;
	int err = cs_serialize_private_key(&buff, &bufflen, key_pair->priv);
	otrv4_assert(!err);

	g_assert_cmpint(bufflen, ==, 404);

	size_t len = 0;
	unsigned char scalar_buff[DECAF_448_SCALAR_BYTES] = { 0 };
	char *b64_buff = malloc(((sizeof(scalar_buff) + 2) / 3) * 4);

	char *cursor = buff;

	//"x1: ..."
	otrv4_assert_cmpmem("x1: ", cursor, 4);
	cursor += 4;

	memset(scalar_buff, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar_buff, key_pair->priv->x1);
	len = otrl_base64_encode(b64_buff, scalar_buff, sizeof(scalar_buff));
	otrv4_assert_cmpmem(b64_buff, cursor, len);
	cursor += len;

	otrv4_assert_cmpmem("\n", cursor, 1);
	cursor++;

	//"x2: ..."
	otrv4_assert_cmpmem("x2: ", cursor, 4);
	cursor += 4;

	memset(scalar_buff, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar_buff, key_pair->priv->x2);
	len = otrl_base64_encode(b64_buff, scalar_buff, sizeof(scalar_buff));
	otrv4_assert_cmpmem(b64_buff, cursor, len);
	cursor += len;

	otrv4_assert_cmpmem("\n", cursor, 1);
	cursor++;

	//"y1: ..."
	otrv4_assert_cmpmem("y1: ", cursor, 4);
	cursor += 4;

	memset(scalar_buff, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar_buff, key_pair->priv->y1);
	len = otrl_base64_encode(b64_buff, scalar_buff, sizeof(scalar_buff));
	otrv4_assert_cmpmem(b64_buff, cursor, len);
	cursor += len;

	otrv4_assert_cmpmem("\n", cursor, 1);
	cursor++;

	//"y2: ..."
	otrv4_assert_cmpmem("y2: ", cursor, 4);
	cursor += 4;

	memset(scalar_buff, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar_buff, key_pair->priv->y2);
	len = otrl_base64_encode(b64_buff, scalar_buff, sizeof(scalar_buff));
	otrv4_assert_cmpmem(b64_buff, cursor, len);
	cursor += len;

	otrv4_assert_cmpmem("\n", cursor, 1);
	cursor++;

	//"z: ..."
	otrv4_assert_cmpmem("z: ", cursor, 3);
	cursor += 3;

	memset(scalar_buff, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar_buff, key_pair->priv->z);
	len = otrl_base64_encode(b64_buff, scalar_buff, sizeof(scalar_buff));
	otrv4_assert_cmpmem(b64_buff, cursor, len);
	cursor += len;

	otrv4_assert_cmpmem("\n", cursor, 1);

	free(buff);
	cs_keypair_destroy(key_pair);
}

