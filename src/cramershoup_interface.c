#include "cramershoup_interface.h"

#include <string.h>

#include "b64.h"
#include "ed448.h"

void cs_public_key_copy(cs_public_key_t * dst, const cs_public_key_t * src)
{
	ec_point_copy(dst->c, src->c);
	ec_point_copy(dst->d, src->d);
	ec_point_copy(dst->h, src->h);
}

int
cs_serialize_private_key(char **dst, size_t * len,
			 const cs_private_key_t * priv)
{
	size_t s = 4 * 6 + 5 * (((DECAF_448_SCALAR_BYTES + 2) / 3) * 4);
	char *buff = malloc(s);
	if (!buff)
		return -1;

	unsigned char scalar[DECAF_448_SCALAR_BYTES] = { 0 };
	char *cursor = buff;

	memcpy(cursor, "x1: ", 4);
	cursor += 4;

	memset(scalar, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar, priv->x1);
	cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
	*(cursor++) = '\n';

	memcpy(cursor, "x2: ", 4);
	cursor += 4;

	memset(scalar, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar, priv->x2);
	cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
	*(cursor++) = '\n';

	memcpy(cursor, "y1: ", 4);
	cursor += 4;

	memset(scalar, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar, priv->y1);
	cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
	*(cursor++) = '\n';

	memcpy(cursor, "y2: ", 4);
	cursor += 4;

	memset(scalar, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar, priv->y2);
	cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
	*(cursor++) = '\n';

	memcpy(cursor, "z: ", 3);
	cursor += 3;

	memset(scalar, 0, DECAF_448_SCALAR_BYTES);
	decaf_448_scalar_encode(scalar, priv->z);
	cursor += otrl_base64_encode(cursor, scalar, sizeof(scalar));
	*(cursor++) = '\n';

	*dst = buff;
	*len = cursor - buff;
	return 0;
}

static int
decaf_448_scalar_decode_b64(decaf_448_scalar_t s, const char *buff, size_t len)
{
	//((base64len+3) / 4) * 3
	unsigned char *dec = malloc(((len + 3) / 4) * 3);
	if (!dec)
		return -1;

	size_t written = otrl_base64_decode(dec, buff, len);
	if (written != DECAF_448_SCALAR_BYTES) {
		free(dec);
		return 1;
	}

	decaf_bool_t ok = decaf_448_scalar_decode(s, dec);
	free(dec);

	return ok == DECAF_FALSE;
}

static int compare_header(const char *buff, size_t len, const char *expected)
{
	if (strstr(buff, expected))
		return strlen(expected);

	return 0;
}

int cs_deserialize_private_key_FILEp(cs_private_key_t * priv, FILE * privf)
{
	char *line = NULL;
	size_t cap = 0;

	int len = 0;
	int h = 0;
	int err = 0;

	if (!privf)
		return -1;

	len = getline(&line, &cap, privf);
	if (len < 0)
		return -1;

	h = compare_header(line, len, "x1: ");
	if (!h) {
		free(line);
		return -1;
	}

	err = decaf_448_scalar_decode_b64(priv->x1, line + h, len - h);
	free(line);
	line = NULL;

	if (err)
		return -1;

	len = getline(&line, &cap, privf);
	if (len < 0)
		return -1;

	h = compare_header(line, len, "x2: ");
	if (!h) {
		free(line);
		return -1;
	}

	err = decaf_448_scalar_decode_b64(priv->x2, line + h, len - h);
	free(line);
	line = NULL;

	if (err)
		return -1;

	len = getline(&line, &cap, privf);
	if (len < 0)
		return -1;

	h = compare_header(line, len, "y1: ");
	if (!h) {
		free(line);
		return -1;
	}

	err = decaf_448_scalar_decode_b64(priv->y1, line + h, len - h);
	free(line);
	line = NULL;

	if (err)
		return -1;

	len = getline(&line, &cap, privf);
	if (len < 0)
		return -1;

	h = compare_header(line, len, "y2: ");
	if (!h) {
		free(line);
		return -1;
	}

	err = decaf_448_scalar_decode_b64(priv->y2, line + h, len - h);
	free(line);
	line = NULL;

	if (err)
		return -1;

	len = getline(&line, &cap, privf);
	if (len < 0)
		return -1;

	h = compare_header(line, len, "z: ");
	if (!h) {
		free(line);
		return -1;
	}

	err = decaf_448_scalar_decode_b64(priv->z, line + h, len - h);
	free(line);
	line = NULL;

	if (err)
		return -1;

	return 0;
}
