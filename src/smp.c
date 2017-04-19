#include <string.h>

#include "auth.h"
#include "deserialize.h"
#include "dh.h"
#include "mpi.h"
#include "serialize.h"
#include "smp.h"
#include "str.h"
#include "tlv.h"

#include "debug.h"

void smp_destroy(smp_context_t smp)
{
	//TODO: I think we should free this
	smp->x = NULL;
}

void generate_smp_secret(unsigned char ** secret, otrv4_fingerprint_t our_fp,
			otrv4_fingerprint_t their_fp, uint8_t * ssid,
			string_t answer)
{
	size_t len = SMP_MIN_SECRET_BYTES + strlen(answer) + 1;
	gcry_md_hd_t hd;
	uint8_t version[1] = { 0x01 };

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, version, 1);
	gcry_md_write(hd, our_fp, sizeof(otrv4_fingerprint_t));
	gcry_md_write(hd, their_fp, sizeof(otrv4_fingerprint_t));
	gcry_md_write(hd, ssid, 8);
	gcry_md_write(hd, answer, strlen(answer) + 1);

	*secret = malloc(len);
	if (!*secret)
		return;

	memcpy(*secret, gcry_md_read(hd, 0), len);
	gcry_md_close(hd);
}

int generate_smp_msg_1(smp_msg_1_t dst, smp_context_t smp)
{
	decaf_448_scalar_t a2, a3;
	snizkpk_keypair_t pair_r2[1], pair_r3[1];
	unsigned char hash[64];
	gcry_md_hd_t hd;
	decaf_448_scalar_t a3c3, a2c2;
	uint8_t version[2] = { 0x01, 0x02 };

	dst->question = NULL;

	generate_keypair(dst->G2a, a2);
	generate_keypair(dst->G3a, a3);

	snizkpk_keypair_generate(pair_r2);
	snizkpk_keypair_generate(pair_r3);

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, &version[0], 1);
	gcry_md_write(hd, pair_r2->pub, ED448_POINT_BYTES);
	memcpy(hash, gcry_md_read(hd, 0), 64);
	gcry_md_close(hd);

	int ok = decaf_448_scalar_decode(dst->c2, hash);
	(void)ok;
	decaf_448_scalar_mul(a2c2, a2, dst->c2);
	decaf_448_scalar_sub(dst->d2, pair_r2->priv, dst->c2);

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, &version[1], 1);
	gcry_md_write(hd, pair_r3->pub, ED448_POINT_BYTES);
	memcpy(hash, gcry_md_read(hd, 0), 64);
	gcry_md_close(hd);

	ok = decaf_448_scalar_decode(dst->c3, hash);
	(void)ok;
	decaf_448_scalar_mul(a3c3, a3, dst->c3);
	decaf_448_scalar_sub(dst->d3, pair_r3->priv, dst->c3);

	return 0;
}

int smp_msg_1_aprint(uint8_t ** dst, size_t * len, const smp_msg_1_t msg)
{
	uint8_t *buff;
	uint8_t buffmpi[DECAF_448_SER_BYTES];
	int bufflen = 0;
	otr_mpi_t c2_mpi, d2_mpi, c3_mpi, d3_mpi;
	size_t s = 0;

	s += 4;
	if (msg->question)
		s += strlen(msg->question) +1;
	s += 2 * DECAF_448_SER_BYTES;
	s += 4 * 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->c2);
	otr_mpi_set(c2_mpi, buffmpi, bufflen);
	s += bufflen;

	bufflen = serialize_ec_scalar(buffmpi, msg->d2);
	otr_mpi_set(d2_mpi, buffmpi, bufflen);
	s += bufflen;

	bufflen = serialize_ec_scalar(buffmpi, msg->c3);
	otr_mpi_set(c3_mpi, buffmpi, bufflen);
	s += bufflen;

	bufflen = serialize_ec_scalar(buffmpi, msg->d3);
	otr_mpi_set(d3_mpi, buffmpi, bufflen);
	s += bufflen;

	buff = malloc(s);
	if (!dst)
		return 1;

	uint8_t *cursor = buff;

	if (!msg->question)
	{
		uint8_t null_question[4] = {0x0, 0x0, 0x0, 0x0};
		cursor += serialize_data(cursor, null_question, 0);
	}
	else
		cursor += serialize_data(cursor, (uint8_t *) msg->question, strlen(msg->question)+1);

	cursor += serialize_ec_point(cursor, msg->G2a);
	cursor += serialize_mpi(cursor, c2_mpi);
	cursor += serialize_mpi(cursor, d2_mpi);
	cursor += serialize_ec_point(cursor, msg->G3a);
	cursor += serialize_mpi(cursor, c3_mpi);
	cursor += serialize_mpi(cursor, d3_mpi);

	*dst = buff;
	*len = s;

	otr_mpi_free(c2_mpi);
	otr_mpi_free(d2_mpi);
	otr_mpi_free(c3_mpi);
	otr_mpi_free(d3_mpi);

	return 0;
}

tlv_t *generate_smp_msg_2(void)
{
	uint8_t *data = NULL;
	size_t len = 0;

	return otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, len, data);
}

//TODO: this function is duplicated from deserialize.c
static bool
deserialize_ec_scalar(ec_scalar_t scalar, const uint8_t * serialized,
		      size_t ser_len)
{
	if (ser_len < DECAF_448_SCALAR_BYTES)
		return false;

	return ec_scalar_deserialize(scalar, serialized);
}

static bool
deserialize_mpi_to_scalar(decaf_448_scalar_t dst, const uint8_t * buff,
		uint16_t bufflen, size_t * read)
{
	otr_mpi_t tmp_mpi;
	size_t r = 0;
	const uint8_t * cursor = buff;

	if (!otr_mpi_deserialize_no_copy(tmp_mpi, cursor, bufflen, &r))
		return false;

	if (!deserialize_ec_scalar(dst, tmp_mpi->data, tmp_mpi->len))
		return false;

	*read = r + tmp_mpi->len;

	return true;
}

bool smp_msg_1_deserialize(smp_msg_1_t msg, const tlv_t * tlv)
{
	const uint8_t * cursor = tlv->data;
	uint16_t len = tlv->len;
	size_t read = 0;

	if (!deserialize_data((uint8_t **) &msg->question, cursor, len, &read))
		return false;

	cursor += read;
	len -= read;

	if (!deserialize_ec_point(msg->G2a, cursor))
		return false;

	cursor += DECAF_448_SER_BYTES;
	len -= DECAF_448_SER_BYTES;

	if (!deserialize_mpi_to_scalar(msg->c2, cursor, len, &read))
		return false;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(msg->d2, cursor, len, &read))
		return false;

	cursor += read;
	len -= read;

	if (!deserialize_ec_point(msg->G3a, cursor))
		return false;

	cursor += DECAF_448_SER_BYTES;
	len -= DECAF_448_SER_BYTES;

	if (!deserialize_mpi_to_scalar(msg->c3, cursor, len, &read))
		return false;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(msg->d3, cursor, len, &read))
		return false;

        return true;
}

bool smp_msg_1_validate(smp_msg_1_t msg)
{
	return ec_point_valid(msg->G2a) || !ec_point_valid(msg->G3a);
}

