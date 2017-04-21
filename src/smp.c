#include <string.h>

#include "auth.h"
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

void generate_smp_secret(smp_context_t smp, otrv4_fingerprint_t our_fp,
			otrv4_fingerprint_t their_fp, uint8_t * ssid,
			string_t answer)
{
	size_t len = SMP_MIN_SECRET_BYTES + strlen (answer) +1;
	gcry_md_hd_t hd;
	uint8_t version[1] = {0x01};

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, version, 1);
	gcry_md_write(hd, our_fp, sizeof(otrv4_fingerprint_t));
	gcry_md_write(hd, their_fp, sizeof(otrv4_fingerprint_t));
	gcry_md_write(hd, ssid, 8);
	gcry_md_write(hd, answer, strlen (answer) +1);

	smp->x = malloc(len);
	if (!smp->x)
		return;

	memcpy(smp->x, gcry_md_read(hd, 0), len);
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
	(void) ok;
	decaf_448_scalar_mul(a2c2, a2, dst->c2);
	decaf_448_scalar_sub(dst->d2, pair_r2->priv, dst->c2);

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, &version[1], 1);
	gcry_md_write(hd, pair_r3->pub, ED448_POINT_BYTES);
	memcpy(hash, gcry_md_read(hd, 0), 64);
	gcry_md_close(hd);

	ok = decaf_448_scalar_decode(dst->c3, hash);
	(void) ok;
	decaf_448_scalar_mul(a3c3, a3, dst->c3);
	decaf_448_scalar_sub(dst->d3, pair_r3->priv, dst->c3);

	return 0;
}

int smp_msg_1_aprint(uint8_t ** dst, size_t * len, const smp_msg_1_t msg)
{
	uint8_t *buff;
	uint8_t buffmpi[56];
	int bufflen = 0;
	otr_mpi_t c2_mpi, d2_mpi, c3_mpi, d3_mpi;
	size_t s = 0;

	s += 4 + strlen (msg->question) +1;
	s += 2 * 56;
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

	uint8_t * cursor = buff;

	if (msg->question)
		cursor += serialize_data(cursor, (uint8_t *) msg->question, strlen(msg->question)+1);
	else
	{
		uint8_t q_len = 0;
		string_t question  = NULL;
		cursor += serialize_uint32(cursor, q_len);
		memcpy(cursor, question, 1);
		cursor += 1;
	}


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

tlv_t * generate_smp_msg_2(void)
{
	uint8_t *data = NULL;
	size_t len = 0;

	return otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, len, data);
}
