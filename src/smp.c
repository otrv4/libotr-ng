#include <string.h>

#include "auth.h"
#include "deserialize.h"
#include "dh.h"
#include "mpi.h"
#include "random.h"
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

void generate_smp_secret(unsigned char **secret, otrv4_fingerprint_t our_fp,
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

int hashToScalar(const unsigned char * buff, const size_t bufflen,
		decaf_448_scalar_t dst)
{
	gcry_md_hd_t hd;
	char otr_marker[4] = "OTR4";
	//TODO: should #DEFINE this size
	unsigned char hash[64];

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, &otr_marker, 4);
	gcry_md_write(hd, buff, bufflen);
	memcpy(hash, gcry_md_read(hd, 0), 64);
	gcry_md_close(hd);

	return DECAF_SUCCESS == decaf_448_scalar_decode(dst, hash);
}

int generate_smp_msg_1(smp_msg_1_t dst, smp_context_t smp)
{
	snizkpk_keypair_t pair_r2[1], pair_r3[1];
	unsigned char hash[ED448_POINT_BYTES+1];
	decaf_448_scalar_t a3c3, a2c2;

	dst->question = NULL;

	generate_keypair(dst->G2a, smp->a2);
	generate_keypair(dst->G3a, smp->a3);

	snizkpk_keypair_generate(pair_r2);
	snizkpk_keypair_generate(pair_r3);

	hash[0] = 0x01;
	memcpy(hash+1, pair_r2->pub, ED448_POINT_BYTES);
	//TODO: handle error
	hashToScalar(hash, 64, dst->c2);

	decaf_448_scalar_mul(a2c2, smp->a2, dst->c2);
	decaf_448_scalar_sub(dst->d2, pair_r2->priv, a2c2);

	hash[0] = 0x02;
	memcpy(hash+1, pair_r3->pub, ED448_POINT_BYTES);
	//TODO: handle error
	hashToScalar(hash, 64, dst->c3);

	decaf_448_scalar_mul(a3c3, smp->a3, dst->c3);
	decaf_448_scalar_sub(dst->d3, pair_r3->priv, a3c3);

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
		s += strlen(msg->question) + 1;
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

	//FIXME: I added 4 and 8 because valgrind reported, but I haven't
	//checked why.
	buff = malloc(s + 4 + 8);
	if (!dst)
		return 1;

	uint8_t *cursor = buff;

	if (!msg->question) {
		uint8_t null_question[4] = { 0x0, 0x0, 0x0, 0x0 };
		cursor += serialize_data(cursor, null_question, 0);
	} else
		cursor +=
		    serialize_data(cursor, (uint8_t *) msg->question,
				   strlen(msg->question) + 1);

	bool ok = serialize_ec_point(cursor, msg->G2a);
	if (!ok) {
		return false;
	}
	cursor += ED448_POINT_BYTES;
	cursor += serialize_mpi(cursor, c2_mpi);
	cursor += serialize_mpi(cursor, d2_mpi);
	ok = serialize_ec_point(cursor, msg->G3a);
	if (!ok) {
		return false;
	}
	cursor += ED448_POINT_BYTES;
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

//TODO: This is triplicated (see auth.c)
static void ed448_random_scalar(decaf_448_scalar_t priv)
{
	unsigned char rand[DECAF_448_SCALAR_BYTES];

	do {
		random_bytes(rand, DECAF_448_SCALAR_BYTES);
		int ok = decaf_448_scalar_decode(priv, rand);
		(void)ok;
	} while (DECAF_TRUE ==
		 decaf_448_scalar_eq(priv, decaf_448_scalar_zero));

	memset(rand, 0, DECAF_448_SCALAR_BYTES);
}

int generate_smp_msg_2(smp_msg_2_t dst, const smp_msg_1_t msg_1,
			  const unsigned char *secret, smp_context_t smp)
{
	decaf_448_scalar_t b2;
	snizkpk_keypair_t pair_r2[1], pair_r3[1], pair_r4[1], pair_r5[1];
	ec_scalar_t r6;
	unsigned char buff[DECAF_448_SER_BYTES+1];
	decaf_448_scalar_t temp_scalar;
	ec_point_t temp_point;

	generate_keypair(dst->G2b, b2);
	generate_keypair(dst->G3b, smp->b3);

	snizkpk_keypair_generate(pair_r2);
	snizkpk_keypair_generate(pair_r3);
	snizkpk_keypair_generate(pair_r4);
	snizkpk_keypair_generate(pair_r5);

	ed448_random_scalar(r6);

	//c2
	buff[0] = 0x03;
	memcpy(buff+1, pair_r2->pub, DECAF_448_SER_BYTES);
	//TODO: handle error
	hashToScalar(buff, DECAF_448_SER_BYTES+1, dst->c2);


	//d2 = r2 - b2 * c2 mod q.
	decaf_448_scalar_mul(temp_scalar, b2, dst->c2);
	decaf_448_scalar_sub(dst->d2, pair_r2->priv, temp_scalar);

	//c3
	buff[0] = 0x04;
	memcpy(buff+1, pair_r3->pub, DECAF_448_SER_BYTES);
	//TODO: handle error
	hashToScalar(buff, DECAF_448_SCALAR_BYTES+1, dst->c3);

	//d3 = r3 - b3 * c3 mod q.
	decaf_448_scalar_mul(temp_scalar, smp->b3, dst->c3);
	decaf_448_scalar_sub(dst->d3, pair_r3->priv, temp_scalar);

	//Compute G2 = G2a * b2
	decaf_448_point_scalarmul(smp->G2, msg_1->G2a, b2);
	//Compute G3 = G3a * b3.
	decaf_448_point_scalarmul(smp->G3, msg_1->G3a, smp->b3);
	memcpy(smp->G3a, msg_1->G3a, ED448_POINT_BYTES);

	//Compute Pb = G3 * r4
	decaf_448_point_scalarmul(smp->Pb, smp->G3, pair_r4->priv);

	//Compute Qb = G * r4 + G2 * hashToScalar(y).
	decaf_448_scalar_t secret_as_scalar;
	hashToScalar(secret, 64, secret_as_scalar);
	decaf_448_point_scalarmul(smp->Qb, smp->G2, secret_as_scalar);
	decaf_448_point_add(smp->Qb, pair_r4->pub, smp->Qb);

	//cp = HashToScalar(5 || G3 * r5 || G * r5 + G2 * r6)
	unsigned char buff_cp[ED448_POINT_BYTES*2+1];
	buff_cp[0] = 0x05;
	decaf_448_point_scalarmul(temp_point, smp->G3, pair_r5->priv);
	memcpy(buff_cp+1, temp_point, ED448_POINT_BYTES);
	decaf_448_point_scalarmul(temp_point, smp->G2, r6);
	decaf_448_point_add(temp_point, pair_r5->pub, temp_point);
	memcpy(buff_cp+1+ED448_POINT_BYTES, temp_point, ED448_POINT_BYTES);
	hashToScalar(buff_cp, ED448_POINT_BYTES*2+1, dst->cp);

	//d5 = r5 - r4 * cp mod q
	decaf_448_scalar_mul(dst->d5, pair_r4->priv, dst->cp);
	decaf_448_scalar_sub(dst->d5, pair_r5->priv, dst->d5);

	//d6 = r6 - y * cp mod q.
	decaf_448_scalar_mul(dst->d6, secret_as_scalar, dst->cp);
	decaf_448_scalar_sub(dst->d6, r6, dst->d6);

	return 0;
}

int smp_msg_2_aprint(uint8_t ** dst, size_t * len, const smp_msg_2_t msg)
{
	uint8_t * buff;
	uint8_t * cursor;
	uint8_t buffmpi[DECAF_448_SER_BYTES];
	int bufflen = 0;
	size_t s = 0;
	s = 4 * ED448_POINT_BYTES;
	otr_mpi_t c2_mpi, d2_mpi, c3_mpi, d3_mpi, cp_mpi, d5_mpi, d6_mpi;

	bufflen = serialize_ec_scalar(buffmpi, msg->c2);
	otr_mpi_set(c2_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->d2);
	otr_mpi_set(d2_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->c3);
	otr_mpi_set(c3_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->d3);
	otr_mpi_set(d3_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->cp);
	otr_mpi_set(cp_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->d5);
	otr_mpi_set(d5_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->d6);
	otr_mpi_set(d6_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	buff = malloc(s);
        cursor = buff;

	bool ok = serialize_ec_point(cursor, msg->G2b);
	if (!ok)
	      //TODO: should free MPIs in all errors
	      return 1;

	cursor += serialize_mpi(cursor, c2_mpi);
	cursor += serialize_mpi(cursor, d2_mpi);

	ok = serialize_ec_point(cursor, msg->G3b);
	if (!ok)
	      return 1;

	cursor += serialize_mpi(cursor, c3_mpi);
	cursor += serialize_mpi(cursor, d3_mpi);

	ok = serialize_ec_point(cursor, msg->Pb);
	if (!ok)
	      return 1;

	ok = serialize_ec_point(cursor, msg->Qb);
	if (!ok)
	      return 1;

	cursor += serialize_mpi(cursor, cp_mpi);
	cursor += serialize_mpi(cursor, d5_mpi);
	cursor += serialize_mpi(cursor, d6_mpi);

	*dst = buff;
	*len = s;

	otr_mpi_free(c2_mpi);
	otr_mpi_free(d2_mpi);
	otr_mpi_free(c3_mpi);
	otr_mpi_free(d3_mpi);
	otr_mpi_free(cp_mpi);
	otr_mpi_free(d5_mpi);
	otr_mpi_free(d6_mpi);

	return 0;
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
	const uint8_t *cursor = buff;

	if (!otr_mpi_deserialize_no_copy(tmp_mpi, cursor, bufflen, &r))
		return false;

	if (!deserialize_ec_scalar(dst, tmp_mpi->data, tmp_mpi->len))
		return false;

	*read = r + tmp_mpi->len;

	return true;
}

bool smp_msg_1_deserialize(smp_msg_1_t msg, const tlv_t * tlv)
{
	const uint8_t *cursor = tlv->data;
	uint16_t len = tlv->len;
	size_t read = 0;

	if (!deserialize_data((uint8_t **) & msg->question, cursor, len, &read))
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
