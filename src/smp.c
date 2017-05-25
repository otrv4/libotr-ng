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

        //TODO: We should also destroy smp->msg1
}

void generate_smp_secret(unsigned char **secret, otrv4_fingerprint_t our_fp,
			 otrv4_fingerprint_t their_fp, uint8_t * ssid,
			 const uint8_t *answer, size_t answerlen)
{
	gcry_md_hd_t hd;
	uint8_t version[1] = { 0x01 };

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, version, 1);
	gcry_md_write(hd, our_fp, sizeof(otrv4_fingerprint_t));
	gcry_md_write(hd, their_fp, sizeof(otrv4_fingerprint_t));
	gcry_md_write(hd, ssid, 8);
	gcry_md_write(hd, answer, answerlen);

	*secret = malloc(64);
	if (!*secret)
		return;

	memcpy(*secret, gcry_md_read(hd, 0), 64);
	gcry_md_close(hd);
}

int hashToScalar(const unsigned char *buff, const size_t bufflen,
		 ec_scalar_t dst)
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
	unsigned char hash[ED448_POINT_BYTES + 1];
	ec_scalar_t a3c3, a2c2;

	dst->question = NULL;

	generate_keypair(dst->G2a, smp->a2);
	generate_keypair(dst->G3a, smp->a3);

	snizkpk_keypair_generate(pair_r2);
	snizkpk_keypair_generate(pair_r3);

	hash[0] = 0x01;
	//TODO: this can goes wrong
	serialize_ec_point(hash + 1, pair_r2->pub);
	//TODO: handle error
	hashToScalar(hash, sizeof(hash), dst->c2);

	decaf_448_scalar_mul(a2c2, smp->a2, dst->c2);
	decaf_448_scalar_sub(dst->d2, pair_r2->priv, a2c2);

	hash[0] = 0x02;
	//TODO: this can goes wrong
	serialize_ec_point(hash + 1, pair_r3->pub);
	//TODO: handle error
	hashToScalar(hash, sizeof(hash), dst->c3);

	decaf_448_scalar_mul(a3c3, smp->a3, dst->c3);
	decaf_448_scalar_sub(dst->d3, pair_r3->priv, a3c3);

	return 0;
}

bool smp_msg_1_aprint(uint8_t ** dst, size_t * len, const smp_msg_1_t msg)
{
	uint8_t buffmpi[ED448_SCALAR_BYTES];
	int bufflen = 0;
	otr_mpi_t c2_mpi, d2_mpi, c3_mpi, d3_mpi;
	size_t s = 0;

	s += 4;
	if (msg->question)
		s += strlen(msg->question) + 1;
	s += 2 * ED448_POINT_BYTES;

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

	*dst = malloc(s);
	if (!*dst)
		return false;

	uint8_t *cursor = *dst;

        cursor += serialize_data(cursor, (uint8_t *) msg->question,
            msg->question ? strlen(msg->question)+1 : 0);

	if (serialize_ec_point(cursor, msg->G2a))
		return false;

	cursor += ED448_POINT_BYTES;
	cursor += serialize_mpi(cursor, c2_mpi);
	cursor += serialize_mpi(cursor, d2_mpi);
	if (serialize_ec_point(cursor, msg->G3a))
		return false;

	cursor += ED448_POINT_BYTES;
	cursor += serialize_mpi(cursor, c3_mpi);
	cursor += serialize_mpi(cursor, d3_mpi);

	*len = s;

	otr_mpi_free(c2_mpi);
	otr_mpi_free(d2_mpi);
	otr_mpi_free(c3_mpi);
	otr_mpi_free(d3_mpi);

	return true;
}

//TODO: This is triplicated (see auth.c)
static void ed448_random_scalar(ec_scalar_t priv)
{
	uint8_t sym[ED448_PRIVATE_BYTES];
	random_bytes(sym, ED448_PRIVATE_BYTES);
	ec_scalar_derive_from_secret(priv, sym);
}

int generate_smp_msg_2(smp_msg_2_t dst, const smp_msg_1_t msg_1,
		       smp_context_t smp)
{
	ec_scalar_t b2;
	snizkpk_keypair_t pair_r2[1], pair_r3[1], pair_r4[1], pair_r5[1];
	ec_scalar_t r6;
	unsigned char buff[ED448_POINT_BYTES + 1];
	ec_scalar_t temp_scalar;
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
    // TODO: test for better error generation here
    if (serialize_ec_point(buff + 1, pair_r2->pub)) {
        return -1;
    }
	hashToScalar(buff, ED448_POINT_BYTES + 1, dst->c2);

	//d2 = r2 - b2 * c2 mod q.
	decaf_448_scalar_mul(temp_scalar, b2, dst->c2);
	decaf_448_scalar_sub(dst->d2, pair_r2->priv, temp_scalar);

	//c3
	buff[0] = 0x04;
    // TODO: test for better error generation here
    if (serialize_ec_point(buff + 1, pair_r3->pub)) {
        return -1;
    }
	hashToScalar(buff, ED448_POINT_BYTES + 1, dst->c3);

	//d3 = r3 - b3 * c3 mod q.
	decaf_448_scalar_mul(temp_scalar, smp->b3, dst->c3);
	decaf_448_scalar_sub(dst->d3, pair_r3->priv, temp_scalar);

	//Compute G2 = G2a * b2
	decaf_448_point_scalarmul(smp->G2, msg_1->G2a, b2);
	//Compute G3 = G3a * b3.
	decaf_448_point_scalarmul(smp->G3, msg_1->G3a, smp->b3);
	ec_point_copy(smp->G3a, msg_1->G3a);

	//Compute Pb = G3 * r4
	decaf_448_point_scalarmul(dst->Pb, smp->G3, pair_r4->priv);
	ec_point_copy(smp->Pb, dst->Pb);

	//Compute Qb = G * r4 + G2 * hashToScalar(y).
	ec_scalar_t secret_as_scalar;
	hashToScalar(smp->y, 64, secret_as_scalar);
	decaf_448_point_scalarmul(dst->Qb, smp->G2, secret_as_scalar);
	decaf_448_point_add(dst->Qb, pair_r4->pub, dst->Qb);
	ec_point_copy(smp->Qb, dst->Qb);

	//cp = HashToScalar(5 || G3 * r5 || G * r5 + G2 * r6)
	unsigned char buff_cp[ED448_POINT_BYTES * 2 + 1];
	buff_cp[0] = 0x05;
	decaf_448_point_scalarmul(temp_point, smp->G3, pair_r5->priv);
    // TODO: test for better error generation here
    if (serialize_ec_point(buff_cp + 1, temp_point)) {
        return -1;
    }

	decaf_448_point_scalarmul(temp_point, smp->G2, r6);
	decaf_448_point_add(temp_point, pair_r5->pub, temp_point);
    // TODO: test for better error generation here
    if (serialize_ec_point(buff_cp + 1 + ED448_POINT_BYTES, temp_point)) {
        return -1;
    }
	hashToScalar(buff_cp, ED448_POINT_BYTES * 2 + 1, dst->cp);

	//d5 = r5 - r4 * cp mod q
	decaf_448_scalar_mul(dst->d5, pair_r4->priv, dst->cp);
	decaf_448_scalar_sub(dst->d5, pair_r5->priv, dst->d5);

	//d6 = r6 - y * cp mod q.
	decaf_448_scalar_mul(dst->d6, secret_as_scalar, dst->cp);
	decaf_448_scalar_sub(dst->d6, r6, dst->d6);

	return 0;
}

bool smp_msg_2_aprint(uint8_t ** dst, size_t * len, const smp_msg_2_t msg)
{
	uint8_t *cursor;
	uint8_t buffmpi[ED448_SCALAR_BYTES];
	int bufflen = 0;
	size_t s = 0;
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

	s += 4 * ED448_POINT_BYTES;
	*dst = malloc(s);
	if (!*dst)
		return false;

	*len = s;
	cursor = *dst;

	if (serialize_ec_point(cursor, msg->G2b))
		//TODO: should free MPIs in all errors
		return false;
	cursor += ED448_POINT_BYTES;

	cursor += serialize_mpi(cursor, c2_mpi);
	cursor += serialize_mpi(cursor, d2_mpi);

	if (serialize_ec_point(cursor, msg->G3b))
		//TODO: should free MPIs in all errors
		return false;
	cursor += ED448_POINT_BYTES;

	cursor += serialize_mpi(cursor, c3_mpi);
	cursor += serialize_mpi(cursor, d3_mpi);

	if (serialize_ec_point(cursor, msg->Pb))
		//TODO: should free MPIs in all errors
		return false;
	cursor += ED448_POINT_BYTES;

	if (serialize_ec_point(cursor, msg->Qb))
		//TODO: should free MPIs in all errors
		return false;
	cursor += ED448_POINT_BYTES;

	cursor += serialize_mpi(cursor, cp_mpi);
	cursor += serialize_mpi(cursor, d5_mpi);
	cursor += serialize_mpi(cursor, d6_mpi);

	otr_mpi_free(c2_mpi);
	otr_mpi_free(d2_mpi);
	otr_mpi_free(c3_mpi);
	otr_mpi_free(d3_mpi);
	otr_mpi_free(cp_mpi);
	otr_mpi_free(d5_mpi);
	otr_mpi_free(d6_mpi);

	return true;
}

static bool
deserialize_mpi_to_scalar(ec_scalar_t dst, const uint8_t * buff,
			  uint16_t bufflen, size_t * read)
{
	otr_mpi_t tmp_mpi;
	size_t r = 0;
	const uint8_t *cursor = buff;

	if (!otr_mpi_deserialize_no_copy(tmp_mpi, cursor, bufflen, &r))
		return false;

	if (deserialize_ec_scalar(dst, tmp_mpi->data, tmp_mpi->len))
		return false;

	*read = r + tmp_mpi->len;

	return true;
}

bool smp_msg_1_deserialize(smp_msg_1_t msg, const tlv_t * tlv)
{
	const uint8_t *cursor = tlv->data;
	uint16_t len = tlv->len;
	size_t read = 0;

        msg->question = NULL;
	if (deserialize_data((uint8_t **) & msg->question, cursor, len, &read))
		return false;

	cursor += read;
	len -= read;

	if (deserialize_ec_point(msg->G2a, cursor))
		return false;

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	if (!deserialize_mpi_to_scalar(msg->c2, cursor, len, &read))
		return false;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(msg->d2, cursor, len, &read))
		return false;

	cursor += read;
	len -= read;

	if (deserialize_ec_point(msg->G3a, cursor))
		return false;

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

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

int smp_msg_2_deserialize(smp_msg_2_t msg, const tlv_t * tlv)
{
	const uint8_t *cursor = tlv->data;
	uint16_t len = tlv->len;
	size_t read = 0;

	if (deserialize_ec_point(msg->G2b, cursor))
		return 1;

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	if (!deserialize_mpi_to_scalar(msg->c2, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(msg->d2, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (deserialize_ec_point(msg->G3b, cursor))
		return 1;

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	if (!deserialize_mpi_to_scalar(msg->c3, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(msg->d3, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (deserialize_ec_point(msg->Pb, cursor))
		return 1;

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	if (deserialize_ec_point(msg->Qb, cursor))
		return 1;

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	if (!deserialize_mpi_to_scalar(msg->cp, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(msg->d5, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(msg->d6, cursor, len, &read))
		return 1;
	len -= read;

	return len;
}

bool smp_msg_2_validate_points(smp_msg_2_t msg)
{
	return ec_point_valid(msg->G2b) && ec_point_valid(msg->G3b) &&
	    ec_point_valid(msg->Pb) && ec_point_valid(msg->Qb);
}

bool smp_msg_2_validate_zkp(smp_msg_2_t msg, const smp_context_t smp)
{
	uint8_t hash[ED448_POINT_BYTES + 1];
	ec_scalar_t temp_scalar;
	ec_point_t Gb_c, G_d, point_cp;
	bool ok;

	//Check that c2 = HashToScalar(3 || G * d2 + G2b * c2).
	decaf_448_point_scalarmul(Gb_c, msg->G2b, msg->c2);
	decaf_448_point_scalarmul(G_d, decaf_448_point_base, msg->d2);
	decaf_448_point_add(G_d, G_d, Gb_c);
	hash[0] = 0x03;
	if (serialize_ec_point(hash + 1, G_d))	return false;

	hashToScalar(hash, ED448_POINT_BYTES + 1, temp_scalar);
	ok = ec_scalar_eq(temp_scalar, msg->c2);

	//Check that c3 = HashToScalar(4 || G * d3 + G3b * c3).
	decaf_448_point_scalarmul(Gb_c, msg->G3b, msg->c3);
	decaf_448_point_scalarmul(G_d, decaf_448_point_base, msg->d3);
	decaf_448_point_add(G_d, G_d, Gb_c);
	hash[0] = 0x04;
	if (serialize_ec_point(hash + 1, G_d))	return false;

	hashToScalar(hash, ED448_POINT_BYTES + 1, temp_scalar);
	ok &= ec_scalar_eq(temp_scalar, msg->c3);

	//Check that cp = HashToScalar(5 || G3 * d5 + Pb * cp || G * d5 + G2 * d6 + Qb * cp)
	uint8_t buff[2 * ED448_POINT_BYTES + 1];
	buff[0] = 0x05;
	decaf_448_point_scalarmul(point_cp, msg->Pb, msg->cp);
	decaf_448_point_scalarmul(G_d, smp->G3, msg->d5);
	decaf_448_point_add(G_d, G_d, point_cp);
	if (serialize_ec_point(buff + 1, G_d))	return false;

	decaf_448_point_scalarmul(point_cp, msg->Qb, msg->cp);
	decaf_448_point_scalarmul(G_d, smp->G2, msg->d6);
	decaf_448_point_add(G_d, G_d, point_cp);

	decaf_448_point_scalarmul(point_cp, decaf_448_point_base, msg->d5);
	decaf_448_point_add(G_d, G_d, point_cp);
	if (serialize_ec_point(buff + 1 + ED448_POINT_BYTES, G_d)) return false;

	hashToScalar(buff, sizeof(buff), temp_scalar);

	return ok & ec_scalar_eq(temp_scalar, msg->cp);
}

bool generate_smp_msg_3(smp_msg_3_t dst, const smp_msg_2_t msg_2,
			smp_context_t smp)
{
	snizkpk_keypair_t pair_r4[1], pair_r5[1], pair_r7[1];
	ec_scalar_t r6, secret_as_scalar;
	ec_point_t temp_point;
	uint8_t buff[1 + 2 * ED448_POINT_BYTES];

	ed448_random_scalar(r6);

	snizkpk_keypair_generate(pair_r4);
	snizkpk_keypair_generate(pair_r5);
	snizkpk_keypair_generate(pair_r7);

	//Pa = G3 * r4
	decaf_448_point_scalarmul(dst->Pa, smp->G3, pair_r4->priv);
	decaf_448_point_sub(smp->Pa_Pb, dst->Pa, msg_2->Pb);

	hashToScalar(smp->x, 64, secret_as_scalar);

	//Qa = G * r4 + G2 * HashToScalar(x)
	decaf_448_point_scalarmul(dst->Qa, smp->G2, secret_as_scalar);
	decaf_448_point_add(dst->Qa, pair_r4->pub, dst->Qa);

	//cp = HashToScalar(6 || G3 * r5 || G * r5 + G2 * r6)
	buff[0] = 0x06;
	decaf_448_point_scalarmul(temp_point, smp->G3, pair_r5->priv);
	if (serialize_ec_point(buff + 1, temp_point)) return false;

	decaf_448_point_scalarmul(temp_point, smp->G2, r6);
	decaf_448_point_add(temp_point, pair_r5->pub, temp_point);
	if (serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point)) return false;
	hashToScalar(buff, sizeof(buff), dst->cp);

	//d5 = r5 - r4 * cp mod q
	decaf_448_scalar_mul(dst->d5, pair_r4->priv, dst->cp);
	decaf_448_scalar_sub(dst->d5, pair_r5->priv, dst->d5);

	//d6 = r6 - HashToScalar(x) * cp mod q
	decaf_448_scalar_mul(dst->d6, secret_as_scalar, dst->cp);
	decaf_448_scalar_sub(dst->d6, r6, dst->d6);

	//Ra = (Qa - Qb) * a3
	decaf_448_point_sub(smp->Qa_Qb, dst->Qa, msg_2->Qb);
	decaf_448_point_scalarmul(dst->Ra, smp->Qa_Qb, smp->a3);

	//cr = HashToScalar(7 || G * r7 || (Qa - Qb) * r7)
	buff[0] = 0x07;
	if (serialize_ec_point(buff + 1, pair_r7->pub)) return false;
	decaf_448_point_scalarmul(temp_point, smp->Qa_Qb, pair_r7->priv);
	if (serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point)) return false;
	hashToScalar(buff, sizeof(buff), dst->cr);

	//d7 = r7 - a3 * cr mod q
	decaf_448_scalar_mul(dst->d7, smp->a3, dst->cr);
	decaf_448_scalar_sub(dst->d7, pair_r7->priv, dst->d7);

	return true;
}

bool smp_msg_3_aprint(uint8_t ** dst, size_t * len, const smp_msg_3_t msg)
{
	uint8_t *cursor;
	uint8_t buffmpi[ED448_SCALAR_BYTES];
	int bufflen = 0;
	size_t s = 0;
	otr_mpi_t cp_mpi, d5_mpi, d6_mpi, cr_mpi, d7_mpi;

	bufflen = serialize_ec_scalar(buffmpi, msg->cp);
	otr_mpi_set(cp_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->d5);
	otr_mpi_set(d5_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->d6);
	otr_mpi_set(d6_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->cr);
	otr_mpi_set(cr_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->d7);
	otr_mpi_set(d7_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	s += 3 * ED448_POINT_BYTES;
	*dst = malloc(s);
	if (!*dst)
		return false;

	*len = s;
	cursor = *dst;
	//TODO: should free buffer in the errors
	if (serialize_ec_point(cursor, msg->Pa))
		return false;
	cursor += ED448_POINT_BYTES;

	if (serialize_ec_point(cursor, msg->Qa))
		return false;
	cursor += ED448_POINT_BYTES;

	cursor += serialize_mpi(cursor, cp_mpi);
	cursor += serialize_mpi(cursor, d5_mpi);
	cursor += serialize_mpi(cursor, d6_mpi);

	if (serialize_ec_point(cursor, msg->Ra))
		return false;
	cursor += ED448_POINT_BYTES;

	cursor += serialize_mpi(cursor, cr_mpi);
	cursor += serialize_mpi(cursor, d7_mpi);

	otr_mpi_free(cp_mpi);
	otr_mpi_free(d5_mpi);
	otr_mpi_free(d6_mpi);
	otr_mpi_free(cr_mpi);
	otr_mpi_free(d7_mpi);

	return true;
}

int smp_msg_3_deserialize(smp_msg_3_t dst, const tlv_t * tlv)
{
	const uint8_t *cursor = tlv->data;
	uint16_t len = tlv->len;
	size_t read = 0;

	if (deserialize_ec_point(dst->Pa, cursor))
		return 1;

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	if (deserialize_ec_point(dst->Qa, cursor))
		return 1;

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	if (!deserialize_mpi_to_scalar(dst->cp, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(dst->d5, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(dst->d6, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (deserialize_ec_point(dst->Ra, cursor))
		return 1;

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	if (!deserialize_mpi_to_scalar(dst->cr, cursor, len, &read))
		return 1;

	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(dst->d7, cursor, len, &read))
		return 1;

	len -= read;
	return len;
}

bool smp_msg_3_validate_points(smp_msg_3_t msg)
{
	return ec_point_valid(msg->Pa) && ec_point_valid(msg->Qa) &&
	    ec_point_valid(msg->Ra);
}

bool smp_msg_3_validate_zkp(smp_msg_3_t msg, const smp_context_t smp)
{
	uint8_t buff[1 + 2 * ED448_POINT_BYTES];
	ec_point_t temp_point, temp_point_2;
	ec_scalar_t temp_scalar;
	bool ok;

	//cp = HashToScalar(6 || G3 * d5 + Pa * cp || G * d5 + G2 * d6 + Qa * cp)
	buff[0] = 0x06;
	decaf_448_point_scalarmul(temp_point, msg->Pa, msg->cp);
	decaf_448_point_scalarmul(temp_point_2, smp->G3, msg->d5);
	decaf_448_point_add(temp_point, temp_point, temp_point_2);
	if (serialize_ec_point(buff + 1, temp_point)) return false;

	decaf_448_point_scalarmul(temp_point, msg->Qa, msg->cp);
	decaf_448_point_scalarmul(temp_point_2, smp->G2, msg->d6);
	decaf_448_point_add(temp_point, temp_point, temp_point_2);
	decaf_448_point_scalarmul(temp_point_2, decaf_448_point_base, msg->d5);
	decaf_448_point_add(temp_point, temp_point, temp_point_2);
	if (serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point))
		return false;

	hashToScalar(buff, sizeof(buff), temp_scalar);
	ok = ec_scalar_eq(temp_scalar, msg->cp);

	//cr = HashToScalar(7 || G * d7 + G3a * cr || (Qa - Qb) * d7 + Ra * cr)
	buff[0] = 0x07;
	decaf_448_point_scalarmul(temp_point, smp->G3a, msg->cr);
	decaf_448_point_scalarmul(temp_point_2, decaf_448_point_base, msg->d7);
	decaf_448_point_add(temp_point, temp_point, temp_point_2);
	if (serialize_ec_point(buff + 1, temp_point)) return false;

	decaf_448_point_scalarmul(temp_point, msg->Ra, msg->cr);
	decaf_448_point_sub(temp_point_2, msg->Qa, smp->Qb);
	decaf_448_point_scalarmul(temp_point_2, temp_point_2, msg->d7);
	decaf_448_point_add(temp_point, temp_point, temp_point_2);
	if (serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point))
		return false;

	hashToScalar(buff, sizeof(buff), temp_scalar);

	return ok & ec_scalar_eq(temp_scalar, msg->cr);
}

bool generate_smp_msg_4(smp_msg_4_t * dst, const smp_msg_3_t msg_3, smp_context_t smp)
{
	uint8_t buff[1 + 2 * ED448_POINT_BYTES];
	ec_point_t Qa_Qb;
	snizkpk_keypair_t pair_r7[1];
	snizkpk_keypair_generate(pair_r7);


	//Rb = (Qa - Qb) * b3
	decaf_448_point_sub(Qa_Qb, msg_3->Qa, smp->Qb);
	decaf_448_point_scalarmul(dst->Rb, Qa_Qb, smp->b3);

	//cr = HashToScalar(8 || G * r7 || (Qa - Qb) * r7)
	buff[0] = 0x08;
	if (serialize_ec_point(buff + 1, pair_r7->pub)) return false;
	decaf_448_point_scalarmul(Qa_Qb, Qa_Qb, pair_r7->priv);
	if (serialize_ec_point(buff + 1 + ED448_POINT_BYTES, Qa_Qb))
		return false;
	hashToScalar(buff, sizeof(buff), dst->cr);

	//d7 = r7 - b3 * cr mod q
	decaf_448_scalar_mul(dst->d7, smp->b3, dst->cr);
	decaf_448_scalar_sub(dst->d7, pair_r7->priv, dst->d7);

	return true;
}

bool smp_msg_4_aprint(uint8_t **dst, size_t *len, smp_msg_4_t *msg)
{
	uint8_t buffmpi[ED448_SCALAR_BYTES];
	int bufflen = 0;
	otr_mpi_t cr_mpi, d7_mpi;
	size_t s = 0;

	bufflen = serialize_ec_scalar(buffmpi, msg->cr);
	otr_mpi_set(cr_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	bufflen = serialize_ec_scalar(buffmpi, msg->d7);
	otr_mpi_set(d7_mpi, buffmpi, bufflen);
	s += bufflen + 4;

	s += ED448_POINT_BYTES;
	*dst = malloc(s);
	if (!*dst)
		return false;

	uint8_t *cursor = *dst;

	if (serialize_ec_point(cursor, msg->Rb))
		return false;

	cursor += ED448_POINT_BYTES;
	cursor += serialize_mpi(cursor, cr_mpi);
	cursor += serialize_mpi(cursor, d7_mpi);

	*len = s;

	otr_mpi_free(cr_mpi);
	otr_mpi_free(d7_mpi);

	return true;
}

int smp_msg_4_deserialize(smp_msg_4_t *dst, const tlv_t *tlv)
{
	uint8_t *cursor = tlv->data;
	size_t len = tlv->len;
	size_t read = 0;

	if (deserialize_ec_point(dst->Rb, cursor))
		return 1;
	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	if (!deserialize_mpi_to_scalar(dst->cr, cursor, len, &read))
		return 1;
	cursor += read;
	len -= read;

	if (!deserialize_mpi_to_scalar(dst->d7, cursor, len, &read))
		return 1;
	len -= read;

	return len;
}

bool smp_msg_4_validate_zkp(smp_msg_4_t * msg, const smp_context_t smp)
{
	uint8_t buff[1 + 2 * ED448_POINT_BYTES];
	ec_point_t temp_point, temp_point_2;
	ec_scalar_t temp_scalar;

	//cr = HashToScalar(8 || G * d7 + G3 * cr || (Qa - Qb) * d7 + Rb * cr).
	buff[0] = 0x08;
	decaf_448_point_scalarmul(temp_point, smp->G3, msg->cr);
	decaf_448_point_scalarmul(temp_point_2, decaf_448_point_base, msg->d7);
	decaf_448_point_add(temp_point, temp_point, temp_point_2);
	if (serialize_ec_point(buff + 1, temp_point)) return false;

	decaf_448_point_scalarmul(temp_point, msg->Rb, msg->cr);
	decaf_448_point_scalarmul(temp_point_2, smp->Qa_Qb, msg->d7);
	decaf_448_point_add(temp_point, temp_point, temp_point_2);
	if (serialize_ec_point(buff + 1 + ED448_POINT_BYTES, temp_point)) return false;

	hashToScalar(buff, sizeof(buff), temp_scalar);

	return ec_scalar_eq(msg->cr, temp_scalar) == 0;
}

static otr4_smp_event_t receive_smp_msg_1(smp_msg_1_t msg_1, const tlv_t *tlv, smp_context_t smp)
{
    if (SMPSTATE_EXPECT1 != smp->state) {
        return OTRV4_SMPEVENT_ABORT;
    }

    if (!smp_msg_1_deserialize(msg_1, tlv))
        return OTRV4_SMPEVENT_ERROR;

    if (!smp_msg_1_validate(msg_1))
        return OTRV4_SMPEVENT_ERROR;

    if (msg_1->question)
        smp->msg1->question = otrv4_strdup(msg_1->question);

    ec_point_copy(smp->msg1->G2a, msg_1->G2a);
    ec_scalar_copy(smp->msg1->c2, msg_1->c2);
    ec_scalar_copy(smp->msg1->d2, msg_1->d2);
    ec_point_copy(smp->msg1->G3a, msg_1->G3a);
    ec_scalar_copy(smp->msg1->c3, msg_1->c3);
    ec_scalar_copy(smp->msg1->d3, msg_1->d3);

    return OTRV4_SMPEVENT_NONE;
}

//TODO:
static otr4_smp_event_t reply_with_smp_msg_2(tlv_t **to_send, const smp_msg_1_t msg_1, smp_context_t smp)
{
    smp_msg_2_t msg_2;
    uint8_t *buff;
    size_t bufflen;

    *to_send = NULL;

    //TODO: what to do is somtheing wrong happen?
    generate_smp_msg_2(msg_2, msg_1, smp);
    if (!smp_msg_2_aprint(&buff, &bufflen, msg_2))
        return OTRV4_SMPEVENT_ERROR;

    *to_send = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, bufflen, buff);
    free(buff);

    if (!to_send)
        return OTRV4_SMPEVENT_ERROR;

    smp->state = SMPSTATE_EXPECT3;
    smp->progress = 50;
    return OTRV4_SMPEVENT_NONE;
}

static otr4_smp_event_t receive_smp_msg_2(smp_msg_2_t msg_2, const tlv_t *tlv,
					  smp_context_t smp)
{
	if (SMPSTATE_EXPECT2 != smp->state)
		return OTRV4_SMPEVENT_ERROR;

	if (smp_msg_2_deserialize(msg_2, tlv) != 0)
		return OTRV4_SMPEVENT_ERROR;

	if (!smp_msg_2_validate_points(msg_2))
		return OTRV4_SMPEVENT_ERROR;

	decaf_448_point_scalarmul(smp->G2, msg_2->G2b,
			smp->a2);
	decaf_448_point_scalarmul(smp->G3, msg_2->G3b,
			smp->a3);

	if (!smp_msg_2_validate_zkp(msg_2, smp))
		return OTRV4_SMPEVENT_ERROR;

	return OTRV4_SMPEVENT_NONE;
}

static otr4_smp_event_t reply_with_smp_msg_3(tlv_t **to_send,
		const smp_msg_2_t msg_2, smp_context_t smp)
{
	smp_msg_3_t msg_3;
	uint8_t *buff = NULL;
	size_t bufflen = 0;

	if (!generate_smp_msg_3(msg_3, msg_2, smp))
		return OTRV4_SMPEVENT_ERROR;

	if (!smp_msg_3_aprint(&buff, &bufflen, msg_3))
		return OTRV4_SMPEVENT_ERROR;

	*to_send = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_3, bufflen, buff);
	free(buff);

	if (!to_send)
		return OTRV4_SMPEVENT_ERROR;

	smp->state = SMPSTATE_EXPECT4;
        smp->progress = 50;
	return OTRV4_SMPEVENT_NONE;
}

static otr4_smp_event_t receive_smp_msg_3(smp_msg_3_t msg_3, const tlv_t *tlv,
		smp_context_t smp)
{
	if (SMPSTATE_EXPECT3 != smp->state)
		return OTRV4_SMPEVENT_ERROR;

	if (smp_msg_3_deserialize(msg_3, tlv) != 0)
		return OTRV4_SMPEVENT_ERROR;

	if (!smp_msg_3_validate_points(msg_3))
		return OTRV4_SMPEVENT_ERROR;

	if (!smp_msg_3_validate_zkp(msg_3, smp))
		return OTRV4_SMPEVENT_ERROR;

        smp->progress = 75;
	return OTRV4_SMPEVENT_NONE;
}

static bool smp_is_valid_for_msg_3(const smp_msg_3_t msg, smp_context_t smp)
{
	ec_point_t Rab, Pa_Pb;
	//Compute Rab = Ra * b3
	decaf_448_point_scalarmul(Rab, msg->Ra, smp->b3);
	//Pa - Pb == Rab
	decaf_448_point_sub(Pa_Pb, msg->Pa, smp->Pb);
	return DECAF_TRUE == decaf_448_point_eq(Pa_Pb, Rab);
}

static otr4_smp_event_t reply_with_smp_msg_4(tlv_t **to_send,
		const smp_msg_3_t msg_3, smp_context_t smp)
{
	smp_msg_4_t msg_4[1];
	uint8_t *buff = NULL;
	size_t bufflen = 0;

	if (!generate_smp_msg_4(msg_4, msg_3, smp))
		return OTRV4_SMPEVENT_ERROR;

	if (!smp_msg_4_aprint(&buff, &bufflen, msg_4))
		return OTRV4_SMPEVENT_ERROR;

	*to_send = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_4, bufflen, buff);

	//Validates SMP
        smp->progress = 100;
	smp->state = SMPSTATE_EXPECT1;
	if (!smp_is_valid_for_msg_3(msg_3, smp))
		return OTRV4_SMPEVENT_FAILURE;

	return OTRV4_SMPEVENT_SUCCESS;
}

static bool smp_is_valid_for_msg_4(smp_msg_4_t *msg, smp_context_t smp)
{
	ec_point_t Rab;
	//Compute Rab = Rb * a3.
	decaf_448_point_scalarmul(Rab, msg->Rb, smp->a3);
	//Pa - Pb == Rab
	return DECAF_TRUE == decaf_448_point_eq(smp->Pa_Pb, Rab);
}

static otr4_smp_event_t receive_smp_msg_4(smp_msg_4_t *msg_4, const tlv_t *tlv,
		smp_context_t smp)
{
	if (SMPSTATE_EXPECT4 != smp->state)
		return OTRV4_SMPEVENT_ERROR;

	if (smp_msg_4_deserialize(msg_4, tlv) != 0)
		return OTRV4_SMPEVENT_ERROR;

	if (!ec_point_valid(msg_4->Rb))
		return OTRV4_SMPEVENT_ERROR;

	if (!smp_msg_4_validate_zkp(msg_4, smp))
		return OTRV4_SMPEVENT_ERROR;

        smp->progress = 100;
	smp->state = SMPSTATE_EXPECT1;
	if (!smp_is_valid_for_msg_4(msg_4, smp))
		return OTRV4_SMPEVENT_FAILURE;

	return OTRV4_SMPEVENT_SUCCESS;
}

static otr4_smp_event_t process_smp_msg1(const tlv_t* tlv, smp_context_t smp)
{
    smp_msg_1_t msg_1;

    otr4_smp_event_t event = receive_smp_msg_1(msg_1, tlv, smp);
    if (!event) {
        smp->progress = 25;
        event = OTRV4_SMPEVENT_ASK_FOR_ANSWER;
    }

    //TODO: destroy msg_1
    return event;
}

static otr4_smp_event_t process_smp_msg2(tlv_t **smp_reply, const tlv_t* tlv, smp_context_t smp)
{
    smp_msg_2_t msg_2;
    otr4_smp_event_t event = receive_smp_msg_2(msg_2, tlv, smp);

    if (!event)
        event = reply_with_smp_msg_3(smp_reply, msg_2, smp);

    //TODO: destroy msg_2
    return event;
}

static otr4_smp_event_t process_smp_msg3(tlv_t **smp_reply, const tlv_t* tlv, smp_context_t smp)
{
    smp_msg_3_t msg_3;
    otr4_smp_event_t event = receive_smp_msg_3(msg_3, tlv, smp);

    if (!event)
        event = reply_with_smp_msg_4(smp_reply, msg_3, smp);

    //TODO: destroy msg_3
    return event;
}

static otr4_smp_event_t process_smp_msg4(const tlv_t* tlv, smp_context_t smp)
{
    smp_msg_4_t msg_4[1];

    otr4_smp_event_t event = receive_smp_msg_4(msg_4, tlv, smp);

    //TODO: destroy msg4
    return event;
}
