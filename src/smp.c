#include "auth.h"
#include "smp.h"
#include "str.h"
#include "tlv.h"
#include "fingerprint.h"
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

tlv_t * generate_smp_msg_1(smp_context_t smp, string_t answer)
{
	uint8_t *data = NULL;
	size_t len = 0;
	decaf_448_scalar_t a2, a3;
	decaf_448_point_t G2a, G3a;
	snizkpk_keypair_t pair_r2[1], pair_r3[1];
	unsigned char hash[64];
	gcry_md_hd_t hd;
	decaf_448_scalar_t a3c3, a2c2;
	decaf_448_scalar_t c2, c3, d2, d3;
	uint8_t version[2] = { 0x01, 0x02 };

	generate_keypair(G2a, a2);
	generate_keypair(G3a, a3);

	snizkpk_keypair_generate(pair_r2);
	snizkpk_keypair_generate(pair_r3);

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, &version[0], 1);
	gcry_md_write(hd, pair_r2->pub, DECAF_448_SER_BYTES);
	memcpy(hash, gcry_md_read(hd, 0), 64);
	gcry_md_close(hd);

	int ok = decaf_448_scalar_decode(c2, hash);
	(void) ok;
	decaf_448_scalar_mul(a2c2, a2, c2);
	decaf_448_scalar_sub(d2, pair_r2->priv, c2);

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, &version[1], 1);
	gcry_md_write(hd, pair_r3->pub, DECAF_448_SER_BYTES);
	memcpy(hash, gcry_md_read(hd, 0), 64);
	gcry_md_close(hd);

	ok = decaf_448_scalar_decode(c3, hash);
	(void) ok;
	decaf_448_scalar_mul(a3c3, a3, c3);
	decaf_448_scalar_sub(d3, pair_r3->priv, c3);

	return otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, len, data);
}

tlv_t * generate_smp_msg_2(void)
{
	uint8_t *data = NULL;
	size_t len = 0;

	return otrv4_tlv_new(OTRV4_TLV_SMP_MSG_2, len, data);
}
