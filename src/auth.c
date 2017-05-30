#include "auth.h"
#include "constants.h"
#include "random.h"

void generate_keypair(snizkpk_pubkey_t pub, snizkpk_privkey_t priv)
{
	ed448_random_scalar(priv);
	decaf_448_point_scalarmul(pub, decaf_448_point_base, priv);
}

void snizkpk_keypair_generate(snizkpk_keypair_t * pair)
{
	generate_keypair(pair->pub, pair->priv);
}

// XXX: in big endian
const unsigned char base_point_bytes_dup[ED448_POINT_BYTES] = {
	0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
	0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
	0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
	0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
	0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
	0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
	0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
	0x00,
};

// XXX: in big endian
const unsigned char prime_order_bytes_dup[ED448_SCALAR_BYTES] = {
	0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x7c, 0xca, 0x23, 0xe9,
	0xc4, 0x4e, 0xdb, 0x49, 0xae, 0xd6, 0x36, 0x90,
	0x21, 0x6c, 0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55,
	0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3,
};

otr4_err_t
snizkpk_authenticate(snizkpk_proof_t * dst, const snizkpk_keypair_t * pair1,
		     const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3,
		     const unsigned char *msg, size_t msglen)
{
	gcry_md_hd_t hd;
	unsigned char hash[HASH_BYTES];
	unsigned char point_buff[ED448_POINT_BYTES];

	snizkpk_privkey_t t1;
	snizkpk_pubkey_t T1, T2, T3, A2c2, A3c3;

	generate_keypair(T1, t1);

	generate_keypair(T2, dst->r2);
	ed448_random_scalar(dst->c2);
	decaf_448_point_scalarmul(A2c2, A2, dst->c2);
	decaf_448_point_add(T2, T2, A2c2);

	generate_keypair(T3, dst->r3);
	ed448_random_scalar(dst->c3);
	decaf_448_point_scalarmul(A3c3, A3, dst->c3);
	decaf_448_point_add(T3, T3, A3c3);

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, base_point_bytes_dup, ED448_POINT_BYTES);
	gcry_md_write(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff,
							      pair1->pub);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A2);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A3);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, T1);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, T2);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, T3);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	gcry_md_write(hd, msg, msglen);

	memcpy(hash, gcry_md_read(hd, 0), HASH_BYTES);
	gcry_md_close(hd);

	//TODO: Do we need anything else to hash from bytes to a scalar?
	snizkpk_privkey_t c, c1a1;
    //TODO: add a code to handle when this fails
	int ok = decaf_448_scalar_decode(c, hash);
	(void)ok;

	decaf_448_scalar_sub(dst->c1, c, dst->c2);
	decaf_448_scalar_sub(dst->c1, dst->c1, dst->c3);

	decaf_448_scalar_mul(c1a1, dst->c1, pair1->priv);
	decaf_448_scalar_sub(dst->r1, t1, c1a1);

	return OTR4_SUCCESS;
}

otr4_err_t
snizkpk_verify(const snizkpk_proof_t * src, const snizkpk_pubkey_t A1,
	       const snizkpk_pubkey_t A2, const snizkpk_pubkey_t A3,
	       const unsigned char *msg, size_t msglen)
{
	gcry_md_hd_t hd;
	unsigned char hash[HASH_BYTES];
	unsigned char point_buff[ED448_POINT_BYTES];

	snizkpk_pubkey_t gr1, gr2, gr3, A1c1, A2c2, A3c3;

	decaf_448_point_scalarmul(gr1, decaf_448_point_base, src->r1);
	decaf_448_point_scalarmul(gr2, decaf_448_point_base, src->r2);
	decaf_448_point_scalarmul(gr3, decaf_448_point_base, src->r3);

	decaf_448_point_scalarmul(A1c1, A1, src->c1);
	decaf_448_point_scalarmul(A2c2, A2, src->c2);
	decaf_448_point_scalarmul(A3c3, A3, src->c3);

	decaf_448_point_add(A1c1, A1c1, gr1);
	decaf_448_point_add(A2c2, A2c2, gr2);
	decaf_448_point_add(A3c3, A3c3, gr3);

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, base_point_bytes_dup, ED448_POINT_BYTES);
	gcry_md_write(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A1);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A2);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A3);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A1c1);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A2c2);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	decaf_448_point_mul_by_cofactor_and_encode_like_eddsa(point_buff, A3c3);
	gcry_md_write(hd, point_buff, ED448_POINT_BYTES);

	gcry_md_write(hd, msg, msglen);

	memcpy(hash, gcry_md_read(hd, 0), HASH_BYTES);
	gcry_md_close(hd);

	snizkpk_privkey_t c, c1c2c3;
	//TODO: add code to handle when this fails
	int ok = decaf_448_scalar_decode(c, hash);
	(void)ok;

	decaf_448_scalar_add(c1c2c3, src->c1, src->c2);
	decaf_448_scalar_add(c1c2c3, c1c2c3, src->c3);

    if (DECAF_TRUE == decaf_448_scalar_eq(c, c1c2c3)) {
        return OTR4_SUCCESS;
    }
    return OTR4_ERROR;
}

void snizkpk_proof_destroy(snizkpk_proof_t * src)
{
	ec_scalar_destroy(src->c1);
	ec_scalar_destroy(src->r1);
	ec_scalar_destroy(src->c2);
	ec_scalar_destroy(src->r2);
	ec_scalar_destroy(src->c3);
	ec_scalar_destroy(src->r3);
}
