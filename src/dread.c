#include "dread.h"
#include "random.h"

#include <sodium.h>

//ElGamal group
//(G, q, g) are from ed448

static void ed448_random_point(decaf_448_point_t p)
{
	unsigned char rand[DECAF_448_SER_BYTES];

	do {
		random_bytes(rand, DECAF_448_SER_BYTES);
	} while (DECAF_FALSE == decaf_448_point_decode(p, rand, DECAF_FALSE));

	memset(rand, 0, DECAF_448_SER_BYTES);
}

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

// pub = g^priv
static int
elgamal_448_generate_keypair(decaf_448_scalar_t priv, decaf_448_point_t pub)
{
	ed448_random_scalar(priv);
	decaf_448_point_scalarmul(pub, decaf_448_point_base, priv);

	return 0;
}

static void
elgamal_448_encrypt(elgamal_448_cipher_t c, decaf_448_scalar_t y,
		    const decaf_448_point_t h, const decaf_448_point_t m)
{
	decaf_448_point_t s;

	elgamal_448_generate_keypair(y, c->c1);	// c1 = g^y
	decaf_448_point_scalarmul(s, h, y);	// s = h^y = g^(xy)
	decaf_448_point_add(c->c2, s, m);	// c2 = s * m
}

static void
elgamal_448_decrypt(decaf_448_point_t m, const elgamal_448_cipher_t c,
		    const decaf_448_scalar_t x)
{
	decaf_448_point_scalarmul(m, c->c1, x);	// s = c1 ^ x
	decaf_448_point_sub(m, c->c2, m);	// m = c2 - s
}

int dread_keypair_generate(dread_keypair_t dst)
{
	return elgamal_448_generate_keypair(dst->priv, dst->pub);
}

const unsigned char base_point_bytes[DECAF_448_SER_BYTES] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const unsigned char prime_order_bytes[DECAF_448_SCALAR_BYTES] = {
	0x33, 0xec, 0x9e, 0x52, 0xb5, 0xf5, 0x1c, 0x72,
	0xab, 0xc2, 0xe9, 0xc8, 0x35, 0xf6, 0x4c, 0x7a,
	0xbf, 0x25, 0xa7, 0x44, 0xd9, 0x92, 0xc4, 0xee,
	0x58, 0x70, 0xd7, 0x0c, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int
dread_encrypt(dread_cipher_t dst, const dread_pubkey_t pub1,
	      const dread_pubkey_t pub2, const unsigned char *msg,
	      size_t msglen, const unsigned char *data, size_t datalen)
{
	gcry_md_hd_t hd;
	unsigned char hash[64];
	unsigned char point_buff[DECAF_448_SER_BYTES];
	unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
	unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
	decaf_448_point_t K, T11, T12, T2, T1;
	decaf_448_scalar_t t1, t2, k1, k2;

	unsigned long long ciphertext_len = 0;
	unsigned char *ciphertext =
	    malloc(msglen + crypto_aead_chacha20poly1305_IETF_ABYTES);
	if (!ciphertext)
		return -1;

	elgamal_448_generate_keypair(t1, T11);	// T11 = g ^ t1
	elgamal_448_generate_keypair(t2, T12);	// T12 = g ^ t2

	decaf_448_point_scalarmul(T1, pub1, t1);
	decaf_448_point_scalarmul(T2, pub2, t2);
	decaf_448_point_sub(T2, T1, T2);

	ed448_random_point(K);
	elgamal_448_encrypt(dst->c1, k1, pub1, K);	// c11, c21
	elgamal_448_encrypt(dst->c2, k2, pub2, K);	// c12, c22

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, base_point_bytes, DECAF_448_SER_BYTES);
	gcry_md_write(hd, prime_order_bytes, DECAF_448_SCALAR_BYTES);

	decaf_448_point_encode(point_buff, pub1);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, pub2);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, dst->c1->c1);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, dst->c1->c2);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, dst->c2->c1);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, dst->c2->c2);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, T11);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, T12);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, T2);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	gcry_md_write(hd, data, datalen);

	memcpy(hash, gcry_md_read(hd, 0), 64);
	gcry_md_close(hd);

	//TODO: Do we need anything else to hash from bytes to a scalar?
	int ok = decaf_448_scalar_decode(dst->L, hash);
	(void)ok;

	decaf_448_scalar_mul(dst->n1, dst->L, k1);
	decaf_448_scalar_sub(dst->n1, t1, dst->n1);

	decaf_448_scalar_mul(dst->n2, dst->L, k2);
	decaf_448_scalar_sub(dst->n2, t2, dst->n2);

	decaf_448_point_encode(point_buff, K);

	gcry_md_open(&hd, GCRY_MD_SHA3_256, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);
	memcpy(key, gcry_md_read(hd, 0), crypto_aead_chacha20poly1305_IETF_KEYBYTES);	// 32 bytes
	gcry_md_close(hd);

	memcpy(nonce, hash, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);	// first 24 bytes

	crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
						  msg, msglen, data, datalen,
						  NULL, nonce, key);

	dst->cipher = ciphertext;
	dst->cipherlen = ciphertext_len;

	return 0;
}

int
dread_decrypt(unsigned char *dst, unsigned long long *dstlen,
	      const dread_keypair_t pair1, const dread_pubkey_t pub2,
	      const dread_cipher_t cipher, const unsigned char *data,
	      size_t datalen)
{
	gcry_md_hd_t hd;
	unsigned char hash[64];
	unsigned char point_buff[DECAF_448_SER_BYTES];
	unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
	unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
	decaf_448_point_t tmp, T11, T12, T2;

	decaf_448_point_scalarmul(tmp, cipher->c1->c1, cipher->L);
	decaf_448_point_scalarmul(T11, decaf_448_point_base, cipher->n1);
	decaf_448_point_add(T11, T11, tmp);

	decaf_448_point_scalarmul(tmp, cipher->c2->c1, cipher->L);
	decaf_448_point_scalarmul(T12, decaf_448_point_base, cipher->n2);
	decaf_448_point_add(T12, T12, tmp);

	decaf_448_point_sub(tmp, cipher->c1->c2, cipher->c2->c2);
	decaf_448_point_scalarmul(T2, tmp, cipher->L);

	decaf_448_point_t p1_n, p2_n;
	decaf_448_point_scalarmul(p1_n, pair1->pub, cipher->n1);
	decaf_448_point_scalarmul(p2_n, pub2, cipher->n2);
	decaf_448_point_sub(tmp, p1_n, p2_n);
	decaf_448_point_add(T2, T2, tmp);

	gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, base_point_bytes, DECAF_448_SER_BYTES);
	gcry_md_write(hd, prime_order_bytes, DECAF_448_SCALAR_BYTES);

	decaf_448_point_encode(point_buff, pair1->pub);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, pub2);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, cipher->c1->c1);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, cipher->c1->c2);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, cipher->c2->c1);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, cipher->c2->c2);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, T11);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, T12);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	decaf_448_point_encode(point_buff, T2);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);

	gcry_md_write(hd, data, datalen);

	memcpy(hash, gcry_md_read(hd, 0), 64);
	gcry_md_close(hd);

	//TODO: Do we need anything else to hash from bytes to a scalar?
	decaf_448_scalar_t L;
	int ok = decaf_448_scalar_decode(L, hash);
	(void)ok;

	if (DECAF_FALSE == decaf_448_scalar_eq(L, cipher->L))
		return 1;

	//TODO: How do we know who we are?
	//It depends if the other side has used us as pub1 or pub2.
	//We could try to decript using both and see which one works.
	decaf_448_point_t K;
	elgamal_448_decrypt(K, cipher->c1, pair1->priv);
	decaf_448_point_encode(point_buff, K);

	gcry_md_open(&hd, GCRY_MD_SHA3_256, GCRY_MD_FLAG_SECURE);
	gcry_md_write(hd, point_buff, DECAF_448_SER_BYTES);
	memcpy(key, gcry_md_read(hd, 0), crypto_aead_chacha20poly1305_IETF_KEYBYTES);	// 32 bytes
	gcry_md_close(hd);

	memcpy(nonce, hash, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);	// first 24 bytes

	return crypto_aead_chacha20poly1305_ietf_decrypt(dst, dstlen, NULL,
							 cipher->cipher,
							 cipher->cipherlen,
							 data, datalen, nonce,
							 key);
}
