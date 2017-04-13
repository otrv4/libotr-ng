#ifndef DREAD_448_H
#define DREAD_448_H

#include <stddef.h>
#include <libdecaf/decaf.h>

typedef decaf_448_scalar_t dread_privkey_t;
typedef decaf_448_point_t dread_pubkey_t;

typedef struct {
	dread_pubkey_t pub;
	dread_privkey_t priv;
} dread_keypair_t[1];

typedef struct {
	decaf_448_point_t c1;
	decaf_448_point_t c2;
} elgamal_448_cipher_t[1];

typedef struct {
	elgamal_448_cipher_t c1;	// c11, c21
	elgamal_448_cipher_t c2;	// c12, c22
	decaf_448_scalar_t L;
	decaf_448_scalar_t n1, n2;
	unsigned char *cipher;
	unsigned long long cipherlen;
} dread_cipher_t[1];

int dread_keypair_generate(dread_keypair_t dst);

int
dread_encrypt(dread_cipher_t dst, const dread_pubkey_t pub1,
	      const dread_pubkey_t pub2, const unsigned char *msg,
	      size_t msglen, const unsigned char *data, size_t datalen);

int
dread_decrypt(unsigned char *dst, unsigned long long *dstlen,
	      const dread_keypair_t pair1, const dread_pubkey_t pub2,
	      const dread_cipher_t cipher, const unsigned char *data,
	      size_t datalen);

#endif
