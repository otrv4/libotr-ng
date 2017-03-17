#ifndef CRAMER_SHOUP_H
#define CRAMER_SHOUP_H

#include <stdbool.h>
#include <cramershoup.h>
#include <string.h>

#include "ed448.h"

#define CRAMER_SHOUP_PUBKEY_TYPE 0x0010

typedef cramershoup_448_public_key_t cs_public_key_t;
typedef cramershoup_448_private_key_t cs_private_key_t;
typedef cramershoup_448_symmetric_key_t dr_cs_symmetric_key_t;
typedef cramershoup_448_dr_encrypted_key_t dr_cs_encrypted_symmetric_key_t;
typedef cramershoup_448_rs_auth_t rs_auth_t;

typedef struct {
	cs_public_key_t pub[1];
	cs_private_key_t priv[1];
} cs_keypair_s, cs_keypair_t[1];

static inline void cs_keypair_generate(cs_keypair_t key_pair)
{
	cramershoup_448_derive_keys(key_pair->priv, key_pair->pub);
}

static inline void cs_keypair_destroy(cs_keypair_t key_pair)
{
	memset(key_pair->pub, 0, sizeof(cs_public_key_t));
	memset(key_pair->priv, 0, sizeof(cs_private_key_t));
}

void cs_public_key_copy(cs_public_key_t * dst, const cs_public_key_t * src);

static inline void dr_cs_generate_symmetric_key(dr_cs_symmetric_key_t k)
{
	cramershoup_448_random_symmetric_key(k);
}

static inline bool
dr_cs_encrypt(dr_cs_encrypted_symmetric_key_t gamma,
	      const dr_cs_symmetric_key_t k,
	      const cs_public_key_t * our_pub,
	      const cs_public_key_t * their_pub)
{
	if (dr_cramershoup_448_enc(gamma, k, our_pub, their_pub) == 0) {
		return true;
	}

	return false;
}

static inline bool
dr_cs_decrypt(dr_cs_symmetric_key_t k,
	      const dr_cs_encrypted_symmetric_key_t gamma,
	      const cs_keypair_t our_keypair, const cs_public_key_t * their_pub)
{

	//FIXME: the public keys must be in this specific order because this is the
	//order used when encrypting
	if (0 !=
	    dr_cramershoup_448_dec(k, gamma, their_pub, our_keypair->pub,
				   our_keypair->priv, 2)) {
		return false;
	}

	return true;
}

static inline void
ring_signature_auth(rs_auth_t dst,
		    const uint8_t * msg,
		    const cs_keypair_t keypair,
		    const cs_public_key_t * their_pub,
		    const ec_point_t their_ephemeral)
{
	rs_448_auth(dst, (char *)msg,
		    keypair->priv->z, keypair->pub->h,
		    their_pub->h, their_ephemeral);
}

static inline bool
ring_signature_auth_valid(const rs_auth_t auth,
			  const uint8_t * msg,
			  const cs_public_key_t * our_pub,
			  const cs_public_key_t * their_pub,
			  const ec_point_t their_ephemeral)
{
	if (0 !=
	    rs_448_verify(auth, (char *)msg, our_pub->h, their_pub->h,
			  their_ephemeral)) {
		return false;
	}

	return true;
}

int
cs_serialize_private_key(char **dst, size_t * len,
			 const cs_private_key_t * priv);

int cs_deserialize_private_key(char *buff, size_t len, cs_private_key_t * priv);

#endif
