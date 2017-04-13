#ifndef DAKE_H
#define DAKE_H

#include <stdbool.h>
#include <sodium.h>

#include "dh.h"
#include "ed448.h"
#include "user_profile.h"
#include "auth.h"

#define DAKE_HEADER_BYTES (2+1+4+4)

//size of PRE_KEY_MESSAGE without user_profile
#define PRE_KEY_MIN_BYTES DAKE_HEADER_BYTES \
                          + DECAF_448_SER_BYTES \
                          + 4+DH3072_MOD_LEN_BYTES

#define AUTH_R_MIN_BYTES DAKE_HEADER_BYTES \
        + DECAF_448_SER_BYTES \
        + DH3072_MOD_LEN_BYTES+4 \
        + SNIZKPK_BYTES

typedef struct {
	uint32_t sender_instance_tag;
	uint32_t receiver_instance_tag;
	user_profile_t profile[1];
	ec_public_key_t Y;
	dh_public_key_t B;
} dake_identity_message_t;

typedef struct {
	uint32_t sender_instance_tag;
	uint32_t receiver_instance_tag;

	user_profile_t profile[1];
	ec_public_key_t X;
	dh_public_key_t A;
	snizkpk_proof_t sigma;
} dake_auth_r_t;

typedef struct {
	uint32_t sender_instance_tag;
	uint32_t receiver_instance_tag;

	snizkpk_proof_t sigma;
} dake_auth_i_t;

dake_identity_message_t *dake_identity_message_new(const user_profile_t *
						   profile);

void dake_identity_message_free(dake_identity_message_t * identity_message);

void dake_identity_message_destroy(dake_identity_message_t * identity_message);

bool
dake_identity_message_deserialize(dake_identity_message_t * dst,
				  const uint8_t * src, size_t src_len);

bool
dake_identity_message_aprint(uint8_t ** dst, size_t * nbytes,
			     const dake_identity_message_t * identity_message);

bool
dake_identity_message_validate(const dake_identity_message_t *
			       identity_message);

bool
dake_auth_r_aprint(uint8_t ** dst, size_t * nbytes,
		   const dake_auth_r_t * dre_auth);
bool
dake_auth_r_deserialize(dake_auth_r_t * dst, uint8_t * buffer, size_t buflen);

bool
dake_auth_i_aprint(uint8_t ** dst, size_t * nbytes,
		   const dake_auth_i_t * dre_auth);
bool
dake_auth_i_deserialize(dake_auth_i_t * dst, uint8_t * buffer, size_t buflen);

bool validate_received_values(const uint8_t their_ecdh[DECAF_448_SER_BYTES],
			      const dh_mpi_t their_dh,
			      const user_profile_t * profile);

#endif
