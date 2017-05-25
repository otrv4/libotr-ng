#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "dake.h"
#include "serialize.h"
#include "deserialize.h"
#include "user_profile.h"
#include "str.h"
#include "random.h"
#include "sha3.h"
#include "constants.h"
#include "error.h"

dake_identity_message_t *dake_identity_message_new(const user_profile_t *
						   profile)
{
	if (profile == NULL) {
		return NULL;
	}

	dake_identity_message_t *identity_message =
	    malloc(sizeof(dake_identity_message_t));
	if (identity_message == NULL) {
		return NULL;
	}

	identity_message->sender_instance_tag = 0;
	identity_message->receiver_instance_tag = 0;
	identity_message->profile->versions = NULL;
	identity_message->B = NULL;
	user_profile_copy(identity_message->profile, profile);

	return identity_message;
}

void dake_identity_message_free(dake_identity_message_t * identity_message)
{
	if (!identity_message)
		return;

	dake_identity_message_destroy(identity_message);
	free(identity_message);
}

void dake_identity_message_destroy(dake_identity_message_t * identity_message)
{
	user_profile_destroy(identity_message->profile);
	dh_mpi_release(identity_message->B);
	identity_message->B = NULL;
}

bool
dake_identity_message_aprint(uint8_t ** dst, size_t * nbytes,
			     const dake_identity_message_t * identity_message)
{
	size_t profile_len = 0;
	uint8_t *profile = NULL;
	if (!user_profile_aprint
	    (&profile, &profile_len, identity_message->profile)) {
		return false;
	}

	size_t s = PRE_KEY_MIN_BYTES + profile_len;
	*dst = malloc(s);
	if (*dst == NULL) {
		free(profile);
		return false;
	}

	if (nbytes != NULL) {
		*nbytes = s;
	}

	uint8_t *target = *dst;
	target += serialize_uint16(target, OTR_VERSION);
	target += serialize_uint8(target, OTR_IDENTITY_MSG_TYPE);
	target +=
	    serialize_uint32(target, identity_message->sender_instance_tag);
	target +=
	    serialize_uint32(target, identity_message->receiver_instance_tag);
	target += serialize_bytes_array(target, profile, profile_len);
	bool ok = serialize_ec_point(target, identity_message->Y);
	if (!ok) {
		return false;
	}
	target += ED448_POINT_BYTES;
	size_t len = 0;
	otr4_err_t err =
	    serialize_dh_public_key(target, &len, identity_message->B);
	if (err) {
		return false;
	}
	target += len;

	free(profile);
	return true;
}

bool
dake_identity_message_deserialize(dake_identity_message_t * dst,
				  const uint8_t * src, size_t src_len)
{
	const uint8_t *cursor = src;
	int64_t len = src_len;
	size_t read = 0;

	uint16_t protocol_version = 0;
	if (deserialize_uint16(&protocol_version, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (protocol_version != OTR_VERSION) {
		return false;
	}

	uint8_t message_type = 0;
	if (deserialize_uint8(&message_type, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (message_type != OTR_IDENTITY_MSG_TYPE) {
		return false;
	}

	if (deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (deserialize_uint32
	    (&dst->receiver_instance_tag, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (!user_profile_deserialize(dst->profile, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (deserialize_ec_point(dst->Y, cursor)) {
		return false;
	}

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	otr_mpi_t b_mpi;	// no need to free, because nothing is copied now
	if (!otr_mpi_deserialize_no_copy(b_mpi, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (!dh_mpi_deserialize(&dst->B, b_mpi->data, b_mpi->len, &read)) {
		return false;
	}

	return true;
}

bool not_expired(time_t expires)
{
	if (difftime(expires, time(NULL)) > 0) {
		return true;
	}

	return false;
}

// Check if the profile contains any version other than supported by this
// messaging protocol (that is, wire protocol v4 and v3).
static bool no_rollback_detected(const char *versions)
{
	while (*versions) {
		if (*versions != '3' && *versions != '4')
			return false;

		versions++;
	}

	return true;
}

bool
dake_identity_message_validate(const dake_identity_message_t * identity_message)
{
	bool valid = user_profile_verify_signature(identity_message->profile);
	valid &= not_expired(identity_message->profile->expires);
	valid &= ec_point_valid(identity_message->Y);
	valid &= dh_mpi_valid(identity_message->B);
	valid &= no_rollback_detected(identity_message->profile->versions);

	return valid;
}

bool validate_received_values(const ec_point_t their_ecdh,
			      const dh_mpi_t their_dh,
			      const user_profile_t * profile)
{
	bool valid = true;

	//5) Verify that the point X received is on curve 448
	valid &= ec_point_valid(their_ecdh);

	//6) Verify that the DH public key A is from the correct group.
	valid &= dh_mpi_valid(their_dh);

	//7) Verify their profile is valid (and not expired).
	valid &= user_profile_verify_signature(profile);
	valid &= not_expired(profile->expires);
	valid &= no_rollback_detected(profile->versions);

	return valid;
}

bool
dake_auth_r_aprint(uint8_t ** dst, size_t * nbytes,
		   const dake_auth_r_t * dre_auth)
{
	size_t our_profile_len = 0;
	uint8_t *our_profile = NULL;

	if (!user_profile_aprint
	    (&our_profile, &our_profile_len, dre_auth->profile)) {
		return false;
	}

	size_t s = AUTH_R_MIN_BYTES + our_profile_len;
	*dst = malloc(s);
	memset(*dst, 0, s);

	if (!*dst) {
		free(our_profile);
		return false;
	}

	if (nbytes) {
		*nbytes = s;
	}

	uint8_t *cursor = *dst;
	cursor += serialize_uint16(cursor, OTR_VERSION);
	cursor += serialize_uint8(cursor, OTR_AUTH_R_MSG_TYPE);
	cursor += serialize_uint32(cursor, dre_auth->sender_instance_tag);
	cursor += serialize_uint32(cursor, dre_auth->receiver_instance_tag);
	cursor += serialize_bytes_array(cursor, our_profile, our_profile_len);
	bool ok = serialize_ec_point(cursor, dre_auth->X);
	if (!ok) {
		return false;
	}
	cursor += ED448_POINT_BYTES;
	size_t len = 0;
	otr4_err_t err = serialize_dh_public_key(cursor, &len, dre_auth->A);
	if (err) {
		return false;
	}
	cursor += len;
	cursor += serialize_snizkpk_proof(cursor, dre_auth->sigma);

	free(our_profile);
	return true;
}

void dake_auth_r_destroy(dake_auth_r_t * auth_r)
{
	dh_mpi_release(auth_r->A);
	auth_r->A = NULL;
	user_profile_destroy(auth_r->profile);
	snizkpk_proof_destroy(auth_r->sigma);
}

void dake_auth_r_free(dake_auth_r_t * auth_r)
{
	if (!auth_r)
		return;

	dake_auth_r_destroy(auth_r);
	free(auth_r);
}

bool
dake_auth_r_deserialize(dake_auth_r_t * dst, const uint8_t * buffer,
			size_t buflen)
{
	const uint8_t *cursor = buffer;
	int64_t len = buflen;
	size_t read = 0;

	uint16_t protocol_version = 0;
	if (deserialize_uint16(&protocol_version, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (protocol_version != OTR_VERSION) {
		return false;
	}

	uint8_t message_type = 0;
	if (deserialize_uint8(&message_type, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (message_type != OTR_AUTH_R_MSG_TYPE) {
		return false;
	}

	if (deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (deserialize_uint32
	    (&dst->receiver_instance_tag, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (!user_profile_deserialize(dst->profile, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (deserialize_ec_point(dst->X, cursor)) {
		return false;
	}

	cursor += ED448_POINT_BYTES;
	len -= ED448_POINT_BYTES;

	otr_mpi_t tmp_mpi;	// no need to free, because nothing is copied now
	if (!otr_mpi_deserialize_no_copy(tmp_mpi, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (!dh_mpi_deserialize(&dst->A, tmp_mpi->data, tmp_mpi->len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

    if (deserialize_snizkpk_proof(dst->sigma, cursor, len, &read)) {
        return false;
    }
    return true;
}

void dake_auth_i_destroy(dake_auth_i_t * auth_i)
{
	snizkpk_proof_destroy(auth_i->sigma);
}

void dake_auth_i_free(dake_auth_i_t * auth_i)
{
	if (!auth_i)
		return;

	dake_auth_i_destroy(auth_i);
	free(auth_i);
}

bool
dake_auth_i_aprint(uint8_t ** dst, size_t * nbytes,
		   const dake_auth_i_t * dre_auth)
{
	size_t s = DAKE_HEADER_BYTES + SNIZKPK_BYTES;
	*dst = malloc(s);
	memset(*dst, 0, s);

	if (!*dst) {
		return false;
	}

	if (nbytes) {
		*nbytes = s;
	}

	uint8_t *cursor = *dst;
	cursor += serialize_uint16(cursor, OTR_VERSION);
	cursor += serialize_uint8(cursor, OTR_AUTH_I_MSG_TYPE);
	cursor += serialize_uint32(cursor, dre_auth->sender_instance_tag);
	cursor += serialize_uint32(cursor, dre_auth->receiver_instance_tag);
	cursor += serialize_snizkpk_proof(cursor, dre_auth->sigma);

	return true;
}

bool
dake_auth_i_deserialize(dake_auth_i_t * dst, const uint8_t * buffer,
			size_t buflen)
{
	const uint8_t *cursor = buffer;
	int64_t len = buflen;
	size_t read = 0;

	uint16_t protocol_version = 0;
	if (deserialize_uint16(&protocol_version, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (protocol_version != OTR_VERSION) {
		return false;
	}

	uint8_t message_type = 0;
	if (deserialize_uint8(&message_type, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (message_type != OTR_AUTH_I_MSG_TYPE) {
		return false;
	}

	if (deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

	if (deserialize_uint32
	    (&dst->receiver_instance_tag, cursor, len, &read)) {
		return false;
	}

	cursor += read;
	len -= read;

    if (deserialize_snizkpk_proof(dst->sigma, cursor, len, &read)) {
        return false;
    }
    return true;
}
