#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "user_profile.h"
#include "serialize.h"
#include "deserialize.h"
#include "mpi.h"
#include "str.h"
#include "random.h"

user_profile_t *user_profile_new(const string_t versions)
{
	if (!versions)
		return NULL;

	user_profile_t *profile = malloc(sizeof(user_profile_t));
	if (!profile)
		return NULL;

	//TODO: Should we initialize to zero?
	//ec_destroy_point(profile->pub_key);
	profile->expires = 0;
	profile->versions = otrv4_strdup(versions);
	memset(profile->signature, 0, sizeof(eddsa_signature_t));
	otr_mpi_init(profile->transitional_signature);

	return profile;
}

void user_profile_copy(user_profile_t * dst, const user_profile_t * src)
{
	//TODO should we set dst to a valid (but empty) profile?
	if (!src)
		return;

	ec_point_copy(dst->pub_key, src->pub_key);
	dst->versions = otrv4_strdup(src->versions);
	dst->expires = src->expires;

	memcpy(dst->signature, src->signature, sizeof(eddsa_signature_t));
	otr_mpi_copy(dst->transitional_signature, src->transitional_signature);
}

void user_profile_destroy(user_profile_t * profile)
{
	if (!profile)
		return;

	//free the pubkey
	free(profile->versions);
	profile->versions = NULL;

	otr_mpi_free(profile->transitional_signature);
}

void user_profile_free(user_profile_t * profile)
{
	user_profile_destroy(profile);
	free(profile);
}

static int
user_profile_body_serialize(uint8_t * dst, const user_profile_t * profile)
{
	uint8_t *target = dst;

	target += serialize_otrv4_public_key(target, profile->pub_key);
	target += serialize_data(target, (uint8_t *) profile->versions,
				 strlen(profile->versions) + 1);
	target += serialize_uint64(target, profile->expires);

	return target - dst;
}

bool
user_profile_body_aprint(uint8_t ** dst, size_t * nbytes,
			 const user_profile_t * profile)
{
	size_t s = ED448_PUBKEY_BYTES + strlen(profile->versions) + 1 + 4 + 8;

	uint8_t *buff = malloc(s);
	if (!buff)
		return false;

	user_profile_body_serialize(buff, profile);

	*dst = buff;
	if (nbytes)
		*nbytes = s;

	return true;
}

bool
user_profile_aprint(uint8_t ** dst, size_t * nbytes,
		    const user_profile_t * profile)
{
	//TODO: should it check if the profile is signed?
	uint8_t *buff = NULL;
	size_t body_len = 0;
	uint8_t *body = NULL;
	if (!user_profile_body_aprint(&body, &body_len, profile))
		return false;

	size_t s = body_len + 4 + sizeof(eddsa_signature_t) +
	    profile->transitional_signature->len;
	buff = malloc(s);
	if (!buff) {
		free(body);
		return false;
	}

	uint8_t *cursor = buff;
	cursor += serialize_bytes_array(cursor, body, body_len);
	cursor +=
	    serialize_bytes_array(cursor, profile->signature,
				  sizeof(eddsa_signature_t));
	cursor += serialize_mpi(cursor, profile->transitional_signature);

	*dst = buff;
	if (nbytes)
		*nbytes = s;

	free(body);
	return true;
}

bool
user_profile_deserialize(user_profile_t * target, const uint8_t * buffer,
			 size_t buflen, size_t * nread)
{
	size_t read = 0;
	int walked = 0;

	if (!target)
		return false;

	bool ok = false;
	do {
		if (!deserialize_otrv4_public_key
		    (target->pub_key, buffer, buflen, &read))
			continue;

		walked += read;

		if (!deserialize_data
		    ((uint8_t **) & target->versions, buffer + walked,
		     buflen - walked, &read))
			continue;

		walked += read;

		if (!deserialize_uint64
		    (&target->expires, buffer + walked, buflen - walked, &read))
			continue;

		walked += read;

		//TODO: check the len
		if (buflen - walked < sizeof(eddsa_signature_t))
			continue;

		memcpy(target->signature, buffer + walked,
		       sizeof(eddsa_signature_t));

		walked += sizeof(eddsa_signature_t);

		if (!otr_mpi_deserialize
		    (target->transitional_signature, buffer + walked,
		     buflen - walked, &read))
			continue;

		walked += read;

		ok = true;
	} while (0);

	if (nread)
		*nread = walked;

	return ok;
}

bool user_profile_sign(user_profile_t * profile,
		       const otrv4_keypair_t * keypair)
{
	uint8_t *body = NULL;
	size_t bodylen = 0;

	ec_point_copy(profile->pub_key, keypair->pub);
	if (!user_profile_body_aprint(&body, &bodylen, profile))
		return false;

	uint8_t pubkey[ED448_POINT_BYTES];
	ec_point_serialize(pubkey, ED448_POINT_BYTES, keypair->pub);
	//maybe ec_derive_public_key again?

	ec_sign(profile->signature, (uint8_t *) keypair->sym, pubkey, body,
		bodylen);

	free(body);
	body = NULL;
	return true;
}

//TODO: I dont think this needs the data structure. Could verify from the
//deserialized bytes.
bool user_profile_verify_signature(const user_profile_t * profile)
{
	//TODO
	return true;
}

user_profile_t *user_profile_build(const string_t versions,
				   otrv4_keypair_t * keypair)
{
	user_profile_t *profile = user_profile_new(versions);
	if (!profile)
		return NULL;

#define PROFILE_EXPIRATION_SECONDS 2 * 7 * 24 * 60 * 60;	//2 weeks
	time_t expires = time(NULL);
	profile->expires = expires + PROFILE_EXPIRATION_SECONDS;
	user_profile_sign(profile, keypair);

	return profile;
}
