#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gcrypt.h"

#include "b64.h"
#include "constants.h"
#include "dake.h"
#include "data_message.h"
#include "deserialize.h"
#include "otrv3.h"
#include "otrv4.h"
#include "random.h"
#include "serialize.h"
#include "smp.c"
#include "sha3.h"
#include "str.h"
#include "tlv.h"

#include "debug.h"

#define OUR_ECDH(s) s->keys->our_ecdh->pub
#define OUR_DH(s) s->keys->our_dh->pub
#define THEIR_ECDH(s) s->keys->their_ecdh
#define THEIR_DH(s) s->keys->their_dh

#define QUERY_MESSAGE_TAG_BYTES 5
#define WHITESPACE_TAG_BASE_BYTES 16
#define WHITESPACE_TAG_VERSION_BYTES 8

static const char tag_base[] = {
	'\x20', '\x09', '\x20', '\x20', '\x09', '\x09', '\x09', '\x09',
	'\x20', '\x09', '\x20', '\x09', '\x20', '\x09', '\x20', '\x20',
	'\0'
};

static const char tag_version_v4[] = {
	'\x20', '\x20', '\x09', '\x09', '\x20', '\x09', '\x20', '\x20',
	'\0'
};

static const char tag_version_v3[] = {
	'\x20', '\x20', '\x09', '\x09', '\x20', '\x20', '\x09', '\x09',
	'\0'
};

static const string_t query_header = "?OTRv";
static const string_t otr_header = "?OTR:";

static void gone_secure_cb(const otrv4_t * otr)
{
	if (!otr->callbacks)
		return;

	otr->callbacks->gone_secure(otr);
}

static void gone_insecure_cb(const otrv4_t * otr)
{
	if (!otr->callbacks)
		return;

	otr->callbacks->gone_insecure(otr);
}

static void fingerprint_seen_cb(const otrv4_fingerprint_t fp,
				const otrv4_t * otr)
{
	if (!otr->callbacks)
		return;

	otr->callbacks->fingerprint_seen(fp, otr);
}

static void handle_smp_event_cb(const otr4_smp_event_t event,
            const uint8_t progress_percent, const char *question,
            const otrv4_t *otr)
{
	if (!otr->callbacks)
		return;

	otr->callbacks->handle_smp_event(event, progress_percent, question, otr);
}

static int allow_version(const otrv4_t * otr, otrv4_supported_version version)
{
	return (otr->supported_versions & version);
}

// dst must be at least 3 bytes long.
static void allowed_versions(string_t dst, const otrv4_t * otr)
{
	if (allow_version(otr, OTRV4_ALLOW_V4))
		*dst++ = '4';

	if (allow_version(otr, OTRV4_ALLOW_V3))
		*dst++ = '3';

	*dst = 0;
}

static user_profile_t *get_my_user_profile(const otrv4_t * otr)
{
	char versions[3] = { 0 };
	allowed_versions(versions, otr);
	return user_profile_build(versions, otr->keypair);
}

otrv4_t *otrv4_new(otrv4_keypair_t * keypair, otrv4_policy_t policy)
{
	otrv4_t *otr = malloc(sizeof(otrv4_t));
	if (!otr)
		return NULL;

	otr->keypair = keypair;
	otr->state = OTRV4_STATE_START;
	otr->running_version = OTRV4_VERSION_NONE;
	otr->supported_versions = policy.allows;

	//TODO: Serialize and deserialize our instance tags to/from disk.
	otr->our_instance_tag = 0;
	otr->their_instance_tag = 0;
	otr->profile = get_my_user_profile(otr);
	otr->their_profile = NULL;

	otr->keys = malloc(sizeof(key_manager_t));
	if (!otr->keys)
		return NULL;

	key_manager_init(otr->keys);
	otr->callbacks = NULL;

	//TODO: moves initialization to smp
	otr->smp->state = SMPSTATE_EXPECT1;
        otr->smp->progress = 0;
        otr->smp->msg1->question = NULL;
	return otr;
}

void otrv4_destroy( /*@only@ */ otrv4_t * otr)
{
	otr->keypair = NULL;
	key_manager_destroy(otr->keys);
	user_profile_free(otr->profile);
	user_profile_free(otr->their_profile);
	otr->profile = NULL;
	otr->their_profile = NULL;
	otr->callbacks = NULL;
	smp_destroy(otr->smp);
	free(otr->keys);
	otr->keys = NULL;
}

void otrv4_free( /*@only@ */ otrv4_t * otr)
{
	if (otr == NULL) {
		return;
	}

	otrv4_destroy(otr);
	free(otr);
}

//TODO: This belongs to the client.
int otrv4_build_query_message(string_t * dst, const string_t message,
			      const otrv4_t * otr)
{
	//size = qm tag + versions + msg length + versions + question mark + whitespace + null byte
	size_t qm_size = QUERY_MESSAGE_TAG_BYTES + 3 + strlen(message) + 2 + 1;
	string_t buff = NULL;
	char allowed[3] = { 0 };

	*dst = NULL;
	allowed_versions(allowed, otr);

	buff = malloc(qm_size);
	if (!buff)
		return -1;

	char *cursor = stpcpy(buff, query_header);
	cursor = stpcpy(cursor, allowed);
	cursor = stpcpy(cursor, "? ");

	int rem = cursor - buff;
	if (*stpncpy(cursor, message, qm_size - rem)) {
		free(buff);
		return 1;	// could not zero-terminate the string
	}

	*dst = buff;
	return 0;
}

//TODO: This belongs to the client.
bool
otrv4_build_whitespace_tag(string_t * whitespace_tag, const string_t message,
			   const otrv4_t * otr)
{
	size_t m_size = WHITESPACE_TAG_BASE_BYTES + strlen(message) + 1;
	int allows_v4 = allow_version(otr, OTRV4_ALLOW_V4);
	int allows_v3 = allow_version(otr, OTRV4_ALLOW_V3);
	string_t buff = NULL;
	string_t cursor = NULL;

	if (allows_v4)
		m_size += WHITESPACE_TAG_VERSION_BYTES;

	if (allows_v3)
		m_size += WHITESPACE_TAG_VERSION_BYTES;

	buff = malloc(m_size);
	if (!buff)
		return false;

	cursor = stpcpy(buff, tag_base);

	if (allows_v4)
		cursor = stpcpy(cursor, tag_version_v4);

	if (allows_v3)
		cursor = stpcpy(cursor, tag_version_v3);

	if (*stpncpy(cursor, message, m_size - strlen(buff))) {
		free(buff);
		return false;
	}

	*whitespace_tag = buff;
	return true;
}

static bool message_contains_tag(const string_t message)
{
	return strstr(message, tag_base) != NULL;
}

//TODO: If it is a string, why having len?
static void
set_to_display(otrv4_response_t * response, const string_t message,
	       size_t msg_len)
{
	response->to_display = otrv4_strndup(message, msg_len);
}

//TODO: this does not remove ALL tags
static bool
message_to_display_without_tag(otrv4_response_t * response,
			       const string_t message,
			       const char *tag_version, size_t msg_len)
{
	size_t tag_length =
	    WHITESPACE_TAG_BASE_BYTES + WHITESPACE_TAG_VERSION_BYTES;
	size_t chars = msg_len - tag_length;

	if (msg_len < tag_length) {
		return false;
	}

	string_t buff = malloc(chars + 1);
	if (buff == NULL) {
		return false;
	}

	strncpy(buff, message + tag_length, chars);
	buff[chars] = '\0';

	set_to_display(response, buff, chars);

	free(buff);
	return true;
}

//TODO: This belongs to the client. A otrv4_t should only "run" the v4 wire protocol.
static void set_running_version_from_tag(otrv4_t * otr, const string_t message)
{
	if (allow_version(otr, OTRV4_ALLOW_V4)
	    && strstr(message, tag_version_v4)) {
		otr->running_version = OTRV4_VERSION_4;
		return;
	}

	if (allow_version(otr, OTRV4_ALLOW_V3)
	    && strstr(message, tag_version_v3)) {
		otr->running_version = OTRV4_VERSION_3;
		return;
	}
}

static bool message_is_query(const string_t message)
{
	return strstr(message, query_header) != NULL;
}

//TODO: This belongs to the client. A otrv4_t should only "run" the v4 wire protocol.
static void set_running_version_from_query_msg(otrv4_t * otr,
					       const string_t message)
{
	if (allow_version(otr, OTRV4_ALLOW_V4) && strstr(message, "4")) {
		otr->running_version = OTRV4_VERSION_4;
		return;
	}

	if (allow_version(otr, OTRV4_ALLOW_V3) && strstr(message, "3")) {
		otr->running_version = OTRV4_VERSION_3;
		return;
	}
}

static bool message_is_otr_encoded(const string_t message)
{
	return strstr(message, otr_header) != NULL;
}

otrv4_response_t *otrv4_response_new(void)
{
	otrv4_response_t *response = malloc(sizeof(otrv4_response_t));
	if (!response)
		return NULL;

	response->to_display = NULL;
	response->to_send = NULL;
	response->warning = OTRV4_WARN_NONE;
	response->tlvs = NULL;

	return response;
}

void otrv4_response_free(otrv4_response_t * response)
{
	if (!response)
		return;

	free(response->to_send);
	response->to_send = NULL;

	free(response->to_display);
	response->to_display = NULL;

	otrv4_tlv_free(response->tlvs);
	response->tlvs = NULL;

	free(response);
}

//TODO: Is not receiving a plaintext a problem?
static void
receive_plaintext(otrv4_response_t * response, const string_t message,
		  const otrv4_t * otr, size_t msg_len)
{
	set_to_display(response, message, msg_len);

	if (otr->state != OTRV4_STATE_START)
		response->warning = OTRV4_WARN_RECEIVED_UNENCRYPTED;
}

static bool
serialize_and_encode_identity_message(string_t * dst,
				      const dake_identity_message_t * m)
{
	uint8_t *buff = NULL;
	size_t len = 0;

	if (!dake_identity_message_aprint(&buff, &len, m))
		return false;

	*dst = otrl_base64_otr_encode(buff, len);
	free(buff);
	return true;
}

static bool
reply_with_identity_msg(otrv4_response_t * response, const otrv4_t * otr)
{
	dake_identity_message_t *m = NULL;
	bool ok = false;

	m = dake_identity_message_new(otr->profile);
	if (!m)
		return false;

	m->sender_instance_tag = otr->our_instance_tag;
	m->receiver_instance_tag = otr->their_instance_tag;

	ec_point_copy(m->Y, OUR_ECDH(otr));
	m->B = dh_mpi_copy(OUR_DH(otr));

	ok = serialize_and_encode_identity_message(&response->to_send, m);
	dake_identity_message_free(m);
	return ok;
}

static bool start_dake(otrv4_response_t * response, otrv4_t * otr)
{
	key_manager_generate_ephemeral_keys(otr->keys);
	otr->state = OTRV4_STATE_WAITING_AUTH_R;

	return reply_with_identity_msg(response, otr);
}

static bool
receive_tagged_plaintext(otrv4_response_t * response,
			 const string_t message, otrv4_t * otr, size_t msg_len)
{
	set_running_version_from_tag(otr, message);

	switch (otr->running_version) {
	case OTRV4_VERSION_4:
		if (!message_to_display_without_tag
		    (response, message, tag_version_v4, msg_len)) {
			return false;
		}

		return start_dake(response, otr);
		break;
	case OTRV4_VERSION_3:
		return otrv3_receive_message(message, msg_len);
		break;
	default:
                //ignore
                return true;
	}

	return false;
}

static bool
receive_query_message(otrv4_response_t * response,
		      const string_t message, otrv4_t * otr, size_t msg_len)
{
	set_running_version_from_query_msg(otr, message);

	switch (otr->running_version) {
	case OTRV4_VERSION_4:
		return start_dake(response, otr);
		break;
	case OTRV4_VERSION_3:
		return otrv3_receive_message(message, 0);
		break;
	default:
		//ignore
                return true;
	}

	return false;
}

bool
extract_header(otrv4_header_t * dst, const uint8_t * buffer,
	       const size_t bufflen)
{
	//TODO: check the length

	size_t read = 0;
	uint16_t version = 0;
	uint8_t type = 0;
	if (deserialize_uint16(&version, buffer, bufflen, &read)) {
		return false;
	}

	buffer += read;

	if (deserialize_uint8(&type, buffer, bufflen - read, &read)) {
		return false;
	}

	dst->version = OTRV4_ALLOW_NONE;
	if (version == 0x04) {
		dst->version = OTRV4_ALLOW_V4;
	} else if (version == 0x03) {
		dst->version = OTRV4_ALLOW_V3;
	}
	dst->type = type;

	return true;
}

static bool double_ratcheting_init(int j, otrv4_t * otr)
{
	if (!key_manager_ratchetting_init(j, otr->keys))
		return false;

	otr->state = OTRV4_STATE_ENCRYPTED_MESSAGES;
	gone_secure_cb(otr);

	return true;
}

static bool
build_auth_message(uint8_t ** msg, size_t * msg_len,
		   const uint8_t type,
		   const user_profile_t * i_profile,
		   const user_profile_t * r_profile,
		   const ec_point_t i_ecdh,
		   const ec_point_t r_ecdh,
		   const dh_mpi_t i_dh, const dh_mpi_t r_dh)
{
	uint8_t *ser_i_profile = NULL, *ser_r_profile = NULL;
	size_t ser_i_profile_len, ser_r_profile_len = 0;
	uint8_t ser_i_ecdh[ED448_POINT_BYTES], ser_r_ecdh[ED448_POINT_BYTES];

	if (serialize_ec_point(ser_i_ecdh, i_ecdh)) {
		return false;
	}
	if (serialize_ec_point(ser_r_ecdh, r_ecdh)) {
		return false;
	}

	uint8_t ser_i_dh[DH3072_MOD_LEN_BYTES], ser_r_dh[DH3072_MOD_LEN_BYTES];
	size_t ser_i_dh_len = 0, ser_r_dh_len = 0;

	otr4_err_t err = serialize_dh_public_key(ser_i_dh, &ser_i_dh_len, i_dh);
	if (err) {
		return false;
	}
	err = serialize_dh_public_key(ser_r_dh, &ser_r_dh_len, r_dh);
	if (err) {
		return false;
	}

	bool ok = false;

	do {
		if (user_profile_asprintf
		    (&ser_i_profile, &ser_i_profile_len, i_profile))
			continue;

		if (user_profile_asprintf
		    (&ser_r_profile, &ser_r_profile_len, r_profile))
			continue;

		size_t len = 1
		    + 2 * ED448_POINT_BYTES
		    + ser_i_profile_len + ser_r_profile_len
		    + ser_i_dh_len + ser_r_dh_len;

		uint8_t *buff = malloc(len);
		if (!buff)
			continue;

		uint8_t *cursor = buff;
		*cursor = type;
		cursor++;

		memcpy(cursor, ser_i_profile, ser_i_profile_len);
		cursor += ser_i_profile_len;

		memcpy(cursor, ser_r_profile, ser_r_profile_len);
		cursor += ser_r_profile_len;

		memcpy(cursor, ser_i_ecdh, ED448_POINT_BYTES);
		cursor += ED448_POINT_BYTES;

		memcpy(cursor, ser_r_ecdh, ED448_POINT_BYTES);
		cursor += ED448_POINT_BYTES;

		memcpy(cursor, ser_i_dh, ser_i_dh_len);
		cursor += ser_i_dh_len;

		memcpy(cursor, ser_r_dh, ser_r_dh_len);
		cursor += ser_r_dh_len;

		*msg = buff;
		*msg_len = len;
		ok = true;
	} while (0);

	free(ser_i_profile);
	free(ser_r_profile);

	//Destroy serialized ephemeral public keys from memory

	return ok;
}

static bool serialize_and_encode_auth_r(string_t * dst, const dake_auth_r_t * m)
{
	uint8_t *buff = NULL;
	size_t len = 0;

	if (!dake_auth_r_aprint(&buff, &len, m))
		return false;

	*dst = otrl_base64_otr_encode(buff, len);
	free(buff);
	return true;
}

static bool reply_with_auth_r_msg(string_t * dst, const otrv4_t * otr)
{
	dake_auth_r_t msg[1];
	msg->sender_instance_tag = otr->our_instance_tag;
	msg->receiver_instance_tag = otr->their_instance_tag;

	user_profile_copy(msg->profile, otr->profile);

	ec_point_copy(msg->X, OUR_ECDH(otr));
	msg->A = dh_mpi_copy(OUR_DH(otr));

	unsigned char *t = NULL;
	size_t t_len = 0;
	if (!build_auth_message
	    (&t, &t_len, 0, otr->their_profile, otr->profile, THEIR_ECDH(otr),
	     OUR_ECDH(otr), THEIR_DH(otr), OUR_DH(otr)))
		return false;

	//sigma = Auth(g^R, R, {g^I, g^R, g^i}, msg)
	int err = snizkpk_authenticate(msg->sigma,
				       otr->keypair,	// g^R and R
				       otr->their_profile->pub_key,	// g^I
				       THEIR_ECDH(otr),	// g^i -- Y
				       t, t_len);

	free(t);
	t = NULL;

	if (err)
		return false;

	bool ok = serialize_and_encode_auth_r(dst, msg);
	dake_auth_r_destroy(msg);
	return ok;
}

static bool
receive_identity_message_on_state_start(string_t * dst,
					dake_identity_message_t *
					identity_message, otrv4_t * otr)
{
	if (!dake_identity_message_validate(identity_message))
		return false;

	otr->their_profile = malloc(sizeof(user_profile_t));
	if (!otr->their_profile)
		return false;

	key_manager_set_their_ecdh(identity_message->Y, otr->keys);
	key_manager_set_their_dh(identity_message->B, otr->keys);
	user_profile_copy(otr->their_profile, identity_message->profile);

	key_manager_generate_ephemeral_keys(otr->keys);

	if (!reply_with_auth_r_msg(dst, otr))
		return false;

	otr->state = OTRV4_STATE_WAITING_AUTH_I;
	return true;
}

static void forget_our_keys(otrv4_t * otr)
{
	key_manager_destroy(otr->keys);
	key_manager_init(otr->keys);
}

static bool
receive_identity_message_while_in_progress(string_t * dst,
					   dake_identity_message_t * msg,
					   otrv4_t * otr)
{
	//1) Compare X with their_dh
	gcry_mpi_t x = NULL;
	gcry_mpi_t y = NULL;
	int err = 0;

	err |= gcry_mpi_scan(&x, GCRYMPI_FMT_USG, OUR_DH(otr),
			     sizeof(ec_public_key_t), NULL);

	err |= gcry_mpi_scan(&y, GCRYMPI_FMT_USG, msg->Y,
			     sizeof(ec_public_key_t), NULL);

	if (err) {
		gcry_mpi_release(x);
		gcry_mpi_release(y);
		return false;
	}

	int cmp = gcry_mpi_cmp(x, y);
	gcry_mpi_release(x);
	gcry_mpi_release(y);

	// If our is lower, ignore.
	if (cmp < 0)
		return true;	//ignore

	forget_our_keys(otr);
	return receive_identity_message_on_state_start(dst, msg, otr);
}

static void received_instance_tag(uint32_t their_instance_tag, otrv4_t * otr)
{
	//TODO: should we do any additional check?
	otr->their_instance_tag = their_instance_tag;
}

static bool
receive_identity_message(string_t * dst, const uint8_t * buff, size_t buflen,
			 otrv4_t * otr)
{
	bool ok = false;
	dake_identity_message_t m[1];

	if (!dake_identity_message_deserialize(m, buff, buflen))
		return false;

	received_instance_tag(m->sender_instance_tag, otr);

	if (!validate_received_values(m->Y, m->B, m->profile))
		return false;

	switch (otr->state) {
	case OTRV4_STATE_START:
		ok = receive_identity_message_on_state_start(dst, m, otr);
		break;
	case OTRV4_STATE_WAITING_AUTH_R:
		ok = receive_identity_message_while_in_progress(dst, m, otr);
		break;
	case OTRV4_STATE_WAITING_AUTH_I:
		//TODO
		break;
	default:
		//Ignore the message, but it is not an error.
		ok = true;
	}

	dake_identity_message_destroy(m);
	return ok;
}

static bool serialize_and_encode_auth_i(string_t * dst, const dake_auth_i_t * m)
{
	uint8_t *buff = NULL;
	size_t len = 0;

	if (!dake_auth_i_aprint(&buff, &len, m))
		return false;

	*dst = otrl_base64_otr_encode(buff, len);
	free(buff);
	return true;
}

static bool
reply_with_auth_i_msg(string_t * dst, const user_profile_t * their,
		      const otrv4_t * otr)
{
	dake_auth_i_t msg[1];
	msg->sender_instance_tag = otr->our_instance_tag;
	msg->receiver_instance_tag = otr->their_instance_tag;

	unsigned char *t = NULL;
	size_t t_len = 0;
	if (!build_auth_message
	    (&t, &t_len, 1, otr->profile, their, OUR_ECDH(otr), THEIR_ECDH(otr),
	     OUR_DH(otr), THEIR_DH(otr)))
		return false;

	if (snizkpk_authenticate
	    (msg->sigma, otr->keypair, their->pub_key, THEIR_ECDH(otr), t,
	     t_len))
		return false;

	free(t);
	t = NULL;

	bool ok = serialize_and_encode_auth_i(dst, msg);
	dake_auth_i_destroy(msg);
	return ok;
}

static bool
verify_auth_r_message(const dake_auth_r_t * auth, const otrv4_t * otr)
{
	uint8_t *t = NULL;
	size_t t_len = 0;

	if (!validate_received_values(auth->X, auth->A, auth->profile))
		return false;

	if (!build_auth_message
	    (&t, &t_len, 0, otr->profile, auth->profile, OUR_ECDH(otr), auth->X,
	     OUR_DH(otr), auth->A))
		return false;

	//Verif({g^I, g^R, g^i}, sigma, msg)
	int err = snizkpk_verify(auth->sigma,
				 auth->profile->pub_key,	// g^R
				 otr->keypair->pub,	// g^I
				 OUR_ECDH(otr),	// g^
				 t, t_len);

	free(t);
	t = NULL;

	return err == 0;
}

static bool
receive_auth_r(string_t * dst, const uint8_t * buff, size_t buff_len,
	       otrv4_t * otr)
{
	if (otr->state != OTRV4_STATE_WAITING_AUTH_R)
		return true; // ignore the message

	dake_auth_r_t auth[1];
	if (!dake_auth_r_deserialize(auth, buff, buff_len))
		return false;

	received_instance_tag(auth->sender_instance_tag, otr);

	if (!verify_auth_r_message(auth, otr))
		return false;

	otr->their_profile = malloc(sizeof(user_profile_t));
	if (!otr->their_profile)
		return false;

	key_manager_set_their_ecdh(auth->X, otr->keys);
	key_manager_set_their_dh(auth->A, otr->keys);
	user_profile_copy(otr->their_profile, auth->profile);

	if (!reply_with_auth_i_msg(dst, otr->their_profile, otr))
		return false;

	dake_auth_r_destroy(auth);

	otrv4_fingerprint_t fp;
	if (!otr4_serialize_fingerprint(fp, otr->their_profile->pub_key))
		fingerprint_seen_cb(fp, otr);

	return double_ratcheting_init(0, otr);
}

static bool
verify_auth_i_message(const dake_auth_i_t * auth, const otrv4_t * otr)
{
	uint8_t *t = NULL;
	size_t t_len = 0;

	if (!build_auth_message(&t, &t_len, 1, otr->their_profile,
				otr->profile, THEIR_ECDH(otr), OUR_ECDH(otr),
				THEIR_DH(otr), OUR_DH(otr)))
		return false;

	int err = snizkpk_verify(auth->sigma, otr->their_profile->pub_key,
				 otr->keypair->pub, OUR_ECDH(otr), t, t_len);
	free(t);
	t = NULL;

	return err == 0;
}

static bool
receive_auth_i(string_t * dst, const uint8_t * buff, size_t buff_len,
	       otrv4_t * otr)
{
	if (otr->state != OTRV4_STATE_WAITING_AUTH_I)
		return true; // Ignore the message

	dake_auth_i_t auth[1];
	if (!dake_auth_i_deserialize(auth, buff, buff_len))
		return false;

	if (!verify_auth_i_message(auth, otr))
		return false;

	dake_auth_i_destroy(auth);

	otrv4_fingerprint_t fp;
	if (!otr4_serialize_fingerprint(fp, otr->their_profile->pub_key))
		fingerprint_seen_cb(fp, otr);

	return double_ratcheting_init(1, otr);
}

static void extract_tlvs(tlv_t ** tlvs, const uint8_t * src, size_t len)
{
	if (!tlvs)
		return;

	uint8_t *tlvs_start = memchr(src, 0, len);
	if (!tlvs_start)
		return;

	size_t tlvs_len = len - (tlvs_start + 1 - src);
	*tlvs = otrv4_parse_tlvs(tlvs_start + 1, tlvs_len);
}

static bool
decrypt_data_msg(otrv4_response_t * response, const m_enc_key_t enc_key,
		 const data_message_t * msg)
{
	string_t *dst = &response->to_display;
	tlv_t **tlvs = &response->tlvs;

#ifdef DEBUG
	printf("DECRYPTING\n");
	printf("enc_key = ");
	otrv4_memdump(enc_key, sizeof(m_enc_key_t));
	printf("nonce = ");
	otrv4_memdump(msg->nonce, DATA_MSG_NONCE_BYTES);
#endif

	uint8_t *plain = malloc(msg->enc_msg_len);
	if (!plain)
		return false;

	int err = crypto_stream_xor(plain, msg->enc_msg, msg->enc_msg_len,
				    msg->nonce, enc_key);

	if (strnlen((string_t) plain, msg->enc_msg_len))
		*dst = otrv4_strndup((char *)plain, msg->enc_msg_len);

	extract_tlvs(tlvs, plain, msg->enc_msg_len);

	free(plain);
	return err == 0;
}

//TODO: Process SMP TLVs
static tlv_t* process_tlv(const tlv_t * tlv, otrv4_t * otr)
{
	switch (tlv->type) {
	case OTRV4_TLV_PADDING:
		break;
	case OTRV4_TLV_DISCONNECTED:
		forget_our_keys(otr);
		otr->state = OTRV4_STATE_FINISHED;
		gone_insecure_cb(otr);
		break;
        case OTRV4_TLV_SMP_MSG_1:
        case OTRV4_TLV_SMP_MSG_2:
        case OTRV4_TLV_SMP_MSG_3:
        case OTRV4_TLV_SMP_MSG_4:
        case OTRV4_TLV_SMP_ABORT:
            return otrv4_process_smp(otr, tlv);
	default:
		//error?
		break;
	}

        return NULL;
}

static bool receive_tlvs(tlv_t **to_send, otrv4_response_t * response, otrv4_t * otr)
{
        tlv_t *cursor = NULL;

	const tlv_t *current = response->tlvs;
	while (current) {
		tlv_t *ret = process_tlv(current, otr);
		current = current->next;

                if (!ret) continue;

                if (cursor)
                    cursor = cursor->next;

                cursor = ret;
	}

        *to_send = cursor;
	return true;
}

static bool
get_receiving_msg_keys(m_enc_key_t enc_key, m_mac_key_t mac_key,
		       const data_message_t * msg, otrv4_t * otr)
{
	if (!key_manager_ensure_on_ratchet(msg->ratchet_id, otr->keys))
		return false;

	return key_manager_retrieve_receiving_message_keys(enc_key, mac_key,
							   msg->ratchet_id,
							   msg->message_id,
							   otr->keys);
}

bool
otrv4_receive_data_message(otrv4_response_t * response, const uint8_t * buff,
			   size_t buflen, otrv4_t * otr)
{
	data_message_t *msg = data_message_new();
	m_enc_key_t enc_key;
	m_mac_key_t mac_key;

	//TODO: warn the user and send an error message with a code.
	if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
		return false;

	if (!data_message_deserialize(msg, buff, buflen))
		return false;

	key_manager_set_their_keys(msg->ecdh, msg->dh, otr->keys);

        tlv_t *reply_tlv = NULL;
	do {
		if (!get_receiving_msg_keys(enc_key, mac_key, msg, otr))
			continue;

		if (!data_message_validate(mac_key, msg))
			continue;

		if (!decrypt_data_msg(response, enc_key, msg))
			continue;

		//TODO: Securely delete receiving chain keys older than message_id-1.

		otr->keys->old_mac_keys = list_add(mac_key, otr->keys->old_mac_keys);

		if (!receive_tlvs(&reply_tlv, response, otr))
			continue;

		key_manager_prepare_to_ratchet(otr->keys);

                if (reply_tlv)
                    if (!otrv4_send_message(&response->to_send, "", reply_tlv, otr))
                        continue;

                otrv4_tlv_free(reply_tlv);
		data_message_free(msg);
		return true;
	} while (0);

	data_message_free(msg);
        otrv4_tlv_free(reply_tlv);
	return false;
}

static bool
receive_encoded_message(otrv4_response_t * response,
			const string_t message, otrv4_t * otr, size_t msg_len)
{
	size_t dec_len = 0;
	uint8_t *decoded = NULL;
	int err = otrl_base64_otr_decode(message, &decoded, &dec_len);
	if (err)
		return false;

	if (dec_len > msg_len)
		return false;

	otrv4_header_t header;
	if (!extract_header(&header, decoded, dec_len)) {
		free(decoded);
		return false;
	}

	if (!allow_version(otr, header.version)) {
		free(decoded);
		return false;
	}
	//TODO: how to prevent version rollback?
	//TODO: where should we ignore messages to a different instance tag?

	switch (header.type) {
	case OTR_IDENTITY_MSG_TYPE:
		if (!receive_identity_message
		    (&response->to_send, decoded, dec_len, otr)) {
			free(decoded);
			return false;
		}
		break;
	case OTR_AUTH_R_MSG_TYPE:
		if (!receive_auth_r(&response->to_send, decoded, dec_len, otr)) {
			free(decoded);
			return false;
		}
		break;
	case OTR_AUTH_I_MSG_TYPE:
		if (!receive_auth_i(&response->to_send, decoded, dec_len, otr)) {
			free(decoded);
			return false;
		}
		break;
	case OTR_DATA_MSG_TYPE:
		if (!otrv4_receive_data_message
		    (response, decoded, dec_len, otr)) {
			free(decoded);
			return false;
		}
		break;
	default:
		//errror. bad message type
		return false;
		break;
	}

	free(decoded);
	return true;
}

otrv4_in_message_type_t get_message_type(const string_t message)
{
	if (message_contains_tag(message)) {
		return IN_MSG_TAGGED_PLAINTEXT;
	} else if (message_is_query(message)) {
		return IN_MSG_QUERY_STRING;
	} else if (message_is_otr_encoded(message)) {
		return IN_MSG_OTR_ENCODED;
	}

	return IN_MSG_PLAINTEXT;
}

// Receive a possibly OTR message.
bool
otrv4_receive_message(otrv4_response_t * response,
		      const string_t message, size_t message_len, otrv4_t * otr)
{
	if (!message || !response)
		return false;

	set_to_display(response, NULL, 0);
	response->to_send = NULL;

	switch (get_message_type(message)) {
	case IN_MSG_NONE:
		return false;
	case IN_MSG_PLAINTEXT:
		receive_plaintext(response, message, otr, message_len);
		return true;
		break;

	case IN_MSG_TAGGED_PLAINTEXT:
		return receive_tagged_plaintext(response, message, otr,
						message_len);
		break;

	case IN_MSG_QUERY_STRING:
		return receive_query_message(response, message, otr,
					     message_len);
		break;

	case IN_MSG_OTR_ENCODED:
		return receive_encoded_message(response, message, otr,
					       message_len);
		break;
	}

	return true;
}

static data_message_t *generate_data_msg(const otrv4_t * otr)
{
	data_message_t *data_msg = data_message_new();
	if (!data_msg)
		return NULL;

	data_msg->sender_instance_tag = otr->our_instance_tag;
	data_msg->receiver_instance_tag = otr->their_instance_tag;
	data_msg->ratchet_id = otr->keys->i;
	data_msg->message_id = otr->keys->j;
	ec_point_copy(data_msg->ecdh, OUR_ECDH(otr));
	data_msg->dh = dh_mpi_copy(OUR_DH(otr));

	return data_msg;
}

static bool
encrypt_data_message(data_message_t * data_msg, const uint8_t * message,
		     size_t message_len, const m_enc_key_t enc_key)
{
	int err = 0;
	uint8_t *c = NULL;

	random_bytes(data_msg->nonce, sizeof(data_msg->nonce));

	c = malloc(message_len);
	if (!c)
		return false;

	//TODO: message is an UTF-8 string. Is there any problem to cast
	//it to (unsigned char *)
	err =
	    crypto_stream_xor(c, message, message_len, data_msg->nonce,
			      enc_key);
	if (err) {
		free(c);
		return false;
	}

	data_msg->enc_msg = c;
	data_msg->enc_msg_len = message_len;

#ifdef DEBUG
	printf("nonce = ");
	otrv4_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
	printf("msg = ");
	otrv4_memdump(message, message_len);
	printf("cipher = ");
	otrv4_memdump(c, message_len);
#endif

	return true;
}

static bool
serialize_and_encode_data_msg(string_t * dst, const m_mac_key_t mac_key,
			      const data_message_t * data_msg)
{
	bool ok = false;
	uint8_t *body = NULL;
	size_t bodylen = 0;

	if (!data_message_body_aprint(&body, &bodylen, data_msg))
		return false;


	//TODO: append old mac keys to be revealed
	size_t serlen = bodylen + DATA_MSG_MAC_BYTES;
	uint8_t *ser = malloc(serlen);
	if (!ser) {
		free(body);
		return false;
	}

	memcpy(ser, body, bodylen);
	free(body);

	ok = sha3_512_mac(ser + bodylen, DATA_MSG_MAC_BYTES, mac_key,
			  sizeof(m_mac_key_t), ser, bodylen);

	if (!ok) {
		free(ser);
		return false;
	}

	*dst = otrl_base64_otr_encode(ser, serlen);
	free(ser);

	return true;
}

static bool
send_data_message(string_t * to_send, const uint8_t * message,
		  size_t message_len, otrv4_t * otr)
{
	bool ok = false;
	data_message_t *data_msg = NULL;
	m_enc_key_t enc_key;
	m_mac_key_t mac_key;

	if (!key_manager_prepare_next_chain_key(otr->keys))
		return false;

	ok = key_manager_retrieve_sending_message_keys(enc_key, mac_key,
						       otr->keys);
	if (!ok)
		return false;

	data_msg = generate_data_msg(otr);
	if (!data_msg)
		return false;

	ok = encrypt_data_message(data_msg, message, message_len, enc_key);
	if (ok)
		ok = serialize_and_encode_data_msg(to_send, mac_key, data_msg);

	data_message_free(data_msg);

	//TODO: Change the spec to say this should be incremented after the message
	//is sent.
	if (ok)
		otr->keys->j++;

	return ok;
}

static
bool serlialize_tlvs(uint8_t ** dst, size_t * dstlen, const tlv_t * tlvs)
{
	const tlv_t *current = tlvs;
	uint8_t *cursor = NULL;

	*dst = NULL;
	*dstlen = 0;

	if (!tlvs)
		return true;

	for (*dstlen = 0; current; current = current->next)
		*dstlen += current->len + 4;

	*dst = malloc(*dstlen);
	if (!*dst)
		return false;

	cursor = *dst;
	for (current = tlvs; current; current = current->next) {
		cursor += serialize_uint16(cursor, current->type);
		cursor += serialize_uint16(cursor, current->len);
		cursor += serialize_bytes_array(cursor, current->data,
						current->len);
	}

	return true;
}

static
bool append_tlvs(uint8_t ** dst, size_t * dstlen, const string_t message,
		 const tlv_t * tlvs)
{
	uint8_t *ser = NULL;
	size_t len = 0;

	if (!serlialize_tlvs(&ser, &len, tlvs))
		return false;

	*dstlen = strlen(message) + 1 + len;
	*dst = malloc(*dstlen);
	if (!*dst) {
		free(ser);
		return false;
	}

	memcpy(stpcpy((char *)*dst, message) + 1, ser, len);

	free(ser);
	return true;
}

bool
otrv4_send_message(string_t * to_send, const string_t message, tlv_t * tlvs,
		   otrv4_t * otr)
{
	uint8_t *msg = NULL;
	size_t msg_len = 0;

	if (otr->state == OTRV4_STATE_FINISHED)
		return false;	//Should restart

	if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
		return false;	//TODO: queue message

	if (!append_tlvs(&msg, &msg_len, message, tlvs))
		return false;

	bool ok = send_data_message(to_send, msg, msg_len, otr);
	free(msg);

	return ok;
}

bool otrv4_close(string_t * to_send, otrv4_t * otr)
{
	if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
		return true;

	tlv_t *disconnected = otrv4_disconnected_tlv_new();
	if (!disconnected)
		return false;

	bool ok = otrv4_send_message(to_send, "", disconnected, otr);
	otrv4_tlv_free(disconnected);

	forget_our_keys(otr);
	otr->state = OTRV4_STATE_START;
	gone_insecure_cb(otr);

	return ok;
}

static void set_smp_secret(unsigned char **secret, const uint8_t *answer,
		    size_t answerlen, bool is_initiator, otrv4_t * otr)
{
	otrv4_fingerprint_t our_fp, their_fp;
	otr4_serialize_fingerprint(our_fp, otr->profile->pub_key);
	otr4_serialize_fingerprint(their_fp, otr->their_profile->pub_key);

	//TODO: return error?
	if (is_initiator)
		generate_smp_secret(secret, our_fp, their_fp, otr->keys->ssid, answer, answerlen);
	else
		generate_smp_secret(secret, their_fp, our_fp, otr->keys->ssid, answer, answerlen);
}

bool otrv4_smp_start(string_t * to_send, const string_t question,
			  const uint8_t *secret, const size_t secretlen,
                          otrv4_t * otr)
{
    if (!otr)
        return false;

    tlv_t *smp_start_tlv = otrv4_smp_initiate(otr, question, secret, secretlen);
    return otrv4_send_message(to_send, "", smp_start_tlv, otr);
}

bool otrv4_smp_continue(string_t * to_send, const uint8_t *secret,
    const size_t secretlen, otrv4_t * otr)
{
    bool ok = false;
    tlv_t *smp_reply = NULL;

    if (!otr)
        return false;

    smp_reply = otrv4_smp_provide_secret(otr, secret, secretlen);

    if (smp_reply)
        ok = otrv4_send_message(to_send, "", smp_reply, otr);

    otrv4_tlv_free(smp_reply);
    return ok;
}

tlv_t *otrv4_smp_initiate(otrv4_t * otr, const string_t question,
			  const uint8_t *secret, size_t secretlen)
{
	if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
		return NULL;

	smp_msg_1_t msg;
	uint8_t *to_send = NULL;
	size_t len = 0;

	set_smp_secret(&otr->smp->x, secret, secretlen, true, otr);

        do {
            if (generate_smp_msg_1(msg, otr->smp))
                continue;

            if (question)
                msg->question = otrv4_strdup(question);

            if (!smp_msg_1_aprint(&to_send, &len, msg))
                continue;

            otr->smp->state = SMPSTATE_EXPECT2;
            otr->smp->progress = 25;
            handle_smp_event_cb(OTRV4_SMPEVENT_IN_PROGRESS, otr->smp->progress, otr->smp->msg1->question, otr);

            tlv_t *tlv = otrv4_tlv_new(OTRV4_TLV_SMP_MSG_1, len, to_send);
            free(to_send);
            return tlv;
        } while(0);

        handle_smp_event_cb(OTRV4_SMPEVENT_ERROR, otr->smp->progress, otr->smp->msg1->question, otr);
	return NULL;
}

tlv_t *otrv4_process_smp(otrv4_t * otr, const tlv_t * tlv)
{
        otr4_smp_event_t event = OTRV4_SMPEVENT_NONE;
	tlv_t *to_send = NULL;

        switch (tlv->type) {
        case OTRV4_TLV_SMP_MSG_1:
            event = process_smp_msg1(tlv, otr->smp);
            break;

        case OTRV4_TLV_SMP_MSG_2:
            event = process_smp_msg2(&to_send, tlv, otr->smp);
            break;

	case OTRV4_TLV_SMP_MSG_3:
            event = process_smp_msg3(&to_send, tlv, otr->smp);
            break;

        case OTRV4_TLV_SMP_MSG_4:
            event = process_smp_msg4(tlv, otr->smp);
            break;

        default:
            //If smpstate is not the receive message:
            //Set smpstate to SMPSTATE_EXPECT1
            //send a SMP abort to other peer.
            otr->smp->state = SMPSTATE_EXPECT1;
            to_send = otrv4_tlv_new(OTRV4_TLV_SMP_ABORT, 0, NULL);
            event = OTRV4_SMPEVENT_ABORT;

            break;
        }

        if (!event)
            event = OTRV4_SMPEVENT_IN_PROGRESS;

        handle_smp_event_cb(event, otr->smp->progress,
            otr->smp->msg1->question, otr);

        return to_send;
}

tlv_t *otrv4_smp_provide_secret(otrv4_t * otr, const uint8_t *secret,
    const size_t secretlen) {
    //TODO: If state is not CONTINUE_SMP then error.
    tlv_t *smp_reply = NULL;

    otr4_smp_event_t event = OTRV4_SMPEVENT_NONE;

    set_smp_secret(&otr->smp->y, secret, secretlen, false, otr);

    event = reply_with_smp_msg_2(&smp_reply, otr->smp->msg1, otr->smp);

    if (!event)
        event = OTRV4_SMPEVENT_IN_PROGRESS;

    //TODO: transition to state 1 if an abort happens
    if (event)
        handle_smp_event_cb(event, otr->smp->progress, otr->smp->msg1->question, otr);

    return smp_reply;
}
