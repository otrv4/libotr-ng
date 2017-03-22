#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "otrv4.h"
#include "otrv3.h"
#include "str.h"
#include "b64.h"
#include "deserialize.h"
#include "sha3.h"
#include "data_message.h"
#include "constants.h"
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

static void fingerprint_seen_cb(const otrv4_fingerprint_t fp,
				const otrv4_t * otr)
{
	if (!otr->callbacks)
		return;

	otr->callbacks->fingerprint_seen(fp, otr);
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

otrv4_t *otrv4_new(cs_keypair_s * keypair, otrv4_policy_t policy)
{
	otrv4_t *otr = malloc(sizeof(otrv4_t));
	if (otr == NULL) {
		return NULL;
	}

	otr->state = OTRV4_STATE_START;
	otr->supported_versions = policy.allows;

	otr->callbacks = NULL;
	otr->our_instance_tag = 0;
	otr->their_instance_tag = 0;
	otr->keypair = keypair;
	otr->running_version = OTRV4_VERSION_NONE;
	otr->profile = get_my_user_profile(otr);
	key_manager_init(otr->keys);

	return otr;
}

void otrv4_destroy( /*@only@ */ otrv4_t * otr)
{
	otr->keypair = NULL;
	key_manager_destroy(otr->keys);
	user_profile_free(otr->profile);
	otr->profile = NULL;
	otr->callbacks = NULL;
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
	if (allow_version(otr, OTRV4_ALLOW_V4)) {
		if (strstr(message, tag_version_v4)) {
			otr->running_version = OTRV4_VERSION_4;
			return;
		}
	}

	if (allow_version(otr, OTRV4_ALLOW_V3)) {
		if (strstr(message, tag_version_v3)) {
			otr->running_version = OTRV4_VERSION_3;
			return;
		}
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
	if (allow_version(otr, OTRV4_ALLOW_V4)) {
		if (strstr(message, "4")) {
			otr->running_version = OTRV4_VERSION_4;
			return;
		}
	}

	if (allow_version(otr, OTRV4_ALLOW_V3)) {
		if (strstr(message, "3")) {
			otr->running_version = OTRV4_VERSION_3;
			return;
		}
	}
}

static bool message_is_otr_encoded(const string_t message)
{
	return strstr(message, otr_header) != NULL;
}

otrv4_response_t *otrv4_response_new(void)
{
	otrv4_response_t *response = malloc(sizeof(otrv4_response_t));
	if (response == NULL) {
		return NULL;
	}

	response->to_display = NULL;
	response->to_send = NULL;
	response->warning = OTRV4_WARN_NONE;

	return response;
}

void otrv4_response_free(otrv4_response_t * response)
{
	if (response == NULL) {
		return;
	}

	free(response->to_send);
	response->to_send = NULL;

	free(response->to_display);
	response->to_display = NULL;

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

	ec_public_key_copy(m->Y, OUR_ECDH(otr));
	m->B = dh_mpi_copy(OUR_DH(otr));

	ok = serialize_and_encode_identity_message(&response->to_send, m);
	dake_identity_message_free(m);
	return ok;
}

static bool start_dake(otrv4_response_t * response, otrv4_t * otr)
{
	key_manager_generate_ephemeral_keys(otr->keys);
	otr->state = OTRV4_STATE_AKE_IN_PROGRESS;

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
		//message_to_display_without_tag(otr, message->raw_text, tag_version_v4);
		//TODO Do we exit(1)?
		break;
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
		//nothing to do
		break;
	}

	return false;
}

static bool
extract_header(otrv4_header_t * dst, const uint8_t * buffer,
	       const size_t bufflen)
{
	//TODO: check the length

	size_t read = 0;
	uint16_t version = 0;
	uint8_t type = 0;
	if (!deserialize_uint16(&version, buffer, bufflen, &read)) {
		return false;
	}

	buffer += read;

	if (!deserialize_uint8(&type, buffer, bufflen - read, &read)) {
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

static dake_dre_auth_t *otrv4_generate_dre_auth(const user_profile_t * their,
						const otrv4_t * otr)
{
	bool ok = false;
	dake_dre_auth_t *dre_auth = dake_dre_auth_new(otr->profile);

	ok = dake_dre_auth_generate_gamma_phi_sigma(otr->keypair, OUR_ECDH(otr),
						    OUR_DH(otr), their,
						    THEIR_ECDH(otr),
						    THEIR_DH(otr), dre_auth);

	if (!ok) {
		dake_dre_auth_free(dre_auth);
		dre_auth = NULL;
	}

	return dre_auth;
}

static bool
serialize_and_encode_dre_auth(string_t * dst, const dake_dre_auth_t * dre_auth)
{
	uint8_t *buff = NULL;
	size_t len = 0;

	if (!dake_dre_auth_aprint(&buff, &len, dre_auth))
		return false;

	*dst = otrl_base64_otr_encode(buff, len);
	free(buff);
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
reply_with_dre_auth_msg(string_t * dst, const user_profile_t * their,
			const otrv4_t * otr)
{
	bool ok = false;
	dake_dre_auth_t *m = otrv4_generate_dre_auth(their, otr);

	if (!m)
		return false;

	ok = serialize_and_encode_dre_auth(dst, m);
	dake_dre_auth_free(m);

	return ok;
}

static bool
receive_identity_message_on_state_start(string_t * dst,
					dake_identity_message_t *
					identity_message, otrv4_t * otr)
{
	if (!dake_identity_message_validate(identity_message))
		return false;

	key_manager_set_their_ecdh(identity_message->Y, otr->keys);
	key_manager_set_their_dh(identity_message->B, otr->keys);

	key_manager_generate_ephemeral_keys(otr->keys);
	if (!reply_with_dre_auth_msg(dst, identity_message->profile, otr))
		return false;

	return double_ratcheting_init(0, otr);
}

static bool
receive_identity_message(string_t * dst, uint8_t * buff, size_t buflen,
			 otrv4_t * otr)
{
	bool ok = false;
	dake_identity_message_t m[1];
	otrv4_fingerprint_t fp;

	if (!dake_identity_message_deserialize(m, buff, buflen))
		return false;

	if (otr->state == OTRV4_STATE_START)
		ok = receive_identity_message_on_state_start(dst, m, otr);

	if (ok && !otr4_serialize_fingerprint(fp, m->profile->pub_key))
		fingerprint_seen_cb(fp, otr);

	dake_identity_message_destroy(m);

	//TODO: other states
	return ok;
}

static bool
receive_dre_auth(string_t * dst, uint8_t * buff, size_t buflen, otrv4_t * otr)
{
	bool ok = false;
	dake_dre_auth_t dre_auth[1];
	ec_public_key_t their_ecdh;
	dh_public_key_t their_dh = NULL;

	*dst = NULL;

	if (otr->state != OTRV4_STATE_AKE_IN_PROGRESS)
		return true;

	if (!dake_dre_auth_deserialize(dre_auth, buff, buflen))
		return false;

	ok = dake_dre_auth_validate(their_ecdh, &their_dh, otr->profile,
				    otr->keypair, OUR_ECDH(otr), OUR_DH(otr),
				    dre_auth);
	dake_dre_auth_destroy(dre_auth);

	if (!ok)
		return false;

	key_manager_set_their_ecdh(their_ecdh, otr->keys);
	key_manager_set_their_dh(their_dh, otr->keys);
	dh_mpi_release(their_dh);

	return double_ratcheting_init(1, otr);
}

static bool
decrypt_data_msg(uint8_t ** dst, const m_enc_key_t enc_key,
		 const data_message_t * data_msg)
{
	uint8_t *plain = malloc(data_msg->enc_msg_len);
	if (plain == NULL)
		return false;

	if (0 !=
	    crypto_stream_xor(plain, data_msg->enc_msg, data_msg->enc_msg_len,
			      data_msg->nonce, enc_key)) {
		free(plain);
		return false;
	}

	*dst = plain;
	return true;
}

//TODO: This belongs to the key_manager
bool
derive_encription_and_mac_keys(m_enc_key_t enc_key, m_mac_key_t mac_key,
			       const chain_key_t chain_key)
{
	uint8_t magic1[1] = { 0x1 };
	if (!sha3_256_kdf
	    (enc_key, sizeof(m_enc_key_t), magic1, chain_key,
	     sizeof(chain_key_t))) {
		return false;
	}

	uint8_t magic2[1] = { 0x2 };
	if (!sha3_512_kdf
	    (mac_key, sizeof(m_mac_key_t), magic2, chain_key,
	     sizeof(chain_key_t))) {
		return false;
	}

	return true;
}

//TODO: This belongs to the key_manager
bool
retrieve_receiving_message_keys(m_enc_key_t enc_key, m_mac_key_t mac_key,
				int ratchet_id, int message_id,
				const otrv4_t * otr)
{
	chain_key_t receiving;
	if (!key_manager_get_receiving_chain_key_by_id
	    (receiving, ratchet_id, message_id, otr->keys)) {
		return false;
	}

	return derive_encription_and_mac_keys(enc_key, mac_key, receiving);
}

bool
otrv4_receive_data_message(otrv4_response_t * response, uint8_t * buff,
			   size_t buflen, otrv4_t * otr)
{
	response->to_display = NULL;
	response->to_send = NULL;
	response->warning = OTRV4_WARN_NONE;

	if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES) {
		//TODO: warn the user and send an error message with a code.
		return false;
	}

	data_message_t data_message[1];
	if (!data_message_deserialize(data_message, buff, buflen)) {
		return false;
	}

	key_manager_set_their_keys(data_message->our_ecdh, data_message->our_dh,
				   otr->keys);
	if (!key_manager_ensure_on_ratchet(data_message->ratchet_id, otr->keys))
		return false;

	m_enc_key_t enc_key;
	m_mac_key_t mac_key;

	if (!retrieve_receiving_message_keys
	    (enc_key, mac_key, data_message->ratchet_id,
	     data_message->message_id, otr)) {
		data_message_destroy(data_message);
		return false;
	}
#ifdef DEBUG
	printf("DECRYPTING\n");
	printf("enc_key = ");
	otrv4_memdump(enc_key, sizeof(m_enc_key_t));
	printf("mac_key = ");
	otrv4_memdump(mac_key, sizeof(m_mac_key_t));
	printf("nonce = ");
	otrv4_memdump(data_message->nonce, DATA_MSG_NONCE_BYTES);
#endif

	if (!data_message_validate(mac_key, data_message)) {
		data_message_destroy(data_message);
		return false;
	}

	if (!decrypt_data_msg
	    ((uint8_t **) & response->to_display, enc_key, data_message)) {
		data_message_destroy(data_message);
		return false;
	}
	//TODO: to_send = depends on the TLVs we proccess
	//TODO: Securely delete receiving chain keys older than message_id-1.
	//TODO: Add the MKmac key to list mac_keys_to_reveal.
	key_manager_prepare_to_ratchet(otr->keys);

	data_message_destroy(data_message);
	return true;
}

static bool
receive_encoded_message(otrv4_response_t * response,
			const string_t message, otrv4_t * otr, size_t msg_len)
{
	size_t dec_len = 0;
	uint8_t *decoded = NULL;
	int err = otrl_base64_otr_decode(message, &decoded, &dec_len);
	if (err) {
		return false;
	}
	if (dec_len > msg_len) {
		return false;
	}

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
	case OTR_PRE_KEY_MSG_TYPE:
		if (!receive_identity_message
		    (&response->to_send, decoded, dec_len, otr)) {
			free(decoded);
			return false;
		}
		break;
	case OTR_DRE_AUTH_MSG_TYPE:
		if (!receive_dre_auth
		    (&response->to_send, decoded, dec_len, otr)) {
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

static otrv4_in_message_type_t get_message_type(const string_t message)
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

//TODO: This belongs to the key_manager
static int
retrieve_sending_message_keys(m_enc_key_t enc_key, m_mac_key_t mac_key,
			      const otrv4_t * otr)
{
	chain_key_t sending;
	int message_id = key_manager_get_sending_chain_key(sending, otr->keys);

	if (!derive_encription_and_mac_keys(enc_key, mac_key, sending)) {
		return -1;
	}

	return message_id;
}

//TODO: This belongs to the key_manager
static bool should_ratchet(const otrv4_t * otr)
{
	return otr->keys->j == 0;
}

static bool
send_data_message(uint8_t ** to_send, const uint8_t * message,
		  size_t message_len, otrv4_t * otr)
{
	if (should_ratchet(otr)) {
		if (!key_manager_rotate_keys(otr->keys))
			return false;
	} else {
		if (!key_manager_derive_sending_chain_key(otr->keys))
			return false;
	}

	m_enc_key_t enc_key;
	m_mac_key_t mac_key;

	int message_id = retrieve_sending_message_keys(enc_key, mac_key, otr);
	if (message_id < 0) {
		return false;
	}
	//TODO: assert
	//if (message_id != otr->keys->j) return false;

#ifdef DEBUG
	printf("ENCRYPTING\n");
	printf("enc_key = ");
	otrv4_memdump(enc_key, sizeof(m_enc_key_t));
	printf("mac_key = ");
	otrv4_memdump(mac_key, sizeof(m_mac_key_t));
#endif

	data_message_t *data_msg = data_message_new();
	if (data_msg == NULL)
		return false;

	data_msg->sender_instance_tag = otr->our_instance_tag;
	data_msg->receiver_instance_tag = otr->their_instance_tag;
	data_msg->ratchet_id = otr->keys->current->id;
	data_msg->message_id = message_id;
	ec_public_key_copy(data_msg->our_ecdh, OUR_ECDH(otr));
	data_msg->our_dh = dh_mpi_copy(OUR_DH(otr));

	random_bytes(data_msg->nonce, sizeof(data_msg->nonce));
	uint8_t *c = malloc(message_len);
	if (c == NULL) {
		data_message_free(data_msg);
		return false;
	}

	if (0 !=
	    crypto_stream_xor(c, message, message_len, data_msg->nonce,
			      enc_key)) {
		free(c);
		data_message_free(data_msg);
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

	uint8_t *body = NULL;
	size_t bodylen = 0;
	if (!data_message_body_aprint(&body, &bodylen, data_msg)) {
		data_message_free(data_msg);
		return false;
	}

	data_message_free(data_msg);

	//TODO: append old mac keys to be revealed
	size_t serlen = bodylen + DATA_MSG_MAC_BYTES;
	uint8_t *ser = malloc(serlen);
	if (ser == NULL) {
		free(body);
		return false;
	}

	memcpy(ser, body, bodylen);
	free(body);

	if (!sha3_512_mac
	    (ser + bodylen, DATA_MSG_MAC_BYTES, mac_key, sizeof(m_mac_key_t),
	     ser, bodylen)) {
		free(ser);
		return false;
	}
	//TODO: Change the spec to say this should be incremented after the message
	//is sent.
	otr->keys->j++;

	*to_send = (uint8_t *) otrl_base64_otr_encode(ser, serlen);
	free(ser);
	return true;
}

bool
otrv4_send_message(uint8_t ** to_send, const uint8_t * message,
		   size_t message_len, otrv4_t * otr)
{
	if (otr->state == OTRV4_STATE_FINISHED)
		return false;	//Should restart

	if (otr->state != OTRV4_STATE_ENCRYPTED_MESSAGES)
		return false;	//TODO: queue message

	return send_data_message(to_send, message, message_len, otr);
}
