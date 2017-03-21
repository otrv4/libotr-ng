#include "client.h"

#include "str.h"
#include "serialize.h"
#include "sha3.h"
#include "cramershoup_interface.h"

void conversation_free(otr4_conversation_t * conv)
{
	otrv4_free(conv->conn);
	conv->conn = NULL;

	free(conv->recipient);
	conv->recipient = NULL;
}

otr4_client_t *otr4_client_new(cs_keypair_s * keypair)
{
	otr4_client_t *client = malloc(sizeof(otr4_client_t));
	if (!client)
		return NULL;

	client->keypair = keypair;
	client->conversations = NULL;
	client->callbacks = NULL;

	return client;
}

void otr4_client_free(otr4_client_t * client)
{
	list_foreach(client->conversations, c, {
		     conversation_free((otr4_conversation_t *) c->data);
		     c->data = NULL;
		     });
	list_free_all(client->conversations);
	client->conversations = NULL;
	client->keypair = NULL;

	free(client);
}

otr4_conversation_t *get_conversation_with(const char *recipient,
					   list_element_t * conversations)
{
	otr4_conversation_t *conv = NULL;
	list_foreach(conversations, c, {
		     conv = (otr4_conversation_t *) c->data;
		     if (!strcmp(conv->recipient, recipient)) {
		     return conv;}
		     }
	) ;

	return NULL;
}

otrv4_policy_t get_policy_for(const char *recipient)
{
	//TODO the policy should come from client config.
	otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4
	};

	return policy;
}

otr4_conversation_t *new_conversation_with(const char *recipient)
{
	otr4_conversation_t *conv = NULL;

	conv = malloc(sizeof(otr4_conversation_t));
	if (!conv)
		return NULL;

	conv->recipient = otrv4_strdup(recipient);
	return conv;
}

static otrv4_t *create_connection_for(const char *recipient,
				      otr4_client_t * client)
{
	otrv4_t *conn = NULL;
	conn = otrv4_new(client->keypair, get_policy_for(recipient));
	if (!conn)
		return NULL;

	conn->callbacks = client->callbacks;

	return conn;
}

otr4_conversation_t *get_or_create_conversation_with(const char *recipient,
						     otr4_client_t * client)
{
	otr4_conversation_t *conv = NULL;
	otrv4_t *conn = NULL;

	conv = get_conversation_with(recipient, client->conversations);
	if (conv)
		return conv;

	if (!client->keypair)
		return NULL;

	conn = create_connection_for(recipient, client);
	if (!conn)
		return NULL;

	conv = new_conversation_with(recipient);
	if (!conv) {
		free(conn);
		return NULL;
	}

	conv->conn = conn;
	client->conversations = list_add(conv, client->conversations);

	return conv;
}

otr4_conversation_t *otr4_client_get_conversation(int force,
						  const char *recipient,
						  otr4_client_t * client)
{
	if (force)
		return get_or_create_conversation_with(recipient, client);

	return get_conversation_with(recipient, client->conversations);
}

int
otr4_client_send(char **newmessage, const char *message,
		 const char *recipient, otr4_client_t * client)
{
	*newmessage = NULL;
	otr4_conversation_t *conv = NULL;

	conv = get_or_create_conversation_with(recipient, client);
	if (conv->conn->state != OTRV4_STATE_ENCRYPTED_MESSAGES) {
		// Cant send a message while not in OTRV4_STATE_ENCRYPTED_MESSAGES
		//TODO: Store the message for retransmition if not FINISHED
		//TODO: Add notifications (like "tried to send a message while not in encrypted")
		return 1;
	}

	return otrv4_send_message((uint8_t **) newmessage, (uint8_t *) message,
				  strlen(message) + 1, conv->conn);
}

int
otr4_client_receive(char **newmessage, char **todisplay, const char *message,
		    const char *recipient, otr4_client_t * client)
{
	otr4_conversation_t *conv = NULL;
	bool ok = false;
	otrv4_response_t *response = otrv4_response_new();

	*newmessage = NULL;
	*todisplay = NULL;

	conv = get_or_create_conversation_with(recipient, client);
	ok = otrv4_receive_message(response, message, strlen(message),
				   conv->conn);
	if (!ok) {
		otrv4_response_free(response);
		return 0;	//Should this cause the message to be ignored or not?
	}

	if (response->to_send)
		*newmessage = otrv4_strdup(response->to_send);

	int should_ignore = 1;
	if (response->to_display) {
		char *plain = otrv4_strdup(response->to_display);
		*todisplay = plain;
		should_ignore = 0;
	}

	otrv4_response_free(response);
	return should_ignore;
}

char *otr4_client_query_message(const char *recipient, const char *message,
				otr4_client_t * client)
{
	otr4_conversation_t *conv =
	    get_or_create_conversation_with(recipient, client);

	//TODO: implement policy
	char *ret = NULL;
	otrv4_build_query_message(&ret, conv->conn, (const string_t)message,
				  strlen(message));
	return ret;
}

void
otr4_client_disconnect(char **newmessage, const char *recipient,
		       otr4_client_t * client)
{
	//TODO
}

uint8_t *otr4_client_get_our_fingerprint(const otr4_client_t * client)
{
	uint8_t serialized[170] = { 0 };
	uint8_t *ser = NULL;

	if (!client->keypair)
		return NULL;

	ser = malloc(64);
	if (!ser)
		return NULL;

	//TODO: do we need to check anything? 
	serialize_cs_public_key(serialized, client->keypair->pub);

	if (sha3_512(ser, 64, serialized, sizeof(serialized)))
		return ser;

	free(ser);
	return NULL;
}

int otr4_privkey_generate_FILEp(const otr4_client_t * client, FILE * privf)
{
	char *buff = NULL;
	size_t s = 0;
	int err = 0;

	if (!privf)
		return -1;

	if (!client->keypair)
		return -2;

	err = cs_serialize_private_key(&buff, &s, client->keypair->priv);
	if (err)
		return err;

	if (1 != fwrite(buff, s, 1, privf))
		return -3;

	return 0;
}

static cs_keypair_s *new_keypair()
{
	cs_keypair_s *pair = NULL;

	pair = malloc(sizeof(cs_keypair_s));
	if (pair)
		cs_keypair_destroy(pair);

	return pair;
}

int otr4_read_privkey_FILEp(otr4_client_t * client, FILE * privf)
{
	if (!privf)
		return -1;

	if (!client->keypair)
		client->keypair = new_keypair();

	if (!client->keypair)
		return -2;

	if (cs_deserialize_private_key_FILEp(client->keypair->priv, privf)) {
		cs_keypair_destroy(client->keypair);
		free(client->keypair);
		client->keypair = NULL;
		return -3;
	}

	cs_keypair_derive_public_key(client->keypair);
	return 0;
}

/* Convert a 64-byte hash value to a 145-byte human-readable value */
void
otr4_fingerprint_hash_to_human(char human[OTR4_FPRINT_HUMAN_LEN],
			       const unsigned char hash[OTR4_FPRINT_LEN_BYTES])
{
	int word, byte;
	char *p = human;

	for (word = 0; word < 16; ++word) {
		for (byte = 0; byte < 4; ++byte) {
			sprintf(p, "%02X", hash[word * 4 + byte]);
			p += 2;
		}
		*(p++) = ' ';
	}

	/* Change that last ' ' to a '\0' */
	--p;
	*p = '\0';
}
