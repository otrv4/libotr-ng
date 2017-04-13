#include "client.h"

#include "str.h"
#include "serialize.h"
#include "sha3.h"

#define CONV(c) ((otr4_conversation_t *) c)

static otr4_conversation_t *new_conversation_with(const char *recipient)
{
	otr4_conversation_t *conv = malloc(sizeof(otr4_conversation_t));
	if (!conv)
		return NULL;

	conv->recipient = otrv4_strdup(recipient);
	return conv;
}

static void conversation_free(otr4_conversation_t * conv)
{
	otrv4_free(conv->conn);
	conv->conn = NULL;

	free(conv->recipient);
	conv->recipient = NULL;

	free(conv);
}

otr4_client_t *otr4_client_new(otrv4_keypair_t * keypair)
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
	list_element_t *el;
	for (el = client->conversations; el; el = el->next) {
		conversation_free(CONV(el->data));
		el->data = NULL;
	}

	list_free_all(client->conversations);
	client->conversations = NULL;
	client->keypair = NULL;

	free(client);
}

otr4_conversation_t *get_conversation_with(const char *recipient,
					   list_element_t * conversations)
{
	list_element_t *el;
	for (el = conversations; el; el = el->next) {
		otr4_conversation_t *conv = CONV(el->data);
		if (!strcmp(conv->recipient, recipient))
			return conv;
	}

	return NULL;
}

otrv4_policy_t get_policy_for(const char *recipient)
{
	//TODO the policy should come from client config.
	otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4
	};

	return policy;
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

	return otrv4_send_message(newmessage, message, NULL, conv->conn);
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
	otr4_conversation_t *conv = NULL;
	char *ret = NULL;

	conv = get_or_create_conversation_with(recipient, client);

	//TODO: implement policy
	otrv4_build_query_message(&ret, message, conv->conn);
	return ret;
}

int
otr4_client_disconnect(char **newmessage, const char *recipient,
		       otr4_client_t * client)
{
	*newmessage = NULL;
	otr4_conversation_t *conv = NULL;

	conv = get_conversation_with(recipient, client->conversations);
	if (!conv)
		return 1;

	if (!otrv4_close(newmessage, conv->conn))
		return 2;

	//TODO: Should we NOT remove the closed conversation?
	list_element_t *elem = list_get_by_value(conv, client->conversations);
	client->conversations =
	    list_remove_element(elem, client->conversations);

	elem->next = NULL;
	conversation_free(conv);
	list_free_all(elem);

	return 0;
}

int otr4_client_get_our_fingerprint(otrv4_fingerprint_t fp,
				    const otr4_client_t * client)
{
	if (!client->keypair)
		return -1;

	return otr4_serialize_fingerprint(fp, client->keypair->pub);
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

        //TODO: serialie otrv4 private key
	//err = cs_serialize_private_key(&buff, &s, client->keypair->priv);
	if (err)
		return err;

	if (1 != fwrite(buff, s, 1, privf))
		return -3;

	return 0;
}

int otr4_read_privkey_FILEp(otr4_client_t * client, FILE * privf)
{
	if (!privf)
		return -1;

	if (!client->keypair)
		client->keypair = otrv4_keypair_new();

	if (!client->keypair)
		return -2;

        //TODO: deserialize private key
	//if (cs_deserialize_private_key_FILEp(client->keypair->priv, privf)) {
	//	cs_keypair_destroy(client->keypair);
	//	free(client->keypair);
	//	client->keypair = NULL;
	//	return -3;
	//}

	//cs_keypair_derive_public_key(client->keypair);
	return 0;
}
