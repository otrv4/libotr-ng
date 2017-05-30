#ifndef OTR4_CLIENT_H
#define OTR4_CLIENT_H

#define OTR4_CLIENT_ERROR_NOT_ENCRYPTED 0x1001

#include <libotr/context.h>

#include "otrv4.h"
#include "list.h"

typedef struct {
	char *recipient;
	otrv4_t *conn;
} otr4_conversation_t;

//A client handle messages from/to a sender to/from multiple recipients.
typedef struct {
	const otrv4_callbacks_t *callbacks;

        char *account;
        char *protocol;
        OtrlUserState userstate;

	otrv4_keypair_t *keypair;
	list_element_t *conversations;
} otr4_client_t;

otr4_client_t *otr4_client_new(otrv4_keypair_t * keypair, const char *protocol, const char *account);

void otr4_client_free(otr4_client_t * client);

char *otr4_client_query_message(const char *recipient, const char *message,
				otr4_client_t * client);

int
otr4_client_send(char **newmessage, const char *message, const char *recipient,
		 otr4_client_t * client);

int otr4_client_smp_start(char **tosend, const char *recipient,
    const char *question, const unsigned char *secret, size_t secretlen,
    otr4_client_t * client);

int otr4_client_smp_respond(char **tosend, const char *recipient,
    const unsigned char *secret, size_t secretlen, otr4_client_t * client);

int
otr4_client_receive(char **newmessage, char **todisplay, const char *message,
		    const char *recipient, otr4_client_t * client);

int
otr4_client_disconnect(char **newmessage, const char *recipient,
		       otr4_client_t * client);

otr4_conversation_t *otr4_client_get_conversation(int force,
						  const char *recipient,
						  otr4_client_t * client);

int
otr4_client_get_our_fingerprint(otrv4_fingerprint_t fp,
				const otr4_client_t * client);

int otr4_read_privkey_FILEp(otr4_client_t * client, FILE * privf);

#endif
