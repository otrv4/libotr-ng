#ifndef OTR4_CLIENT_H
#define OTR4_CLIENT_H

#include "otrv4.h"
#include "list.h"

#define OTR4_FPRINT_LEN_BYTES 64
#define OTR4_FPRINT_HUMAN_LEN 64/4*9 + 1

typedef struct {
	char *recipient;
	otrv4_t *conn;

	//const char* accountname;
	//const char* proto; //???
	//otrl_instag_t their_instance;
	//otrl_instag_t our_instance;
} otr4_conversation_t;

//A client handle messages from/to a sender to/from multiple recipients.
typedef struct {
	otrv4_callbacks_t *callbacks;

	cs_keypair_s *keypair;
	list_element_t *conversations;
} otr4_client_t;

void conversation_free(otr4_conversation_t * conv);

otr4_client_t *otr4_client_new(cs_keypair_s * keypair);

void otr4_client_free(otr4_client_t * client);

char *otr4_client_query_message(const char *recipient,
				const char *message, otr4_client_t * client);

int
otr4_client_send(char **newmessage,
		 const char *message,
		 const char *recipient, otr4_client_t * client);

int
otr4_client_receive(char **newmessage,
		    char **todisplay,
		    const char *message,
		    const char *recipient, otr4_client_t * client);

void
otr4_client_disconnect(char **newmessage,
		       const char *recipient, otr4_client_t * client);

otr4_conversation_t *otr4_client_get_conversation(int force,
						  const char *recipient,
						  otr4_client_t * client);

uint8_t *otr4_client_get_our_fingerprint(const otr4_client_t * client);

int otr4_privkey_generate_FILEp(const otr4_client_t * client, FILE * privf);
int otr4_read_privkey_FILEp(otr4_client_t * client, FILE * privf);

void otr4_fingerprint_hash_to_human(char human[OTR4_FPRINT_HUMAN_LEN],
				    const unsigned char
				    hash[OTR4_FPRINT_LEN_BYTES]);

#endif
