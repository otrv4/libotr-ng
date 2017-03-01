#ifndef OTR4_CLIENT_H
#define OTR4_CLIENT_H

#include "otrv4.h"
#include "list.h"

typedef struct {
  char *recipient;
  otrv4_t *conn;

  //const char* accountname;
  //const char* proto; //???
  //otrl_instag_t their_instance;
  //otrl_instag_t our_instance;
} otr4_conversation_t;

typedef struct {
  /* A conversation has entered a secure state. */
  void (*gone_secure)(const otr4_conversation_t *conv);

  /* A conversation has left a secure state. */
  void (*gone_insecure)(const otr4_conversation_t *conv);
} otr4_client_callbacks_t;

//A client handle messages from/to a sender to/from multiple recipients.
typedef struct {
  otr4_client_callbacks_t *callbacks;

  cs_keypair_t keypair;
  list_element_t* conversations;
} otr4_client_t;

otr4_client_t*
otr4_client_new();

void
otr4_client_free(otr4_client_t *client);

char*
otr4_client_query_message(const char *recipient,
                          const char* message,
                          otr4_client_t *client);

int
otr4_client_send(char **newmessage,
                 const char *message,
                 const char *recipient,
                 otr4_client_t *client);

int
otr4_client_receive(char **newmessage,
                    char **todisplay,
                    const char *message,
                    const char *recipient,
                    otr4_client_t *client);

otr4_conversation_t*
otr4_client_get_conversation(int force, const char *recipient, otr4_client_t *client);

#endif
