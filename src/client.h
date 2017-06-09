#ifndef OTR4_CLIENT_H
#define OTR4_CLIENT_H

#define OTR4_CLIENT_ERROR_NOT_ENCRYPTED 0x1001

#include <libotr/context.h>

#include "client_state.h"
#include "instance_tag.h"
#include "list.h"
#include "otrv4.h"

// TODO: REMOVE
typedef struct {
  void *conversation_id; // Data in the messaging application context that
                         // represents a conversation and should map directly to
                         // it. For example, in libpurple-based apps (like
                         // Pidgin) this could be a PurpleConversation*

  char *recipient;
  otrv4_t *conn;
} otr4_conversation_t;

// A client handle messages from/to a sender to/from multiple recipients.
typedef struct {
  char *account;  // TODO: move to client_state?
  char *protocol; // TODO: move to client_state?
  otr4_client_state_t *state;

  list_element_t *conversations;
} otr4_client_t;

otr4_client_t *otr4_client_new(otr4_client_state_t *, const char *protocol,
                               const char *account, FILE *instag_file);

void otr4_client_free(otr4_client_t *client);

int otr4_client_generate_keypair(otr4_client_t *client);

char *otr4_client_query_message(const char *recipient, const char *message,
                                otr4_client_t *client);

int otr4_client_send(char **newmessage, const char *message,
                     const char *recipient, otr4_client_t *client);

int otr4_client_smp_start(char **tosend, const char *recipient,
                          const char *question, const unsigned char *secret,
                          size_t secretlen, otr4_client_t *client);

int otr4_client_smp_respond(char **tosend, const char *recipient,
                            const unsigned char *secret, size_t secretlen,
                            otr4_client_t *client);

int otr4_client_receive(char **newmessage, char **todisplay,
                        const char *message, const char *recipient,
                        otr4_client_t *client);

int otr4_client_disconnect(char **newmessage, const char *recipient,
                           otr4_client_t *client);

otr4_conversation_t *otr4_client_get_conversation(int force,
                                                  const char *recipient,
                                                  otr4_client_t *client);

int otr4_conversation_is_encrypted(otr4_conversation_t *conv);

int otr4_conversation_is_finished(otr4_conversation_t *conv);

int otr4_client_get_our_fingerprint(otrv4_fingerprint_t fp,
                                    const otr4_client_t *client);

int otr3_privkey_generate(otr4_client_t *client, FILE *privf);

int otr3_instag_generate(otr4_client_t *client, FILE *privf);

#endif
