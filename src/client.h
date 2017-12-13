#ifndef OTR4_CLIENT_H
#define OTR4_CLIENT_H

#define OTR4_CLIENT_ERROR_NOT_ENCRYPTED 0x1001
// TODO: check the error codes on client
#define OTR4_CLIENT_ERROR_MSG_NOT_VALID 0x1011

#include <libotr/context.h>

#include "client_state.h"
#include "list.h"
#include "otrv4.h"

// TODO: REMOVE
typedef struct {
  void *conversation_id; /* Data in the messaging application context that
                          represents a conversation and should map directly to
                          it. For example, in libpurple-based apps (like
                          Pidgin) this could be a PurpleConversation */

  char *recipient;
  otrv4_t *conn;
} otr4_conversation_t;

/* A client handle messages from/to a sender to/from multiple recipients. */
typedef struct {
  otr4_client_state_t *state;
  list_element_t *conversations;
} otr4_client_t;

otr4_client_t *otr4_client_new(otr4_client_state_t *);

void otr4_client_free(otr4_client_t *client);

char *otr4_client_query_message(const char *recipient, const char *message,
                                otr4_client_t *client);

int otr4_client_send(char **newmessage, const char *message,
                     const char *recipient, otr4_client_t *client);

int otr4_client_send_fragment(otr4_message_to_send_t **newmessage,
                              const char *message, int mms,
                              const char *recipient, otr4_client_t *client);

int otr4_client_smp_start(char **tosend, const char *recipient,
                          const char *question, const size_t q_len,
                          const unsigned char *secret, size_t secretlen,
                          otr4_client_t *client);

int otr4_client_smp_respond(char **tosend, const char *recipient,
                            const unsigned char *secret, size_t secretlen,
                            otr4_client_t *client);

int otr4_client_receive(char **newmsg, char **todisplay, const char *message,
                        const char *recipient, otr4_client_t *client);

int otr4_client_disconnect(char **newmsg, const char *recipient,
                           otr4_client_t *client);

int otr4_encrypted_conversation_expire(char **newmsg, const char *recipient,
                                       int expiration_time,
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
