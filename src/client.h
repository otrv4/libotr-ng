#ifndef OTRV4_CLIENT_H
#define OTRV4_CLIENT_H

#define CLIENT_ERROR_NOT_ENCRYPTED 0x1001
// TODO: check the error codes on client
#define CLIENT_ERROR_MSG_NOT_VALID 0x1011

#include <libotr/context.h>

#include "client_state.h"
#include "list.h"
#include "otrv4.h"
#include "shared.h"

// TODO: REMOVE
typedef struct {
  void *conversation_id; /* Data in the messaging application context that
                          represents a conversation and should map directly to
                          it. For example, in libpurple-based apps (like
                          Pidgin) this could be a PurpleConversation */

  char *recipient;
  otrv4_t *conn;
} otrv4_conversation_t;

/* A client handle messages from/to a sender to/from multiple recipients. */
typedef struct {
  otrv4_client_state_t *state;
  list_element_t *conversations;
} otrv4_client_t;

API otrv4_client_t *otrv4_client_new(otrv4_client_state_t *);

API void otrv4_client_free(otrv4_client_t *client);

API char *otrv4_client_query_message(const char *recipient, const char *message,
                                     otrv4_client_t *client, OtrlPolicy policy);

API int otrv4_client_send(char **newmessage, const char *message,
                          const char *recipient, otrv4_client_t *client);

API int otrv4_client_send_fragment(otrv4_message_to_send_t **newmessage,
                                   const char *message, int mms,
                                   const char *recipient,
                                   otrv4_client_t *client);

/* tstatic int otr4_client_smp_start(char **tosend, const char *recipient, */
/*                           const char *question, const size_t q_len, */
/*                           const unsigned char *secret, size_t secretlen, */
/*                           otrv4_client_t *client); */

/* tstatic int otr4_client_smp_respond(char **tosend, const char *recipient, */
/*                             const unsigned char *secret, size_t secretlen, */
/*                             otrv4_client_t *client); */

API int otrv4_client_receive(char **newmsg, char **todisplay,
                             const char *message, const char *recipient,
                             otrv4_client_t *client);

API int otrv4_client_disconnect(char **newmsg, const char *recipient,
                                otrv4_client_t *client);

/* tstatic int otr4_encrypted_conversation_expire(char **newmsg, const char
 * *recipient, */
/*                                        int expiration_time, */
/*                                        otrv4_client_t *client); */

API otrv4_conversation_t *otrv4_client_get_conversation(int force,
                                                        const char *recipient,
                                                        otrv4_client_t *client);

/* tstatic int otr4_conversation_is_encrypted(otrv4_conversation_t *conv); */

/* tstatic int otr4_conversation_is_finished(otrv4_conversation_t *conv); */

API int otrv4_client_get_our_fingerprint(otrv4_fingerprint_t fp,
                                         const otrv4_client_t *client);

/* tstatic int otr3_privkey_generate(otrv4_client_t *client, FILE *privf); */

/* tstatic int otr3_instag_generate(otrv4_client_t *client, FILE *privf); */

#ifdef OTRV4_CLIENT_PRIVATE
#endif

#endif
