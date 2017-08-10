#include "client.h"

#include <libotr/privkey.h>

#include "deserialize.h"
#include "instance_tag.h"
#include "serialize.h"
#include "sha3.h"
#include "str.h"

#define CONV(c) ((otr4_conversation_t *)c)

static otr4_conversation_t *new_conversation_with(const char *recipient,
                                                  otrv4_t *conn) {
  otr4_conversation_t *conv = malloc(sizeof(otr4_conversation_t));
  if (!conv) {
    free(conn);
    return NULL;
  }

  conv->recipient = otrv4_strdup(recipient);
  conv->conn = conn;

  return conv;
}

static void conversation_free(void *data) {
  otr4_conversation_t *conv = data;

  free(conv->recipient);
  conv->recipient = NULL;

  otrv4_free(conv->conn);
  conv->conn = NULL;

  free(conv);
}

otr4_client_t *otr4_client_new(otr4_client_state_t *state) {
  otr4_client_t *client = malloc(sizeof(otr4_client_t));
  if (!client)
    return NULL;

  client->state = state;
  client->conversations = NULL;

  return client;
}

void otr4_client_free(otr4_client_t *client) {
  if (!client)
    return;

  client->state = NULL;

  list_free(client->conversations, conversation_free);
  client->conversations = NULL;

  free(client);
}

// TODO: There may be multiple conversations with the same recipient if they
// uses multiple instance tags. We are not allowing this yet.
otr4_conversation_t *get_conversation_with(const char *recipient,
                                           list_element_t *conversations) {
  const list_element_t *el = NULL;
  otr4_conversation_t *conv = NULL;

  for (el = conversations; el; el = el->next) {
    conv = CONV(el->data);
    if (!strcmp(conv->recipient, recipient))
      return conv;
  }

  return NULL;
}

otrv4_policy_t get_policy_for(const char *recipient) {
  // TODO the policy should come from client config.
  otrv4_policy_t policy = {.allows = OTRV4_ALLOW_V3 | OTRV4_ALLOW_V4};

  return policy;
}

int otr4_conversation_is_encrypted(otr4_conversation_t *conv) {
  if (!conv)
    return 0;

  switch (conv->conn->running_version) {
  case OTRV4_VERSION_NONE:
    return 0;
  case OTRV4_VERSION_4:
    return conv->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES;
  case OTRV4_VERSION_3:
    return conv->conn->otr3_conn->ctx->msgstate == OTRL_MSGSTATE_ENCRYPTED;
  }

  return 0;
}

int otr4_conversation_is_finished(otr4_conversation_t *conv) {
  if (!conv)
    return 0;

  switch (conv->conn->running_version) {
  case OTRV4_VERSION_NONE:
    return 0;
  case OTRV4_VERSION_4:
    return conv->conn->state == OTRV4_STATE_FINISHED;
  case OTRV4_VERSION_3:
    return conv->conn->otr3_conn->ctx->msgstate == OTRL_MSGSTATE_FINISHED;
  }

  return 0;
}

static otrv4_t *create_connection_for(const char *recipient,
                                      otr4_client_t *client) {
  otr3_conn_t *otr3_conn = NULL;
  otrv4_t *conn = NULL;

  // TODO: This should receive only the client_state (which should allow
  // you to get protocol, account, v3 userstate, etc)
  otr3_conn = otr3_conn_new(client->state, recipient);
  if (!otr3_conn)
    return NULL;

  conn = otrv4_new(client->state, get_policy_for(recipient));
  if (!conn) {
    free(otr3_conn);
    return NULL;
  }

  conn->conversation->peer = otrv4_strdup(recipient);
  otr3_conn->opdata = conn; /* For use in callbacks */
  conn->otr3_conn = otr3_conn;

  return conn;
}

otr4_conversation_t *get_or_create_conversation_with(const char *recipient,
                                                     otr4_client_t *client) {
  otr4_conversation_t *conv = NULL;
  otrv4_t *conn = NULL;

  conv = get_conversation_with(recipient, client->conversations);
  if (conv)
    return conv;

  conn = create_connection_for(recipient, client);
  if (!conn)
    return NULL;

  conv = new_conversation_with(recipient, conn);
  if (!conv)
    return NULL;

  client->conversations = list_add(conv, client->conversations);

  return conv;
}

otr4_conversation_t *otr4_client_get_conversation(int force_create,
                                                  const char *recipient,
                                                  otr4_client_t *client) {
  if (force_create)
    return get_or_create_conversation_with(recipient, client);

  return get_conversation_with(recipient, client->conversations);
}

static int otrv4_send_message(char **newmsg, const char *message,
                              const char *recipient, otr4_client_t *client) {
  otr4_conversation_t *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return 1;

  otr4_err_t error = otrv4_prepare_to_send_message(newmsg, message, NULL, conv->conn);
  if (error == OTR4_STATE_NOT_ENCRYPTED)
    return OTR4_CLIENT_ERROR_NOT_ENCRYPTED;
  else
    return OTR4_SUCCESS != error;
}

int otr4_client_send(char **newmessage, const char *message,
                     const char *recipient, otr4_client_t *client) {
  /* OTR4 client will know how to transition to OTR3 if a v3 conversation is
   started */
  return otrv4_send_message(newmessage, message, recipient, client);
}

int otr4_client_send_fragment(otr4_message_to_send_t **newmessage,
                              const char *message, int mms,
                              const char *recipient, otr4_client_t *client) {
  string_t to_send = NULL;
  otr4_err_t err = otrv4_send_message(&to_send, message, recipient, client);
  if (err != OTR4_SUCCESS)
    return 1;

  otr4_conversation_t *conv = NULL;
  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return 1;

  uint32_t ourtag = conv->conn->our_instance_tag;
  uint32_t theirtag = conv->conn->their_instance_tag;
  err = otr4_fragment_message(mms, *newmessage, ourtag, theirtag, to_send);
  free(to_send);

  return err != OTR4_SUCCESS;
}

int otr4_client_smp_start(char **tosend, const char *recipient,
                          const char *question, const size_t q_len,
                          const unsigned char *secret, size_t secretlen,
                          otr4_client_t *client) {
  otr4_conversation_t *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return 1;

  if (otrv4_smp_start(tosend, question, q_len, secret, secretlen, conv->conn))
    return 1;

  return 0;
}

int otr4_client_smp_respond(char **tosend, const char *recipient,
                            const unsigned char *secret, size_t secretlen,
                            otr4_client_t *client) {
  otr4_conversation_t *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return 1;

  if (otrv4_smp_continue(tosend, secret, secretlen, conv->conn))
    return 1;

  return 0;
}

static int unfragment(char **unfragmented, const char *received,
                      fragment_context_t *ctx, int our_instance_tag) {
  otr4_err_t err = otr4_unfragment_message(unfragmented, ctx, received, our_instance_tag);
  return err != OTR4_SUCCESS || ctx->status == OTR4_FRAGMENT_INCOMPLETE;
}

int otr4_client_receive(char **newmessage, char **todisplay,
                        const char *message, const char *recipient,
                        otr4_client_t *client) {
  otr4_err_t err = OTR4_ERROR;
  char *unfrag_msg = NULL;
  int should_ignore = 1;
  otrv4_response_t *response = NULL;
  otr4_conversation_t *conv = NULL;

  if (!newmessage)
    return err;

  *newmessage = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return should_ignore;

  if (unfragment(&unfrag_msg, message, conv->conn->frag_ctx, conv->conn
		 ->our_instance_tag))
    return should_ignore;

  response = otrv4_response_new();
  err = otrv4_receive_message(response, unfrag_msg, conv->conn);
  free(unfrag_msg);

  if (response->to_send)
    *newmessage = otrv4_strdup(response->to_send);

  *todisplay = NULL;
  if (response->to_display) {
    char *plain = otrv4_strdup(response->to_display);
    *todisplay = plain;
    otrv4_response_free(response);
    return !should_ignore;
  }

  otrv4_response_free(response);

  if (err != OTR4_SUCCESS)
    return !should_ignore; // Should this cause the message to be ignored or
                           // not?

  return should_ignore;
}

char *otr4_client_query_message(const char *recipient, const char *message,
                                otr4_client_t *client) {
  otr4_conversation_t *conv = NULL;
  char *ret = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return NULL;

  // TODO: implement policy
  // TODO: Check for errors when calling this function
  otrv4_build_query_message(&ret, message, conv->conn);
  return ret;
}

static void destroy_client_conversation(const otr4_conversation_t *conv,
                                        otr4_client_t *client) {
  list_element_t *elem = list_get_by_value(conv, client->conversations);
  client->conversations = list_remove_element(elem, client->conversations);
  list_free_nodes(elem);
}

int otr4_client_disconnect(char **newmsg, const char *recipient,
                           otr4_client_t *client) {
  otr4_conversation_t *conv = NULL;

  conv = get_conversation_with(recipient, client->conversations);
  if (!conv)
    return 1;

  if (otrv4_close(newmsg, conv->conn))
    return 2;

  destroy_client_conversation(conv, client);
  conversation_free(conv);
  conv = NULL;

  return 0;
}

int otr4_client_get_our_fingerprint(otrv4_fingerprint_t fp,
                                    const otr4_client_t *client) {
  if (!client->state->keypair)
    return -1;

  return otr4_serialize_fingerprint(fp, client->state->keypair->pub);
}

// TODO: Read privkeys, fingerprints, instance tags for OTRv3
/*
 *To read stored private keys:

    otrl_privkey_read(userstate, privkeyfilename);

To read stored instance tags:

    otrl_instag_read(userstate, instagfilename);

        To read stored fingerprints:

    otrl_privkey_read_fingerprints(userstate, fingerprintfilename,
            add_app_info, add_app_info_data);
*/

int otr3_privkey_generate(otr4_client_t *client, FILE *privf) {
  return otrl_privkey_generate_FILEp(client->state->userstate, privf,
                                     client->state->account_name,
                                     client->state->protocol_name);
}

int otr3_instag_generate(otr4_client_t *client, FILE *privf) {
  return otrl_instag_generate_FILEp(client->state->userstate, privf,
                                    client->state->account_name,
                                    client->state->protocol_name);
}
