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

  conv->conn = conn;
  conv->recipient = otrv4_strdup(recipient);

  return conv;
}

static void conversation_free(void *data) {
  otr4_conversation_t *conv = data;
  otrv4_free(conv->conn);
  conv->conn = NULL;

  free(conv->recipient);
  conv->recipient = NULL;

  free(conv);
}

otr4_client_t *otr4_client_new(otrv4_keypair_t *keypair,
                               OtrlUserState userstate, const char *protocol,
                               const char *account, FILE *instag_file) {
  otr4_client_t *client = malloc(sizeof(otr4_client_t));
  if (!client)
    return NULL;

  client->keypair = keypair;
  client->protocol = otrv4_strdup(protocol);
  client->account = otrv4_strdup(account);

  client->instag = malloc(sizeof(otrv4_instag_t));
  if (!client->instag) {
    return NULL;
  }

  if (!instag_file) {
    instag_file = tmpfile();
  }

  otrv4_instag_get(client->instag, account, protocol, instag_file);
  fclose(instag_file);

  client->userstate = userstate;
  client->conversations = NULL;
  client->callbacks = NULL;

  return client;
}

void otr4_client_free(otr4_client_t *client) {
  client->userstate = NULL;

  free(client->protocol);
  client->protocol = NULL;

  free(client->account);
  client->account = NULL;

  otr4_instag_free(client->instag);
  client->instag = NULL;

  list_free(client->conversations, conversation_free);
  client->conversations = NULL;
  client->keypair = NULL;

  free(client);
}

int otr4_client_generate_keypair(otr4_client_t *client) {
  if (client->keypair)
    return 0;

  client->keypair = malloc(sizeof(otrv4_keypair_t));
  if (!client->keypair)
    return -1;

  uint8_t sym[ED448_PRIVATE_BYTES];
  gcry_randomize(sym, ED448_PRIVATE_BYTES, GCRY_VERY_STRONG_RANDOM);

  otrv4_keypair_generate(client->keypair, sym);

  // Set this new keypair to every conversation in this client
  list_element_t *el;
  for (el = client->conversations; el; el = el->next) {
    otr4_conversation_t *conv = CONV(el->data);
    if (!conv->conn || conv->conn->keypair) // This should never happen
      return 1;

    conv->conn->keypair = client->keypair;
  }

  return 0;
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

  otr3_conn = otr3_conn_new(client->protocol, client->account, recipient);
  if (!otr3_conn)
    return NULL;

  conn = otrv4_new(client->keypair, get_policy_for(recipient));
  if (!conn) {
    free(otr3_conn);
    return NULL;
  }

  otr3_conn->userstate = client->userstate;
  otr3_conn->opdata = conn; // For use in callbacks
  conn->otr3_conn = otr3_conn;
  conn->callbacks = client->callbacks;

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

static int send_otrv4_message(char **newmessage, const char *message,
                              const char *recipient, otr4_client_t *client) {
  *newmessage = NULL;
  otr4_conversation_t *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return 1;

  otr4_err_t error = otrv4_send_message(newmessage, message, NULL, conv->conn);
  if (error == OTR4_STATE_NOT_ENCRYPTED)
    return OTR4_CLIENT_ERROR_NOT_ENCRYPTED;
  else
    return OTR4_SUCCESS != error;
}

int otr4_client_send(char **newmessage, const char *message,
                     const char *recipient, otr4_client_t *client) {
  // OTR4 client will know how to transition to OTR3 if a v3 conversation is
  // started
  return send_otrv4_message(newmessage, message, recipient, client);
}

int otr4_client_smp_start(char **tosend, const char *recipient,
                          const char *question, const unsigned char *secret,
                          size_t secretlen, otr4_client_t *client) {
  *tosend = NULL;
  otr4_conversation_t *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return 1;

  if (otrv4_smp_start(tosend, question, secret, secretlen, conv->conn))
    return 1;

  return 0;
}

int otr4_client_smp_respond(char **tosend, const char *recipient,
                            const unsigned char *secret, size_t secretlen,
                            otr4_client_t *client) {
  *tosend = NULL;
  otr4_conversation_t *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return 1;

  if (otrv4_smp_continue(tosend, secret, secretlen, conv->conn))
    return 1;

  return 0;
}

int otr4_client_receive(char **newmessage, char **todisplay,
                        const char *message, const char *recipient,
                        otr4_client_t *client) {
  otr4_conversation_t *conv = NULL;
  otrv4_response_t *response = otrv4_response_new();

  *newmessage = NULL;
  *todisplay = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return 1;

  conv->conn->our_instance_tag = client->instag->value;
  if (otrv4_receive_message(response, message, conv->conn)) {
    otrv4_response_free(response);
    return 0; // Should this cause the message to be ignored or not?
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

int otr4_client_disconnect(char **newmessage, const char *recipient,
                           otr4_client_t *client) {
  *newmessage = NULL;
  otr4_conversation_t *conv = NULL;

  conv = get_conversation_with(recipient, client->conversations);
  if (!conv)
    return 1;

  if (otrv4_close(newmessage, conv->conn))
    return 2;

  destroy_client_conversation(conv, client);
  conversation_free(conv);
  conv = NULL;

  return 0;
}

int otr4_client_get_our_fingerprint(otrv4_fingerprint_t fp,
                                    const otr4_client_t *client) {
  if (!client->keypair)
    return -1;

  return otr4_serialize_fingerprint(fp, client->keypair->pub);
}

int otr4_read_privkey_FILEp(otr4_client_t *client, FILE *privf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;
  int err = 0;

  if (!privf)
    return -1;

  if (!client->keypair)
    client->keypair = otrv4_keypair_new();

  if (!client->keypair)
    return -2;

  len = getline(&line, &cap, privf);
  if (len < 0)
    return -3;

  if (otrv4_symmetric_key_deserialize(client->keypair, line, len)) {
    free(line);
    return -1;
  }
  free(line);

  return err;
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
  return otrl_privkey_generate_FILEp(client->userstate, privf, client->account,
                                     client->protocol);
}

int otr3_instag_generate(otr4_client_t *client, FILE *privf) {
  return otrl_instag_generate_FILEp(client->userstate, privf, client->account,
                                    client->protocol);
}
