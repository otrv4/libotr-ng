#include "client.h"
#include "str.h"

void
conversation_free(otr4_conversation_t *conv) {
  otrv4_free(conv->conn);
  conv->conn = NULL;

  free(conv->recipient);
  conv->recipient = NULL;
}

otr4_client_t*
otr4_client_new() {
    otr4_client_t *client = malloc(sizeof(otr4_client_t));
    if (!client)
        return NULL;

    cs_keypair_generate(client->keypair); //TODO: maybe not
    client->conversations = NULL;
    client->callbacks = NULL;

    return client;
}

void
otr4_client_free(otr4_client_t *client) {
    list_foreach(client->conversations, c, {
      conversation_free((otr4_conversation_t*) c->data);
      c->data = NULL;
    });
    list_free_all(client->conversations);
    client->conversations = NULL;

    cs_keypair_destroy(client->keypair);

    free(client);
}

otr4_conversation_t*
get_conversation_with(const char *recipient, list_element_t *conversations) {
    list_foreach(conversations, c, {
      otr4_conversation_t *conv = (otr4_conversation_t*) c->data;
      if (!strcmp(conv->recipient, recipient))
        return conv;
    });

    return NULL;
}

otr4_conversation_t*
new_conversation_with(const char *recipient) {
    otr4_conversation_t *conv = malloc(sizeof(otr4_conversation_t));
    if (!conv)
      return NULL;

    conv->recipient = otrv4_strdup(recipient);

    return conv;
}

otr4_conversation_t*
get_or_create_conversation_with(const char *recipient, otr4_client_t *client) {
    otr4_conversation_t *conv = get_conversation_with(recipient, client->conversations);
    if (!conv) {
        conv = new_conversation_with(recipient);
        conv->conn = otrv4_new(client->keypair);
        client->conversations = list_add(conv, client->conversations);
    }

    return conv;
}

otr4_conversation_t*
otr4_client_get_conversation(int force, const char *recipient, otr4_client_t *client) {
  if (force)
      return get_or_create_conversation_with(recipient, client);

    return get_conversation_with(recipient, client->conversations);
}

int
otr4_client_send(char **newmessage, const char *message, const char *recipient, otr4_client_t *client) {
    otr4_conversation_t *conv = get_or_create_conversation_with(recipient, client);

    if (conv->conn->state == OTRV4_STATE_START) {
        return 1;
    }

    //TODO: add notifications (like "ttried to send a message while not in
    //encrypted")
    *newmessage = NULL;
    if (!otrv4_send_message((unsigned char **) newmessage, (unsigned char*) message, strlen(message)+1, conv->conn)) {
        return -1;
    }

    return 0;
}

int
otr4_client_receive(char **newmessage, char **todisplay, const char *message, const char *recipient, otr4_client_t *client) {
    otrv4_state state_before;
    *newmessage = NULL;
    *todisplay = NULL;

    otr4_conversation_t *conv = get_or_create_conversation_with(recipient, client);
    state_before = conv->conn->state;

    otrv4_response_t *response = otrv4_response_new();
    if (!otrv4_receive_message(response, (const string_t) message, strlen(message), conv->conn)) {
      otrv4_response_free(response);
      return 0; //Should this cause the message to be ignored or not?
    }

    if (state_before != OTRV4_STATE_ENCRYPTED_MESSAGES && conv->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES) {
        //conv->ctx->msgstate = OTRL_MSGSTATE_ENCRYPTED; //Sync our state with OTR3 state

        if (client->callbacks && client->callbacks->gone_secure)
            client->callbacks->gone_secure(conv);
    }

    if (response->to_send) {
      char *tosend = otrv4_strdup(response->to_send);
      *newmessage = tosend;
    }

    int should_ignore = 1;
    if (response->to_display) {
	char *plain = otrv4_strdup(response->to_display);
        *todisplay = plain;
        should_ignore = 0;
    }

    otrv4_response_free(response);
    return should_ignore;
}

char*
otr4_client_query_message(const char *recipient, const char* message, otr4_client_t *client) {
    otr4_conversation_t *conv = get_or_create_conversation_with(recipient, client);

    //TODO: implement policy
    char *ret = NULL;
    otrv4_build_query_message(&ret, conv->conn, (const string_t) message, strlen(message));
    return ret;
}

