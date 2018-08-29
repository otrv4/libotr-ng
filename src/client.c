/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libotr/privkey.h>
#include <time.h>

#define OTRNG_CLIENT_PRIVATE

#include "client.h"
#include "serialize.h"
#include "smp.h"
#include "str.h"

#define MAX_NUMBER_PUBLISHED_PREKEY_MESSAGES 255

tstatic otrng_conversation_s *new_conversation_with(const char *recipient,
                                                    otrng_s *conn) {
  otrng_conversation_s *conv = malloc(sizeof(otrng_conversation_s));
  if (!conv) {
    free(conn);
    return NULL;
  }

  conv->recipient = otrng_strdup(recipient);
  conv->conn = conn;

  return conv;
}

tstatic void conversation_free(void *data) {
  otrng_conversation_s *conv = data;

  free(conv->recipient);
  otrng_free(conv->conn);
  free(conv);
}

API otrng_client_s *otrng_client_new(otrng_client_state_s *state) {
  otrng_client_s *client = malloc(sizeof(otrng_client_s));
  if (!client) {
    return NULL;
  }

  client->state = state;
  client->conversations = NULL;
  client->prekey_client = NULL;

  return client;
}

API void otrng_client_free(otrng_client_s *client) {
  if (!client) {
    return;
  }

  client->state = NULL;

  otrng_list_free(client->conversations, conversation_free);
  client->conversations = NULL;

  otrng_prekey_client_free(client->prekey_client);
  client->prekey_client = NULL;

  free(client);
}

// TODO: @instance_tag There may be multiple conversations with the same
// recipient if they use multiple instance tags. We are not allowing this yet.
tstatic otrng_conversation_s *
get_conversation_with(const char *recipient, list_element_s *conversations) {
  const list_element_s *el = NULL;
  otrng_conversation_s *conv = NULL;

  for (el = conversations; el; el = el->next) {
    conv = el->data;
    if (!strcmp(conv->recipient, recipient)) {
      return conv;
    }
  }

  return NULL;
}

tstatic otrng_policy_s get_policy_for(const char *recipient) {
  // TODO: @policy the policy should come from client config.
  // or a callback.
  UNUSED_ARG(recipient);
  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V3 | OTRNG_ALLOW_V4};

  return policy;
}

API otrng_bool otrng_conversation_is_encrypted(otrng_conversation_s *conv) {
  if (!conv) {
    return otrng_false;
  }

  switch (conv->conn->running_version) {
  case 0:
    return otrng_false;
  case 3:
    return conv->conn->v3_conn->ctx->msgstate == OTRL_MSGSTATE_ENCRYPTED;
  case 4:
    return conv->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES;
  }

  return otrng_false;
}

API otrng_bool otrng_conversation_is_finished(otrng_conversation_s *conv) {
  if (!conv) {
    return otrng_false;
  }

  switch (conv->conn->running_version) {
  case 0:
    return otrng_false;
  case 4:
    return conv->conn->state == OTRNG_STATE_FINISHED;
  case 3:
    return conv->conn->v3_conn->ctx->msgstate == OTRL_MSGSTATE_FINISHED;
  }

  return otrng_false;
}

tstatic otrng_s *create_connection_for(const char *recipient,
                                       otrng_client_s *client) {
  otrng_v3_conn_s *v3_conn = NULL;
  otrng_s *conn = NULL;

  v3_conn = otrng_v3_conn_new(client->state, recipient);
  if (!v3_conn) {
    return NULL;
  }

  conn = otrng_new(client->state, get_policy_for(recipient));
  if (!conn) {
    otrng_v3_conn_free(v3_conn);
    return NULL;
  }

  conn->conversation->peer = otrng_strdup(recipient);
  v3_conn->opdata = conn; /* For use in callbacks */
  conn->v3_conn = v3_conn;

  return conn;
}

tstatic otrng_conversation_s *
get_or_create_conversation_with(const char *recipient, otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;
  otrng_s *conn = NULL;

  conv = get_conversation_with(recipient, client->conversations);
  if (conv) {
    return conv;
  }

  conn = create_connection_for(recipient, client);
  if (!conn) {
    return NULL;
  }

  conv = new_conversation_with(recipient, conn);
  if (!conv) {
    return NULL;
  }

  client->conversations = otrng_list_add(conv, client->conversations);

  return conv;
}

API otrng_conversation_s *
otrng_client_get_conversation(int force_create, const char *recipient,
                              otrng_client_s *client) {
  if (force_create) {
    return get_or_create_conversation_with(recipient, client);
  }

  return get_conversation_with(recipient, client->conversations);
}

// TODO: @client this should allow TLVs to be added to the message
tstatic otrng_client_result send_message(char **newmsg, const char *message,
                                         const char *recipient,
                                         otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;
  otrng_warning warn = OTRNG_WARN_NONE;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_CLIENT_RESULT_ERROR;
  }

  otrng_result result =
      otrng_send_message(newmsg, message, &warn, NULL, 0, conv->conn);

  if (warn == OTRNG_WARN_SEND_NOT_ENCRYPTED) {
    return OTRNG_CLIENT_RESULT_ERROR_NOT_ENCRYPTED;
  }
  if (OTRNG_SUCCESS == result) {
    return OTRNG_CLIENT_RESULT_OK;
  }
  return OTRNG_CLIENT_RESULT_ERROR;
}

API int otrng_client_send(char **newmessage, const char *message,
                          const char *recipient, otrng_client_s *client) {
  /* v4 client will know how to transition to v3 if a v3 conversation is
   started */
  return send_message(newmessage, message, recipient, client);
}

API int otrng_client_send_non_interactive_auth(
    char **newmessage, const prekey_ensemble_s *ensemble, const char *recipient,
    otrng_client_s *client) {
  otrng_conversation_s *conv =
      get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_CLIENT_RESULT_ERROR;
  }

  return !otrng_send_non_interactive_auth(newmessage, ensemble, conv->conn);
}

API otrng_result otrng_client_send_fragment(otrng_message_to_send_s **newmessage,
                                   const char *message, int mms,
                                   const char *recipient,
                                   otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;
  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_ERROR;
  }

  string_p to_send = NULL;
  if (!send_message(&to_send, message, recipient, client)) {
    free(to_send); // TODO: @freeing send_message should free to_send if
                   // something fails
    return OTRNG_ERROR;
  }

  uint32_t our_tag = otrng_client_state_get_instance_tag(client->state);
  uint32_t their_tag = conv->conn->their_instance_tag;

  otrng_result ret =
      otrng_fragment_message(mms, *newmessage, our_tag, their_tag, to_send);
  free(to_send);
  return ret;
}

API otrng_result otrng_client_smp_start(char **tosend, const char *recipient,
                               const unsigned char *question,
                               const size_t q_len, const unsigned char *secret,
                               size_t secretlen, otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_ERROR;
  }

  if (!otrng_smp_start(tosend, question, q_len, secret, secretlen,
                       conv->conn)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_client_smp_respond(char **tosend, const char *recipient,
                                 const unsigned char *secret, size_t secretlen,
                                 otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_ERROR;
  }

  if (!otrng_smp_continue(tosend, secret, secretlen, conv->conn)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

// TODO: this function is very likely not doing the right thing with
//   return codes for example, look at the return of
//   CLIENT_ERROR_MSG_NOT_VALID. this function in general returns
//   ERROR=0 for errors, so anything not ERROR will be success...
API otrng_result otrng_client_receive(char **newmessage, char **todisplay,
                             const char *message, const char *recipient,
                                   otrng_client_s *client,
                                   otrng_bool *should_ignore) {
  otrng_result result = OTRNG_ERROR;
  otrng_response_s *response = NULL;
  otrng_conversation_s *conv = NULL;
  *should_ignore = otrng_false;

  if (!newmessage) {
    return result;
  }

  *newmessage = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    *should_ignore = otrng_true;
    return OTRNG_SUCCESS;
  }

  response = otrng_response_new();
  otrng_warning warn = OTRNG_WARN_NONE;
  result = otrng_receive_message(response, &warn, message, conv->conn);

  if (warn == OTRNG_WARN_RECEIVED_NOT_VALID) {
    //    return OTRNG_CLIENT_RESULT_ERROR_NOT_VALID;
    // TODO: fix this
    return OTRNG_ERROR;
  }

  if (response->to_send) {
    *newmessage = otrng_strdup(response->to_send);
  }

  *todisplay = NULL;
  if (response->to_display) {
    char *plain = otrng_strdup(response->to_display);
    *todisplay = plain;
    otrng_response_free(response);
    return OTRNG_SUCCESS;
  }

  otrng_response_free(response);

  return result;
}

API char *otrng_client_query_message(const char *recipient, const char *message,
                                     otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;
  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return NULL;
  }

  char *ret = NULL;
  if (!otrng_build_query_message(&ret, message, conv->conn)) {
    // TODO: @client This should come from the client (a callback maybe?)
    // because it knows in which language this should be sent, for example.
    return otrng_strdup(
        "Failed to start an Off-the-Record private conversation.");
  }

  return ret;
}

tstatic void destroy_client_conversation(const otrng_conversation_s *conv,
                                         otrng_client_s *client) {
  list_element_s *elem = otrng_list_get_by_value(conv, client->conversations);
  client->conversations =
      otrng_list_remove_element(elem, client->conversations);
  otrng_list_free_nodes(elem);
}

API otrng_result otrng_client_disconnect(char **newmsg, const char *recipient,
                                otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;

  conv = get_conversation_with(recipient, client->conversations);
  if (!conv) {
    return OTRNG_ERROR;
  }

  if (!otrng_close(newmsg, conv->conn)) {
    return OTRNG_ERROR;
  }

  destroy_client_conversation(conv, client);
  conversation_free(conv);

  return OTRNG_SUCCESS;
}

// TODO: @client this depends on how is going to be handled: as a different
// event or inside process_conv_updated?
/* expiration time should be set on seconds */
API otrng_result otrng_expire_encrypted_session(char **newmsg, const char *recipient,
                                       int expiration_time,
                                       otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;
  time_t now;

  conv = get_conversation_with(recipient, client->conversations);
  if (!conv) {
    return OTRNG_ERROR;
  }

  now = time(NULL);
  if (conv->conn->keys->last_generated < now - expiration_time) {
    if (!otrng_expire_session(newmsg, conv->conn)) {
      return OTRNG_ERROR;
    }
  }

  destroy_client_conversation(conv, client);
  conversation_free(conv);

  return OTRNG_SUCCESS;
}

API otrng_result otrng_client_expire_fragments(int expiration_time,
                                      otrng_client_s *client) {
  const list_element_s *el = NULL;
  otrng_conversation_s *conv = NULL;
  time_t now;

  now = time(NULL);
  for (el = client->conversations; el; el = el->next) {
    conv = el->data;
    if (!otrng_expire_fragments(now, expiration_time,
                                &conv->conn->pending_fragments)) {
      return OTRNG_ERROR;
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_client_get_our_fingerprint(otrng_fingerprint_p fp,
                                         const otrng_client_s *client) {
  if (!client->state->keypair) {
    return OTRNG_ERROR;
  }

  return otrng_serialize_fingerprint(fp, client->state->keypair->pub);
}

API otrng_prekey_client_s *
otrng_client_get_prekey_client(const char *server_identity,
                               otrng_prekey_client_callbacks_s *callbacks,
                               otrng_client_s *client) {
  if (client->prekey_client) {
    return client->prekey_client;
  }

  char *account = NULL;
  char *protocol = NULL;
  if (!otrng_client_state_get_account_and_protocol(&account, &protocol,
                                                   client->state)) {
    return NULL;
  }
  free(protocol);

  // TODO: this should be a hashmap, since it its one client PER server
  client->prekey_client = otrng_prekey_client_new(
      server_identity, account,
      otrng_client_state_get_instance_tag(client->state),
      otrng_client_state_get_keypair_v4(client->state),
      otrng_client_state_get_client_profile(client->state),
      otrng_client_state_get_prekey_profile(client->state),
      otrng_client_state_get_max_published_prekey_msg(client->state),
      otrng_client_state_get_minimum_stored_prekey_msg(client->state));

  free(account);

  client->prekey_client->callbacks = callbacks;

  return client->prekey_client;
}

API dake_prekey_message_s **
otrng_client_build_prekey_messages(uint8_t num_messages,
                                   otrng_client_s *client) {
  if (num_messages > MAX_NUMBER_PUBLISHED_PREKEY_MESSAGES) {
    // TODO: notify error
    return NULL;
  }

  uint32_t instance_tag = otrng_client_state_get_instance_tag(client->state);

  dake_prekey_message_s **messages =
      malloc(num_messages * sizeof(dake_prekey_message_s *));
  if (!messages) {
    return NULL;
  }

  for (int i = 0; i < num_messages; i++) {
    messages[i] = NULL;
  }

  for (int i = 0; i < num_messages; i++) {
    ecdh_keypair_p ecdh;
    dh_keypair_p dh;
    otrng_generate_ephemeral_keys(ecdh, dh);

    messages[i] =
        otrng_dake_prekey_message_build(instance_tag, ecdh->pub, dh->pub);
    if (!messages[i]) {
      for (int j = 0; j < num_messages; j++) {
        otrng_dake_prekey_message_free(messages[j]);
      }
      free(messages);
      return NULL;
    }

    store_my_prekey_message(messages[i]->id, messages[i]->sender_instance_tag,
                            ecdh, dh, client->state);

    // TODO: ecdh_keypair_destroy()
    // dh_keypair_detroy()
  }

  return messages;
}

// TODO: @client Read privkeys, fingerprints, instance tags for v3
/*
 *To read stored private keys:

    otrl_privkey_read(user_state, privkeyfilename);

To read stored instance tags:

    otrl_instag_read(user_state, instagfilename);

        To read stored fingerprints:

    otrl_privkey_read_fingerprints(user_state, fingerprintfilename,
            add_app_info, add_app_info_data);
*/

/* tstatic int v3_privkey_generate(otrng_client_s *client, FILE *privf) { */
/*   return otrl_privkey_generate_FILEp(client->state->user_state, privf, */
/*                                      client->state->account_name, */
/*                                      client->state->protocol_name); */
/* } */

/* tstatic int v3_instag_generate(otrng_client_s *client, FILE *privf) { */
/*   return otrl_instag_generate_FILEp(client->state->user_state, privf, */
/*                                     client->state->account_name, */
/*                                     client->state->protocol_name); */
/* } */
