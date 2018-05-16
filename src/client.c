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
#include "str.h"

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
  conv->recipient = NULL;

  otrng_free(conv->conn);
  conv->conn = NULL;

  free(conv);
  conv = NULL;
}

API otrng_client_s *otrng_client_new(otrng_client_state_s *state) {
  otrng_client_s *client = malloc(sizeof(otrng_client_s));
  if (!client)
    return NULL;

  client->state = state;
  client->conversations = NULL;

  return client;
}

API void otrng_client_free(otrng_client_s *client) {
  if (!client)
    return;

  client->state = NULL;

  otrng_list_free(client->conversations, conversation_free);
  client->conversations = NULL;

  free(client);
  client = NULL;
}

// TODO: There may be multiple conversations with the same recipient if they
// uses multiple instance tags. We are not allowing this yet.
tstatic otrng_conversation_s *
get_conversation_with(const char *recipient, list_element_s *conversations) {
  const list_element_s *el = NULL;
  otrng_conversation_s *conv = NULL;

  for (el = conversations; el; el = el->next) {
    conv = el->data;
    if (!strcmp(conv->recipient, recipient))
      return conv;
  }

  return NULL;
}

tstatic otrng_policy_s get_policy_for(const char *recipient) {
  // TODO: the policy should come from client config.
  UNUSED_ARG(recipient);
  otrng_policy_s policy = {.allows = OTRNG_ALLOW_V3 | OTRNG_ALLOW_V4};

  return policy;
}

/* tstatic int otrng_conversation_is_encrypted(otrng_conversation_s *conv) { */
/*   if (!conv) */
/*     return 0; */

/*   switch (conv->conn->running_version) { */
/*   case OTRNG_VERSION_NONE: */
/*     return 0; */
/*   case OTRNG_VERSION_4: */
/*     return conv->conn->state == OTRNG_STATE_ENCRYPTED_MESSAGES; */
/*   case OTRNG_VERSION_3: */
/*     return conv->conn->v3_conn->ctx->msgstate == OTRL_MSGSTATE_ENCRYPTED;
 */
/*   } */

/*   return 0; */
/* } */

/* tstatic int otrng_conversation_is_finished(otrng_conversation_s *conv) { */
/*   if (!conv) */
/*     return 0; */

/*   switch (conv->conn->running_version) { */
/*   case OTRNG_VERSION_NONE: */
/*     return 0; */
/*   case OTRNG_VERSION_4: */
/*     return conv->conn->state == OTRNG_STATE_FINISHED; */
/*   case OTRNG_VERSION_3: */
/*     return conv->conn->v3_conn->ctx->msgstate == OTRL_MSGSTATE_FINISHED; */
/*   } */

/*   return 0; */
/* } */

tstatic otrng_s *create_connection_for(const char *recipient,
                                       otrng_client_s *client) {
  otrng_v3_conn_s *v3_conn = NULL;
  otrng_s *conn = NULL;

  // TODO: This should receive only the client_state (which should allow
  // you to get protocol, account, v3 user_state, etc)
  v3_conn = otrng_v3_conn_new(client->state, recipient);
  if (!v3_conn)
    return NULL;

  // TODO: put here policy none
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
  if (conv)
    return conv;

  conn = create_connection_for(recipient, client);
  if (!conn)
    return NULL;

  conv = new_conversation_with(recipient, conn);
  if (!conv)
    return NULL;

  client->conversations = otrng_list_add(conv, client->conversations);

  return conv;
}

API otrng_conversation_s *
otrng_client_get_conversation(int force_create, const char *recipient,
                              otrng_client_s *client) {
  if (force_create)
    return get_or_create_conversation_with(recipient, client);

  return get_conversation_with(recipient, client->conversations);
}

tstatic int send_message(char **newmsg, const char *message,
                         const char *recipient, otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;
  tlv_list_s *tlvs = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return 1;

  otrng_err error =
      otrng_prepare_to_send_message(newmsg, message, &tlvs, 0, conv->conn);
  otrng_tlv_list_free(tlvs);

  if (error == STATE_NOT_ENCRYPTED)
    return CLIENT_ERROR_NOT_ENCRYPTED;
  else
    return SUCCESS != error;
}

API int otrng_client_send(char **newmessage, const char *message,
                          const char *recipient, otrng_client_s *client) {
  /* v4 client will know how to transition to v3 if a v3 conversation is
   started */
  return send_message(newmessage, message, recipient, client);
}

API int otrng_client_send_fragment(otrng_message_to_send_s **newmessage,
                                   const char *message, int mms,
                                   const char *recipient,
                                   otrng_client_s *client) {
  string_p to_send = NULL;
  otrng_err err = send_message(&to_send, message, recipient, client);
  if (err != SUCCESS) {
    free(to_send);
    to_send = NULL;
    return 1;
  }

  otrng_conversation_s *conv = NULL;
  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    free(to_send);
    to_send = NULL;
    return 1;
  }

  uint32_t our_tag = conv->conn->our_instance_tag;
  uint32_t their_tag = conv->conn->their_instance_tag;
  err = otrng_fragment_message(mms, *newmessage, our_tag, their_tag, to_send);
  free(to_send);
  to_send = NULL;

  return err != SUCCESS;
}

/* tstatic int otrng_client_smp_start(char **tosend, const char *recipient, */
/*                           const char *question, const size_t q_len, */
/*                           const unsigned char *secret, size_t secretlen, */
/*                           otrng_client_s *client) { */
/*   otrng_conversation_s *conv = NULL; */

/*   conv = get_or_create_conversation_with(recipient, client); */
/*   if (!conv) */
/*     return 1; */

/*   if (otrng_smp_start(tosend, question, q_len, secret, secretlen,
 * conv->conn)) */
/*     return 1; */

/*   return 0; */
/* } */

/* tstatic int otrng_client_smp_respond(char **tosend, const char *recipient, */
/*                             const unsigned char *secret, size_t secretlen, */
/*                             otrng_client_s *client) { */
/*   otrng_conversation_s *conv = NULL; */

/*   conv = get_or_create_conversation_with(recipient, client); */
/*   if (!conv) */
/*     return 1; */

/*   if (otrng_smp_continue(tosend, secret, secretlen, conv->conn)) */
/*     return 1; */

/*   return 0; */
/* } */

tstatic int unfragment(char **unfragmented, const char *received,
                       fragment_context_s *ctx, int our_instance_tag) {
  otrng_err err =
      otrng_unfragment_message(unfragmented, ctx, received, our_instance_tag);
  return err != SUCCESS || ctx->status == FRAGMENT_INCOMPLETE;
}

API int otrng_client_receive(char **newmessage, char **todisplay,
                             const char *message, const char *recipient,
                             otrng_client_s *client) {
  otrng_err error = ERROR;
  char *unfrag_msg = NULL;
  int should_ignore = 1;
  otrng_response_s *response = NULL;
  otrng_conversation_s *conv = NULL;

  if (!newmessage)
    return error;

  *newmessage = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return should_ignore;

  if (unfragment(&unfrag_msg, message, conv->conn->frag_ctx,
                 conv->conn->our_instance_tag))
    return should_ignore;

  response = otrng_response_new();
  error = otrng_receive_message(response, unfrag_msg, conv->conn);
  if (error == MSG_NOT_VALID)
    return CLIENT_ERROR_MSG_NOT_VALID;

  free(unfrag_msg);
  unfrag_msg = NULL;

  if (response->to_send)
    *newmessage = otrng_strdup(response->to_send);

  *todisplay = NULL;
  if (response->to_display) {
    char *plain = otrng_strdup(response->to_display);
    *todisplay = plain;
    otrng_response_free(response);
    return !should_ignore;
  }

  otrng_response_free(response);

  if (error != SUCCESS)
    return !should_ignore; // Should this cause the message to be ignored or
                           // not?

  return should_ignore;
}

API char *otrng_client_query_message(const char *recipient, const char *message,
                                     otrng_client_s *client,
                                     OtrlPolicy policy) {
  otrng_conversation_s *conv = NULL;
  char *ret = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv)
    return NULL;

  // TODO: add name
  ret = "Failed to start an Off-the-Record private conversation.";

  conv->conn->supported_versions = policy;
  // TODO: implement policy
  if (!otrng_build_query_message(&ret, message, conv->conn))
    return ret;

  return ret;
}

tstatic void destroy_client_conversation(const otrng_conversation_s *conv,
                                         otrng_client_s *client) {
  list_element_s *elem = otrng_list_get_by_value(conv, client->conversations);
  client->conversations =
      otrng_list_remove_element(elem, client->conversations);
  otrng_list_free_nodes(elem);
}

API int otrng_client_disconnect(char **newmsg, const char *recipient,
                                otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;

  conv = get_conversation_with(recipient, client->conversations);
  if (!conv)
    return 1;

  if (!otrng_close(newmsg, conv->conn))
    return 2;

  destroy_client_conversation(conv, client);
  conversation_free(conv);

  return 0;
}

// TODO: this depends on how is going to be handled: as a different
// event or inside process_conv_updated?
/* expiration time should be set on seconds */
/* tstatic int otrng_encrypted_conversation_expire(char **newmsg, const char
 * *recipient, */
/*                                        int expiration_time, */
/*                                        otrng_client_s *client) { */
/*   otrng_conversation_s *conv = NULL; */
/*   time_t now; */

/*   conv = get_conversation_with(recipient, client->conversations); */
/*   if (!conv) */
/*     return 1; */

/*   now = time(NULL); */
/*   if (conv->conn->keys->lastgenerated < now - expiration_time) { */
/*     if (otrng_expire_session(newmsg, conv->conn)) */
/*       return 2; */
/*   } */

/*   destroy_client_conversation(conv, client); */
/*   conversation_free(conv); */

/*   return 0; */
/* } */

API int otrng_client_get_our_fingerprint(otrng_fingerprint_p fp,
                                         const otrng_client_s *client) {
  if (!client->state->keypair)
    return -1;

  return otrng_serialize_fingerprint(fp, client->state->keypair->pub);
}

// TODO: Read privkeys, fingerprints, instance tags for v3
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
