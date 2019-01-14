/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
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

#ifndef S_SPLINT_S
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include <libotr/privkey.h>
#pragma clang diagnostic pop
#endif

#include <assert.h>
#include <time.h>

#define OTRNG_CLIENT_PRIVATE

#include "alloc.h"
#include "client.h"
#include "client_callbacks.h"
#include "debug.h"
#include "deserialize.h"
#include "instance_tag.h"
#include "messaging.h"
#include "serialize.h"
#include "smp.h"
#include "str.h"

#define MAX_NUMBER_PUBLISHED_PREKEY_MSGS 255
#define HEARTBEAT_INTERVAL 60

tstatic otrng_conversation_s *new_conversation_with(const char *recipient,
                                                    otrng_s *conn) {
  otrng_conversation_s *conv = otrng_xmalloc_z(sizeof(otrng_conversation_s));

  conv->recipient = otrng_xstrdup(recipient);

  conv->conn = conn;

  return conv;
}

tstatic void conversation_free(void *data) {
  otrng_conversation_s *conv = data;

  otrng_free(conv->recipient);
  otrng_conn_free(conv->conn);

  otrng_free(conv);
}

tstatic otrng_bool should_heartbeat(long last_sent) {
  time_t now = time(NULL);
  long interval = now - HEARTBEAT_INTERVAL;
  if (last_sent < interval) {
    return otrng_true;
  }
  return otrng_false;
}

/* The given client_id will be copied, so managing the lifetime of the protocol
   and account strings is the responsibility of the client. */
API otrng_client_s *otrng_client_new(const otrng_client_id_s client_id) {
  otrng_client_s *client = otrng_xmalloc_z(sizeof(otrng_client_s));
  const otrng_client_id_s cid = {
      .protocol = otrng_xstrdup(client_id.protocol),
      .account = otrng_xstrdup(client_id.account),
  };

  client->client_id = cid;
  client->max_stored_msg_keys = 1000;
  client->max_published_prekey_msg = 100;
  client->minimum_stored_prekey_msg = 20;
  client->should_heartbeat = should_heartbeat;

#define EXTRA_CLIENT_PROFILE_EXPIRATION_SECONDS 2 * 24 * 60 * 60; /* 2 days */
  client->profiles_extra_valid_time = EXTRA_CLIENT_PROFILE_EXPIRATION_SECONDS;

#define CLIENT_PROFILE_EXPIRATION_SECONDS 2 * 7 * 24 * 60 * 60; /* 2 weeks */
  client->client_profile_exp_time = CLIENT_PROFILE_EXPIRATION_SECONDS;

#define PROFILES_CLOSE_TO_EXPIRATION_TIME_SECONDS 57 * 60 /* 57 minutes*/
  client->profiles_buffer_time = PROFILES_CLOSE_TO_EXPIRATION_TIME_SECONDS;

  return client;
}

tstatic void prekey_message_free_from_list(void *prekeys) {
  otrng_prekey_message_free(prekeys);
}

API void otrng_client_free(otrng_client_s *client) {
  if (!client) {
    return;
  }

  otrng_keypair_free(client->keypair);
  if (client->forging_key) {
    otrng_ec_point_destroy(*client->forging_key);
  }
  otrng_free(client->forging_key);
  otrng_list_free(client->our_prekeys, prekey_message_free_from_list);
  otrng_client_profile_free(client->client_profile);
  otrng_client_profile_free(client->exp_client_profile);
  otrng_prekey_profile_free(client->prekey_profile);
  otrng_prekey_profile_free(client->exp_prekey_profile);
  otrng_list_free(client->conversations, conversation_free);
  otrng_prekey_client_free(client->prekey_client);
  if (client->fingerprints) {
    otrng_known_fingerprints_free(client->fingerprints);
  }
  otrng_free((char *)client->client_id.account);
  otrng_free((char *)client->client_id.protocol);

  otrng_free(client);
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

tstatic otrng_policy_s get_policy_for(otrng_client_s *client) {
  const otrng_client_callbacks_s *cb = client->global_state->callbacks;
  otrng_policy_s policy = otrng_client_callbacks_define_policy(cb, client);

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
  default:
    break;
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
  default:
    break;
  }

  return otrng_false;
}

tstatic /*@temp@*/ otrng_s *create_connection_for(const char *recipient,
                                                  otrng_client_s *client) {
  otrng_v3_conn_s *v3_conn = NULL;
  otrng_s *conn = NULL;

  v3_conn = otrng_v3_conn_new(client, recipient);
  if (!v3_conn) {
    return NULL;
  }

  conn = otrng_new(client, get_policy_for(client));
  if (!conn) {
    otrng_v3_conn_free(v3_conn);
    return NULL;
  }

  conn->peer = otrng_xstrdup(recipient);

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
    otrng_free(conn);
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
tstatic otrng_result send_message(char **new_msg, const char *msg,
                                  const char *recipient,
                                  otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;
  otrng_result result;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_ERROR;
  }

  result = otrng_send_message(new_msg, msg, NULL, 0, conv->conn);

  return result;
}

API char *otrng_client_query_message(const char *recipient, const char *msg,
                                     otrng_client_s *client) {
  char *ret = NULL;
  otrng_conversation_s *conv = NULL;
  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return NULL;
  }

  if (otrng_failed(otrng_build_query_message(&ret, msg, conv->conn))) {
    // TODO: @client This should come from the client (a callback maybe?)
    // because it knows in which language this should be sent, for example.
    char *error = otrng_xstrdup(
        "Failed to start an Off-the-Record private conversation.");
    return error;
  }

  return ret;
}

API otrng_result otrng_client_send(char **new_msg, const char *msg,
                                   const char *recipient,
                                   otrng_client_s *client) {
  /* v4 client will know how to transition to v3 if a v3 conversation is
   started */
  return send_message(new_msg, msg, recipient, client);
}

API otrng_result otrng_client_send_non_interactive_auth(
    char **new_msg, const prekey_ensemble_s *ensemble, const char *recipient,
    otrng_client_s *client) {
  otrng_conversation_s *conv =
      get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_ERROR;
  }

  return otrng_send_non_interactive_auth(new_msg, ensemble, conv->conn);
}

API otrng_result otrng_client_send_fragment(otrng_message_to_send_s **new_msg,
                                            const char *msg, int mms,
                                            const char *recipient,
                                            otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;
  string_p to_send = NULL;
  uint32_t our_tag, their_tag;
  otrng_result ret = OTRNG_ERROR;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_ERROR;
  }

  if (otrng_failed(send_message(&to_send, msg, recipient, client))) {
    if (to_send) {
      otrng_free(to_send);
    }
    return OTRNG_ERROR;
  }

  our_tag = otrng_client_get_instance_tag(client);
  their_tag = conv->conn->their_instance_tag;

  if (to_send) {
    ret = otrng_fragment_message(mms, *new_msg, our_tag, their_tag, to_send);
    otrng_free(to_send);
  }

  return ret;
}

API otrng_result otrng_client_smp_start(char **to_send, const char *recipient,
                                        const unsigned char *question,
                                        const size_t q_len,
                                        const unsigned char *secret,
                                        size_t secret_len,
                                        otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_ERROR;
  }

  return otrng_smp_start(to_send, question, q_len, secret, secret_len,
                         conv->conn);
}

API otrng_result otrng_client_smp_respond(char **to_send, const char *recipient,
                                          const unsigned char *secret,
                                          size_t secret_len,
                                          otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_ERROR;
  }

  return otrng_smp_continue(to_send, secret, secret_len, conv->conn);
}

API otrng_result otrng_client_smp_abort(char **to_send, const char *recipient,
                                        otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    return OTRNG_ERROR;
  }

  return otrng_smp_abort(to_send, conv->conn);
}

API otrng_result otrng_client_receive(char **new_msg, char **to_display,
                                      const char *msg, const char *recipient,
                                      otrng_client_s *client,
                                      otrng_bool *should_ignore) {
  otrng_result result = OTRNG_ERROR;
  otrng_response_s *response = NULL;
  otrng_conversation_s *conv = NULL;

  *should_ignore = otrng_false;

  if (!client) {
    return OTRNG_ERROR;
  }

  if (!new_msg) {
    return result;
  }

  *new_msg = NULL;

  conv = get_or_create_conversation_with(recipient, client);
  if (!conv) {
    *should_ignore = otrng_true;
    return OTRNG_SUCCESS;
  }

  response = otrng_response_new();

  result = otrng_receive_message(response, msg, conv->conn);

  if (response->to_send) {
    *new_msg = otrng_xstrdup(response->to_send);
  }

  *to_display = NULL;
  if (response->to_display) {
    char *plain = otrng_xstrdup(response->to_display);
    *to_display = plain;
    otrng_response_free(response);
    return OTRNG_SUCCESS;
  }

  otrng_response_free(response);

  return result;
}

tstatic void destroy_client_conversation(const otrng_conversation_s *conv,
                                         otrng_client_s *client) {
  list_element_s *elem = otrng_list_get_by_value(conv, client->conversations);
  client->conversations =
      otrng_list_remove_element(elem, client->conversations);
  otrng_list_free_nodes(elem);
}

API otrng_result otrng_client_disconnect(char **new_msg, const char *recipient,
                                         otrng_client_s *client) {
  otrng_conversation_s *conv = NULL;

  conv = get_conversation_with(recipient, client->conversations);
  if (!conv) {
    return OTRNG_ERROR;
  }

  if (otrng_failed(otrng_close(new_msg, conv->conn))) {
    return OTRNG_ERROR;
  }

  destroy_client_conversation(conv, client);
  conversation_free(conv);

  return OTRNG_SUCCESS;
}

// TODO: @client this depends on how is going to be handled: as a different
// event or inside process_conv_updated?
/* expiration time should be set on seconds */
API otrng_result otrng_expire_encrypted_session(char **new_msg,
                                                const char *recipient,
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
    if (otrng_failed(otrng_expire_session(new_msg, conv->conn))) {
      return OTRNG_ERROR;
    }
  }

  destroy_client_conversation(conv, client);
  conversation_free(conv);

  return OTRNG_SUCCESS;
}

API otrng_result otrng_client_expire_fragments(uint32_t expiration_time,
                                               otrng_client_s *client) {
  const list_element_s *el = NULL;
  otrng_conversation_s *conv = NULL;
  time_t now;

  now = time(NULL);
  for (el = client->conversations; el; el = el->next) {
    conv = el->data;
    if (otrng_failed(otrng_expire_fragments(now, expiration_time,
                                            &conv->conn->pending_fragments))) {
      return OTRNG_ERROR;
    }
  }

  return OTRNG_SUCCESS;
}

API otrng_result otrng_client_get_our_fingerprint(
    otrng_fingerprint fp, const otrng_client_s *client) {
  if (!client->keypair) {
    return OTRNG_ERROR;
  }

  return otrng_serialize_fingerprint(fp, client->keypair->pub);
}

tstatic otrng_result
otrng_client_get_max_published_prekey_msg(otrng_client_s *client) {
  assert(client != NULL);

  return client->max_published_prekey_msg;
}

tstatic otrng_result
otrng_client_get_minimum_stored_prekey_msg(otrng_client_s *client) {
  assert(client != NULL);

  return client->minimum_stored_prekey_msg;
}

tstatic uint64_t
otrng_client_get_client_profile_exp_time(otrng_client_s *client) {
  assert(client != NULL);

  return client->client_profile_exp_time;
}

API otrng_prekey_client_s *
otrng_client_get_prekey_client(const char *server_identity,
                               otrng_prekey_client_callbacks_s *callbacks,
                               otrng_client_s *client) {
  if (client->prekey_client) {
    return client->prekey_client;
  }

  // TODO: this should be a hashmap, since it its one client PER server
  client->prekey_client = otrng_prekey_client_new();
  otrng_prekey_client_init(client->prekey_client, server_identity,
                           client->client_id.account,
                           otrng_client_get_instance_tag(client),
                           otrng_client_get_keypair_v4(client),
                           otrng_client_get_client_profile(client),
                           otrng_client_get_prekey_profile(client),
                           otrng_client_get_max_published_prekey_msg(client),
                           otrng_client_get_minimum_stored_prekey_msg(client));

  client->prekey_client->callbacks =
      otrng_xmalloc_z(sizeof(otrng_prekey_client_callbacks_s));
  memcpy(client->prekey_client->callbacks, callbacks,
         sizeof(otrng_prekey_client_callbacks_s));

  return client->prekey_client;
}

INTERNAL void otrng_client_store_my_prekey_message(prekey_message_s *msg,
                                                   otrng_client_s *client) {
  if (!client) {
    return;
  }

  client->our_prekeys = otrng_list_add(msg, client->our_prekeys);
}

API prekey_message_s **
otrng_client_build_prekey_messages(uint8_t num_messages,
                                   otrng_client_s *client) {
  uint32_t instance_tag;
  prekey_message_s **messages;
  int i, j;

  if (num_messages > MAX_NUMBER_PUBLISHED_PREKEY_MSGS) {
    otrng_client_callbacks_handle_event(
        client->global_state->callbacks,
        OTRNG_MSG_EVENT_INCORRECT_AMMOUNT_PREKEYS);
    return NULL;
  }

  instance_tag = otrng_client_get_instance_tag(client);

  messages = otrng_xmalloc_z(num_messages * sizeof(prekey_message_s *));

  for (i = 0; i < num_messages; i++) {
    ecdh_keypair_s ecdh;
    dh_keypair_s dh;
    if (!otrng_generate_ephemeral_keys(&ecdh, &dh)) {
      otrng_free(messages);
      return NULL;
    }

    messages[i] = otrng_prekey_message_build(instance_tag, &ecdh, &dh);
    otrng_dh_keypair_destroy(&dh);

    if (!messages[i]) {
      for (j = 0; j < i; j++) {
        otrng_prekey_message_free(messages[j]);
      }
      otrng_free(messages);
      return NULL;
    }

    otrng_client_store_my_prekey_message(messages[i], client);
  }

  return messages;
}

#ifdef DEBUG_API

#include "debug.h"

API void otrng_client_debug_print(FILE *f, int indent, otrng_client_s *c) {
  int ix;
  list_element_s *curr;

  if (otrng_debug_print_should_ignore("client")) {
    return;
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "client(");
  otrng_debug_print_pointer(f, c);
  debug_api_print(f, ") {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("client->conversations")) {
    debug_api_print(f, "conversations = IGNORED\n");
  } else {
    debug_api_print(f, "conversations = {\n");
    ix = 0;
    curr = c->conversations;
    while (curr) {
      otrng_print_indent(f, indent + 4);
      debug_api_print(f, "[%d] = {\n", ix);
      otrng_conversation_debug_print(f, indent + 6, curr->data);
      otrng_print_indent(f, indent + 4);
      debug_api_print(f, "} // [%d]\n", ix);
      curr = curr->next;
      ix++;
    }
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "} // conversations\n");
  }

  // TODO / DEBUG_API: implement
  /* otrng_prekey_client_s *prekey_client; */

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // client\n");
}

API void otrng_conversation_debug_print(FILE *f, int indent,
                                        otrng_conversation_s *c) {
  if (otrng_debug_print_should_ignore("conversation")) {
    return;
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "conversation(");
  otrng_debug_print_pointer(f, c);
  debug_api_print(f, ") {\n");

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("conversation->conversation_id")) {
    debug_api_print(f, "conversation_id = IGNORED\n");
  } else {
    debug_api_print(f, "conversation_id = ");
    otrng_debug_print_pointer(f, c->conversation_id);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent + 2);
  if (otrng_debug_print_should_ignore("conversation->recipient")) {
    debug_api_print(f, "recipient = IGNORED\n");
  } else {
    debug_api_print(f, "recipient = %s\n", c->recipient);
  }

  // TODO / DEBUG_API: implement
  /* otrng_s *conn */

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // conversation\n");
}

#endif /* DEBUG */

INTERNAL OtrlPrivKey *
otrng_client_get_private_key_v3(const otrng_client_s *client) {
  return otrl_privkey_find(client->global_state->user_state_v3,
                           client->client_id.account,
                           client->client_id.protocol);
}

INTERNAL otrng_keypair_s *otrng_client_get_keypair_v4(otrng_client_s *client) {
  assert(client != NULL);

  if (client->keypair) {
    return client->keypair;
  }

  /* @secret_information: the long-term key pair lives for as long the client
     decides */
  // TODO @orchestration remove this when orchestration is done
  otrng_debug_fprintf(
      stderr, "client.c otrng_client_get_keypair_v4 -> creating private key\n");
  client->global_state->callbacks->create_privkey_v4(client);

  return client->keypair;
}

INTERNAL otrng_result otrng_client_add_private_key_v4(
    otrng_client_s *client, const uint8_t sym[ED448_PRIVATE_BYTES]) {
  assert(client != NULL);

  if (client->keypair) {
    return OTRNG_ERROR;
  }

  /* @secret_information: the long-term key pair lives for as long the client
     decides */
  client->keypair = otrng_keypair_new();
  if (!client->keypair) {
    return OTRNG_ERROR;
  }

  if (!otrng_keypair_generate(client->keypair, sym)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_public_key *
otrng_client_get_forging_key(otrng_client_s *client) {
  assert(client != NULL);
  assert(client->forging_key != NULL);

  return client->forging_key;
}

INTERNAL otrng_result otrng_client_add_forging_key(
    otrng_client_s *client, const otrng_public_key forging_key) {
  assert(client != NULL);

  if (client->forging_key) {
    return OTRNG_ERROR;
  }

  client->forging_key = otrng_xmalloc_z(sizeof(otrng_public_key));

  otrng_ec_point_copy(*client->forging_key, forging_key);

  return OTRNG_SUCCESS;
}

API otrng_client_profile_s *
otrng_client_get_client_profile(otrng_client_s *client) {
  assert(client != NULL);
  assert(client->client_profile != NULL);

  return client->client_profile;
}

API otrng_client_profile_s *
otrng_client_build_default_client_profile(otrng_client_s *client) {
  otrng_policy_s policy = get_policy_for(client);
  const char *allowed_versions = NULL;

  if (policy.allows == OTRNG_ALLOW_V34) {
    allowed_versions = "34";
  } else if (policy.allows == OTRNG_ALLOW_V4) {
    allowed_versions = "4";
  } else if (policy.allows == OTRNG_ALLOW_V3) {
    allowed_versions = "3";
  }

  assert(client != NULL);

  return otrng_client_profile_build(
      otrng_client_get_instance_tag(client), allowed_versions,
      otrng_client_get_keypair_v4(client), *client->forging_key,
      otrng_client_get_client_profile_exp_time(client));
}

API otrng_result otrng_client_add_client_profile(
    otrng_client_s *client, const otrng_client_profile_s *profile) {
  assert(client != NULL);

  if (client->client_profile) {
    return OTRNG_ERROR;
  }

  client->client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));

  if (!otrng_client_profile_copy(client->client_profile, profile)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

API const otrng_client_profile_s *
otrng_client_get_exp_client_profile(otrng_client_s *client) {
  assert(client != NULL);

  return client->exp_client_profile;
}

API otrng_result otrng_client_add_exp_client_profile(
    otrng_client_s *client, const otrng_client_profile_s *exp_profile) {
  assert(client != NULL);

  if (client->exp_client_profile) {
    return OTRNG_ERROR;
  }

  client->exp_client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));

  if (otrng_client_profile_copy(client->exp_client_profile, exp_profile)) {
    return OTRNG_ERROR;
  }

  return OTRNG_SUCCESS;
}

API otrng_prekey_profile_s *
otrng_client_get_prekey_profile(otrng_client_s *client) {
  assert(client != NULL);

  if (client->prekey_profile) {
    return client->prekey_profile;
  }

  client->global_state->callbacks->create_prekey_profile(client);

  return client->prekey_profile;
}

API otrng_prekey_profile_s *
otrng_client_build_default_prekey_profile(otrng_client_s *client) {
  assert(client != NULL);

  return otrng_prekey_profile_build(otrng_client_get_instance_tag(client),
                                    otrng_client_get_keypair_v4(client));
}

API otrng_result otrng_client_add_prekey_profile(
    otrng_client_s *client, const otrng_prekey_profile_s *profile) {
  assert(client != NULL);
  if (client->prekey_profile) {
    return OTRNG_ERROR;
  }

  client->prekey_profile = otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));

  otrng_prekey_profile_copy(client->prekey_profile, profile);

  return OTRNG_SUCCESS;
}

API const otrng_prekey_profile_s *
otrng_client_get_exp_prekey_profile(otrng_client_s *client) {
  assert(client != NULL);

  if (client->exp_prekey_profile) {
    return client->prekey_profile;
  }

  return NULL;
}

API otrng_result otrng_client_add_exp_prekey_profile(
    otrng_client_s *client, const otrng_prekey_profile_s *exp_profile) {
  assert(client != NULL);

  if (client->exp_prekey_profile) {
    return OTRNG_ERROR;
  }

  client->exp_prekey_profile = otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));

  otrng_prekey_profile_copy(client->exp_prekey_profile, exp_profile);

  return OTRNG_SUCCESS;
}

tstatic OtrlInsTag *otrng_instance_tag_new(const char *protocol,
                                           const char *account,
                                           unsigned int instag) {
  OtrlInsTag *p;
  if (instag < OTRNG_MIN_VALID_INSTAG) {
    return NULL;
  }

  p = otrng_xmalloc_z(sizeof(OtrlInsTag));

  p->accountname = otrng_xstrdup(account);
  p->protocol = otrng_xstrdup(protocol);
  p->instag = instag;

  return p;
}

tstatic void otrl_userstate_instance_tag_add(OtrlUserState us,
                                             OtrlInsTag *instag) {
  // This comes from libotr
  instag->next = us->instag_root;
  if (instag->next) {
    instag->next->tous = &(instag->next);
  }

  instag->tous = &(us->instag_root);
  us->instag_root = instag;
}

INTERNAL unsigned int otrng_client_get_instance_tag(otrng_client_s *client) {
  OtrlInsTag *instag;

  if (client->global_state->user_state_v3 == NULL) {
    return (unsigned int)0;
  }

  //  fprintf(stderr,"first: %s\n",
  //  client->global_state->user_state_v3->instag_root->accountname);
  instag =
      otrl_instag_find(client->global_state->user_state_v3,
                       client->client_id.account, client->client_id.protocol);

  if (!instag) {
    otrng_client_callbacks_create_instag(client->global_state->callbacks,
                                         client);
  }

  instag =
      otrl_instag_find(client->global_state->user_state_v3,
                       client->client_id.account, client->client_id.protocol);

  if (!instag) {
    return (unsigned int)0;
  }

  return instag->instag;
}

INTERNAL otrng_result otrng_client_add_instance_tag(otrng_client_s *client,
                                                    unsigned int instag) {
  OtrlInsTag *p;

  if (!client) {
    return OTRNG_ERROR;
  }

  if (client->global_state->user_state_v3 == NULL) {
    return OTRNG_ERROR;
  }

  p = otrl_instag_find(client->global_state->user_state_v3,
                       client->client_id.account, client->client_id.protocol);
  if (p) {
    return OTRNG_ERROR;
  }

  p = otrng_instance_tag_new(client->client_id.protocol,
                             client->client_id.account, instag);

  if (!p) {
    return OTRNG_ERROR;
  }

  otrl_userstate_instance_tag_add(client->global_state->user_state_v3, p);
  return OTRNG_SUCCESS;
}

tstatic list_element_s *get_stored_prekey_node_by_id(uint32_t id,
                                                     list_element_s *l) {
  while (l) {
    const prekey_message_s *s = l->data;
    if (!s) {
      continue;
    }

    if (s->id == id) {
      return l;
    }

    l = l->next;
  }

  return NULL;
}

INTERNAL const prekey_message_s *
otrng_client_get_prekey_by_id(uint32_t id, const otrng_client_s *client) {
  list_element_s *node = get_stored_prekey_node_by_id(id, client->our_prekeys);
  if (!node) {
    return NULL;
  }

  return node->data;
}

INTERNAL void
otrng_client_delete_my_prekey_message_by_id(uint32_t id,
                                            otrng_client_s *client) {
  list_element_s *node = get_stored_prekey_node_by_id(id, client->our_prekeys);
  if (!node) {
    return;
  }

  client->our_prekeys = otrng_list_remove_element(node, client->our_prekeys);
  otrng_list_free(node, prekey_message_free_from_list);
}

API void otrng_client_set_should_heartbeat(otrng_bool (*heartbeat)(long),
                                           otrng_client_s *client) {
  assert(client != NULL);

  client->should_heartbeat = heartbeat;
}

API void otrng_client_set_padding(size_t granularity, otrng_client_s *client) {
  client->padding = granularity;
  assert(client != NULL);
}

API void otrng_client_set_max_stored_msg_keys(unsigned int max_stored_msg_keys,
                                              otrng_client_s *client) {
  assert(client != NULL);

  client->max_stored_msg_keys = max_stored_msg_keys;
}

API void
otrng_client_set_max_published_prekey_msg(unsigned int max_published_prekey_msg,
                                          otrng_client_s *client) {
  assert(client != NULL);

  client->max_published_prekey_msg = max_published_prekey_msg;
}

API void otrng_client_state_set_minimum_stored_prekey_msg(
    unsigned int minimum_stored_prekey_msg, otrng_client_s *client) {
  assert(client != NULL);

  client->minimum_stored_prekey_msg = minimum_stored_prekey_msg;
}

API void
otrng_client_set_profiles_extra_valid_time(uint64_t profiles_extra_valid_time,
                                           otrng_client_s *client) {
  assert(client != NULL);

  client->profiles_extra_valid_time = profiles_extra_valid_time;
}

API void
otrng_client_set_client_profile_exp_time(uint64_t client_profile_exp_time,
                                         otrng_client_s *client) {
  assert(client != NULL);

  client->client_profile_exp_time = client_profile_exp_time;
}

API uint64_t otrng_client_get_prekey_profile_exp_time(otrng_client_s *client) {
  assert(client != NULL);

  return client->prekey_profile_exp_time;
}

API void
otrng_client_set_prekey_profile_exp_time(uint64_t prekey_profile_exp_time,
                                         otrng_client_s *client) {
  assert(client != NULL);

  client->prekey_profile_exp_time = prekey_profile_exp_time;
}

API void otrng_client_start_publishing(otrng_client_s *client) {
  client->is_publishing = otrng_true;
}

API otrng_bool otrng_client_should_publish(otrng_client_s *client) {
  return client->should_publish && !client->is_publishing;
}

API void otrng_client_failed_published(otrng_client_s *client) {
  list_element_s *current;

  client->client_profile->is_publishing = otrng_false;
  client->prekey_profile->is_publishing = otrng_false;
  for (current = client->our_prekeys; current != NULL;
       current = current->next) {
    prekey_message_s *pm = current->data;
    pm->is_publishing = otrng_false;
  }

  client->is_publishing = otrng_false;
}

API void otrng_client_published(otrng_client_s *client) {
  list_element_s *current;
  otrng_bool has_any_pms = otrng_false;

  if (client->client_profile->is_publishing) {
    client->client_profile->should_publish = otrng_false;
    client->client_profile->is_publishing = otrng_false;
    client->global_state->callbacks->store_client_profile(client);
  }

  if (client->prekey_profile->is_publishing) {
    client->prekey_profile->should_publish = otrng_false;
    client->prekey_profile->is_publishing = otrng_false;
    client->global_state->callbacks->store_prekey_profile(client);
  }

  for (current = client->our_prekeys; current != NULL;
       current = current->next) {
    prekey_message_s *pm = current->data;
    if (pm->is_publishing) {
      has_any_pms = otrng_true;
      pm->should_publish = otrng_false;
      pm->is_publishing = otrng_false;
    }
  }
  if (has_any_pms) {
    client->global_state->callbacks->store_prekey_messages(client);
  }

  if (client->is_publishing) {
    client->should_publish = otrng_false;
    client->is_publishing = otrng_false;
  }
}
