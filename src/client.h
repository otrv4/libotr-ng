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

#ifndef OTRNG_CLIENT_H
#define OTRNG_CLIENT_H

#define CLIENT_ERROR_NOT_ENCRYPTED 0x1001
// TODO: check the error codes on client
#define CLIENT_ERROR_MSG_NOT_VALID 0x1011

#include <libotr/context.h>

#include "client_state.h"
#include "list.h"
#include "otrng.h"
#include "shared.h"

// TODO: REMOVE
typedef struct otrng_conversation_s {
  void *conversation_id; /* Data in the messaging application context that
                          represents a conversation and should map directly to
                          it. For example, in libpurple-based apps (like
                          Pidgin) this could be a PurpleConversation */

  char *recipient;
  otrng_s *conn;
} otrng_conversation_s, otrng_conversation_p[1];

/* A client handle messages from/to a sender to/from multiple recipients. */
typedef struct otrng_client_s {
  otrng_client_state_s *state;
  list_element_s *conversations;
} otrng_client_s, otrng_client_p[1];

API otrng_client_s *otrng_client_new(otrng_client_state_s *);

API void otrng_client_free(otrng_client_s *client);

API char *otrng_client_query_message(const char *recipient, const char *message,
                                     otrng_client_s *client);

API int otrng_client_send(char **newmessage, const char *message,
                          const char *recipient, otrng_client_s *client);

API int otrng_client_send_fragment(otrng_message_to_send_s **newmessage,
                                   const char *message, int mms,
                                   const char *recipient,
                                   otrng_client_s *client);

/* tstatic int otrng_client_smp_start(char **tosend, const char *recipient, */
/*                           const char *question, const size_t q_len, */
/*                           const unsigned char *secret, size_t secretlen, */
/*                           otrng_client_s *client); */

/* tstatic int otrng_client_smp_respond(char **tosend, const char *recipient, */
/*                             const unsigned char *secret, size_t secretlen, */
/*                             otrng_client_s *client); */

API int otrng_client_receive(char **newmsg, char **todisplay,
                             const char *message, const char *recipient,
                             otrng_client_s *client);

API int otrng_client_disconnect(char **newmsg, const char *recipient,
                                otrng_client_s *client);

/* tstatic int otrng_encrypted_conversation_expire(char **newmsg, const char
 * *recipient, */
/*                                        int expiration_time, */
/*                                        otrng_client_s *client); */

API otrng_conversation_s *otrng_client_get_conversation(int force,
                                                        const char *recipient,
                                                        otrng_client_s *client);

/* tstatic int otrng_conversation_is_encrypted(otrng_conversation_s *conv); */

/* tstatic int otrng_conversation_is_finished(otrng_conversation_s *conv); */

API int otrng_expire_encrypted_session(char **newmsg, const char *recipient,
                                       int expiration_time,
                                       otrng_client_s *client);

API int otrng_client_get_our_fingerprint(otrng_fingerprint_p fp,
                                         const otrng_client_s *client);

API int should_heartbeat(int last_sent);
/* tstatic int v3_privkey_generate(otrng_client_s *client, FILE *privf); */

/* tstatic int v3_instag_generate(otrng_client_s *client, FILE *privf); */

#ifdef OTRNG_CLIENT_PRIVATE
#endif

#endif
