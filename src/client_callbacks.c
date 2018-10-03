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

#define OTRNG_CLIENT_CALLBACKS_PRIVATE
#include "client_callbacks.h"
#include "client.h"

INTERNAL otrng_bool
otrng_client_callbacks_ensure_needed_exist(const otrng_client_callbacks_s *cb) {
  return otrng_bool_is_true(
      cb->get_account_and_protocol != NULL && cb->create_privkey_v3 != NULL &&
      cb->create_privkey_v4 != NULL && cb->create_forging_key != NULL &&
      cb->create_client_profile != NULL &&
      cb->write_expired_client_profile != NULL &&
      cb->create_prekey_profile != NULL &&
      cb->write_expired_prekey_profile != NULL &&
      cb->create_shared_prekey != NULL &&
      cb->get_shared_session_state != NULL && cb->load_privkey_v4 != NULL &&
      cb->load_client_profile != NULL && cb->load_prekey_profile != NULL &&
      cb->store_client_profile != NULL && cb->store_prekey_profile != NULL);
}

INTERNAL void
otrng_client_callbacks_create_instag(const otrng_client_callbacks_s *cb,
                                     const otrng_client_id_s client_opdata) {
  if (!cb->create_instag) {
    return;
  }

  cb->create_instag(client_opdata);
}

INTERNAL void
otrng_client_callbacks_gone_secure(const otrng_client_callbacks_s *cb,
                                   const otrng_s *conv) {
  if (!cb->gone_secure) {
    return;
  }

  cb->gone_secure(conv);
}

INTERNAL void
otrng_client_callbacks_gone_insecure(const otrng_client_callbacks_s *cb,
                                     const otrng_s *conv) {
  if (!cb->gone_insecure) {
    return;
  }

  cb->gone_insecure(conv);
}

INTERNAL void
otrng_client_callbacks_fingerprint_seen(const otrng_client_callbacks_s *cb,
                                        const otrng_fingerprint_t fp,
                                        const otrng_s *conv) {
  if (!cb->fingerprint_seen) {
    return;
  }

  cb->fingerprint_seen(fp, conv);
}

INTERNAL void
otrng_client_callbacks_fingerprint_seen_v3(const otrng_client_callbacks_s *cb,
                                           const otrng_fingerprint_v3_t fp,
                                           const otrng_s *conv) {
  if (!cb->fingerprint_seen_v3) {
    return;
  }

  cb->fingerprint_seen_v3(fp, conv);
}

INTERNAL void
otrng_client_callbacks_smp_ask_for_secret(const otrng_client_callbacks_s *cb,
                                          const otrng_s *conv) {
  if (!cb->smp_ask_for_secret) {
    return;
  }

  cb->smp_ask_for_secret(conv);
}

INTERNAL void
otrng_client_callbacks_smp_ask_for_answer(const otrng_client_callbacks_s *cb,
                                          const char *question,
                                          const otrng_s *conv) {
  if (!cb->smp_ask_for_answer) {
    return;
  }

  // TODO: The question should be a string
  cb->smp_ask_for_answer((const uint8_t *)question, strlen(question + 1), conv);
}

INTERNAL void otrng_client_callbacks_smp_update(
    const otrng_client_callbacks_s *cb, const otrng_smp_event_t event,
    const uint8_t progress_percent, const otrng_s *conv) {
  if (!cb->smp_update) {
    return;
  }

  cb->smp_update(event, progress_percent, conv);
}

#ifdef DEBUG_API

#include "debug.h"

API void otrng_client_callbacks_debug_print(FILE *f, int indent,
                                            const otrng_client_callbacks_s *c) {
  if (otrng_debug_print_should_ignore("client_callbacks")) {
    return;
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "client_callbacks(");
  otrng_debug_print_pointer(f, c);
  debug_api_print(f, ") {\n");

  if (otrng_debug_print_should_ignore(
          "client_callbacks->get_account_and_protocol")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "get_account_and_protocol = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "get_account_and_protocol = ");
    otrng_debug_print_pointer(f, c->get_account_and_protocol);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("client_callbacks->create_instag")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_instag = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_instag = ");
    otrng_debug_print_pointer(f, c->create_instag);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("client_callbacks->create_privkey_v3")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_privkey_v3 = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_privkey_v3 = ");
    otrng_debug_print_pointer(f, c->create_privkey_v3);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("client_callbacks->create_privkey_v4")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_privkey_v4 = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_privkey_v4 = ");
    otrng_debug_print_pointer(f, c->create_privkey_v4);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore(
          "client_callbacks->create_client_profile")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_client_profile = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_client_profile = ");
    otrng_debug_print_pointer(f, c->create_client_profile);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore(
          "client_callbacks->create_prekey_profile")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_prekey_profile = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_prekey_profile = ");
    otrng_debug_print_pointer(f, c->create_prekey_profile);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore(
          "client_callbacks->create_shared_prekey")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_shared_prekey = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "create_shared_prekey = ");
    otrng_debug_print_pointer(f, c->create_shared_prekey);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("client_callbacks->gone_secure")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "gone_secure = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "gone_secure = ");
    otrng_debug_print_pointer(f, c->gone_secure);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("client_callbacks->gone_insecure")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "gone_insecure = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "gone_insecure = ");
    otrng_debug_print_pointer(f, c->gone_insecure);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("client_callbacks->fingerprint_seen")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "fingerprint_seen = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "fingerprint_seen = ");
    otrng_debug_print_pointer(f, c->fingerprint_seen);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore(
          "client_callbacks->fingerprint_seen_v3")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "fingerprint_seen_v3 = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "fingerprint_seen_v3 = ");
    otrng_debug_print_pointer(f, c->fingerprint_seen_v3);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("client_callbacks->smp_ask_for_secret")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "smp_ask_for_secret = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "smp_ask_for_secret = ");
    otrng_debug_print_pointer(f, c->smp_ask_for_secret);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("client_callbacks->smp_ask_for_answer")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "smp_ask_for_answer = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "smp_ask_for_answer = ");
    otrng_debug_print_pointer(f, c->smp_ask_for_answer);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore("client_callbacks->smp_update")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "smp_update = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "smp_update = ");
    otrng_debug_print_pointer(f, c->smp_update);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore(
          "client_callbacks->received_extra_symm_key")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "received_extra_symm_key = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "received_extra_symm_key = ");
    otrng_debug_print_pointer(f, c->received_extra_symm_key);
    debug_api_print(f, "\n");
  }

  if (otrng_debug_print_should_ignore(
          "client_callbacks->get_shared_session_state")) {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "get_shared_session_state = IGNORED\n");
  } else {
    otrng_print_indent(f, indent + 2);
    debug_api_print(f, "get_shared_session_state = ");
    otrng_debug_print_pointer(f, c->get_shared_session_state);
    debug_api_print(f, "\n");
  }

  otrng_print_indent(f, indent);
  debug_api_print(f, "} // client_callbacks\n");
}

#endif /* DEBUG_API */
