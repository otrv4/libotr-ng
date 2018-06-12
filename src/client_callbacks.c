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

#define OTRNG_CLIENT_CALLBACKS_PRIVATE
#include "client_callbacks.h"

INTERNAL void
otrng_client_callbacks_create_privkey(const otrng_client_callbacks_s *cb,
                                      const void *client_opdata) {
  if (!cb) {
    return;
  }
}

INTERNAL void
otrng_client_callbacks_gone_secure(const otrng_client_callbacks_s *cb,
                                   const otrng_client_conversation_s *conv) {
  if (!cb || !cb->gone_secure) {
    return;
  }

  cb->gone_secure(conv);
}

INTERNAL void
otrng_client_callbacks_gone_insecure(const otrng_client_callbacks_s *cb,
                                     const otrng_client_conversation_s *conv) {
  if (!cb || !cb->gone_insecure) {
    return;
  }

  cb->gone_insecure(conv);
}

INTERNAL void otrng_client_callbacks_fingerprint_seen(
    const otrng_client_callbacks_s *cb, const otrng_fingerprint_p fp,
    const otrng_client_conversation_s *conv) {
  if (!cb) {
    return;
  }
}

INTERNAL void otrng_client_callbacks_fingerprint_seen_v3(
    const otrng_client_callbacks_s *cb, const v3_fingerprint_p fp,
    const otrng_client_conversation_s *conv) {
  if (!cb) {
    return;
  }
}

INTERNAL void otrng_client_callbacks_smp_ask_for_secret(
    const otrng_client_callbacks_s *cb,
    const otrng_client_conversation_s *conv) {
  if (!cb) {
    return;
  }
}

INTERNAL void otrng_client_callbacks_smp_ask_for_answer(
    const otrng_client_callbacks_s *cb, const char *question,
    const otrng_client_conversation_s *conv) {
  if (!cb) {
    return;
  }
}

INTERNAL void otrng_client_callbacks_smp_update(
    const otrng_client_callbacks_s *cb, const otrng_smp_event_t event,
    const uint8_t progress_percent, const otrng_client_conversation_s *conv) {
  if (!cb) {
    return;
  }
}
