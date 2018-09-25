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

#define OTRNG_CLIENT_ORCHESTRATION_PRIVATE

#include "client_orchestration.h"
#include "messaging.h"
#include <stdio.h>

tstatic void load_long_term_keys_from_storage(otrng_client_s *client) {
  fprintf(stderr, "orchestration.load_long_term_keys_from_storage\n");
  otrng_client_callbacks_load_privkey_v4(client->global_state->callbacks,
                                         client->client_id);
}

tstatic void create_long_term_keys(otrng_client_s *client) {
  fprintf(stderr, "orchestration.create_long_term_keys\n");
  otrng_client_callbacks_create_privkey_v4(client->global_state->callbacks,
                                           client->client_id);
}

tstatic void signal_error_in_state_management(otrng_client_s *client,
                                              const char *area) {
  (void)client;
  // TOOD> this should probably have a better implementation later
  fprintf(stderr, "encountered error when trying to ensure OTR state: %s\n",
          area);
}

tstatic void ensure_valid_long_term_key(otrng_client_s *client) {
  if (client->keypair == NULL) {
    load_long_term_keys_from_storage(client);
  } else {
    fprintf(stderr, "orchestration.ensure_valid_long_term_key - we already "
                    "have a keypair! Hurrah\n");
  }
  if (client->keypair == NULL) {
    create_long_term_keys(client);
  }
  // TODO: we should persist the newly created long term key as well
  if (client->keypair == NULL) {
    signal_error_in_state_management(client, "long term key pair");
  }
}

API void otrng_client_ensure_correct_state(otrng_client_s *client) {
  fprintf(stderr, "otrng_client_ensure_correct_state()\n");
  ensure_valid_long_term_key(client);
}
