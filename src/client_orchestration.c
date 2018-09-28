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

tstatic void signal_error_in_state_management(otrng_client_s *client,
                                              const char *area) {
  (void)client;
  // TODO: this should probably have a better implementation later
  fprintf(stderr, "encountered error when trying to ensure OTR state: %s\n",
          area);
}

tstatic void load_long_term_keys_from_storage(otrng_client_s *client) {
  /* fprintf(stderr, "orchestration.load_long_term_keys_from_storage\n"); */
  otrng_client_callbacks_load_privkey_v4(client->global_state->callbacks,
                                         client->client_id);
}

tstatic void create_long_term_keys(otrng_client_s *client) {
  /* fprintf(stderr, "orchestration.create_long_term_keys\n"); */
  otrng_client_callbacks_create_privkey_v4(client->global_state->callbacks,
                                           client->client_id);
}

tstatic void load_client_profile_from_storage(otrng_client_s *client) {
  otrng_client_callbacks_load_client_profile(client->global_state->callbacks,
                                             client->client_id);
}

tstatic void create_client_profile(otrng_client_s *client) {
  otrng_client_callbacks_create_client_profile(client->global_state->callbacks,
                                               client, client->client_id);
}

tstatic void load_prekey_profile_from_storage(otrng_client_s *client) {
  otrng_client_callbacks_load_prekey_profile(client->global_state->callbacks,
                                             client->client_id);
}

tstatic void create_prekey_profile(otrng_client_s *client) {
  otrng_client_callbacks_create_prekey_profile(client->global_state->callbacks,
                                               client, client->client_id);
}

tstatic void ensure_valid_long_term_key(otrng_client_s *client) {
  if (client->keypair == NULL) {
    load_long_term_keys_from_storage(client);
    /* } else { */
    /*   fprintf(stderr, "orchestration.ensure_valid_long_term_key - we already
     * " */
    /*                   "have a keypair! Hurrah\n"); */
  }

  if (client->keypair == NULL) {
    create_long_term_keys(client);
  }

  if (client->keypair == NULL) {
    signal_error_in_state_management(client, "long term key pair");
  }
}

tstatic void ensure_valid_client_profile(otrng_client_s *client) {
  if (!client->client_profile) {
    load_client_profile_from_storage(client);
    /* } else { */
    /*   fprintf(stderr, "orchestration.ensure_valid_client_profile - we already
     * " */
    /*                   "have a client profile! Hurrah\n"); */
  }

  if (!client->client_profile) {
    create_client_profile(client);
  }

  if (!client->client_profile) {
    signal_error_in_state_management(client, "No Client Profile");
  }
}

static otrng_bool orchestration_reentry;
tstatic void ensure_valid_prekey_profile(otrng_client_s *client) {
  if (!client->prekey_profile) {
    load_prekey_profile_from_storage(client);
  }

  if (!client->prekey_profile) {
    create_prekey_profile(client);
  }

  if (!client->prekey_profile) {
    signal_error_in_state_management(client, "prekey profile");
  }
}

API void otrng_client_ensure_correct_state(otrng_client_s *client) {
  fprintf(stderr, "otrng_client_ensure_correct_state(client=%s)\n",
          client->client_id.account);
  if (orchestration_reentry) {
    fprintf(stderr, "ORCHESTRATION REENTRY\n");
  }

  orchestration_reentry = otrng_true;

  ensure_valid_long_term_key(client);
  ensure_valid_client_profile(client);
  ensure_valid_prekey_profile(client);

  orchestration_reentry = otrng_false;

  //
  // if ANY dependent values changed
  //    - save away a list of the changes somewhere, so that next time
  //    publication is triggered, this process knows what to do
}
