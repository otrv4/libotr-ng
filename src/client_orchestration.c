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

#include <stdio.h>

#include "client_orchestration.h"
#include "debug.h"
#include "messaging.h"

tstatic void signal_error_in_state_management(otrng_client_s *client,
                                              const char *area) {
  (void)client;
  // this should probably have a better implementation later
  otrng_debug_fprintf(
      stderr, "encountered error when trying to ensure OTR state: %s\n", area);
}

tstatic void load_long_term_keys_from_storage(otrng_client_s *client) {
  otrng_debug_enter("orchestration.load_long_term_keys_from_storage");
  client->global_state->callbacks->load_privkey_v4(client);
  otrng_debug_exit("orchestration.load_long_term_keys_from_storage");
}

tstatic void load_long_term_keys_v3_from_storage(otrng_client_s *client) {
  otrng_debug_enter("orchestration.load_long_term_keys_v3_from_storage");
  client->global_state->callbacks->load_privkey_v3(client);
  otrng_debug_exit("orchestration.load_long_term_keys_v3_from_storage");
}

tstatic void load_forging_key_from_storage(otrng_client_s *client) {
  otrng_debug_enter("orchestration.load_forging_key_from_storage");
  client->global_state->callbacks->load_forging_key(client);
  otrng_debug_exit("orchestration.load_forging_key_from_storage");
}

tstatic void create_long_term_keys(otrng_client_s *client) {
  otrng_debug_enter("orchestration.create_long_term_keys");
  client->global_state->callbacks->create_privkey_v4(client);
  otrng_debug_exit("orchestration.create_long_term_keys");
}

tstatic void create_long_term_keys_v3(otrng_client_s *client) {
  otrng_debug_enter("orchestration.create_long_term_keys_v3");
  client->global_state->callbacks->create_privkey_v3(client);
  otrng_debug_exit("orchestration.create_long_term_keys_v3");
}

tstatic void create_forging_key(otrng_client_s *client) {
  otrng_debug_enter("orchestration.create_forging_key");
  client->global_state->callbacks->create_forging_key(client);
  otrng_debug_exit("orchestration.create_forging_key");
}

tstatic void load_client_profile_from_storage(otrng_client_s *client) {
  otrng_debug_enter("orchestration.load_client_profile_from_storage");
  client->global_state->callbacks->load_client_profile(client);
  otrng_debug_exit("orchestration.load_client_profile_from_storage");
}

tstatic void load_expired_client_profile_from_storage(otrng_client_s *client) {
  otrng_debug_enter("orchestration.load_expired_client_profile_from_storage");
  client->global_state->callbacks->load_expired_client_profile(client);
  otrng_debug_exit("orchestration.load_expired_client_profile_from_storage");
}

tstatic void load_expired_prekey_profile_from_storage(otrng_client_s *client) {
  otrng_debug_enter("orchestration.load_expired_prekey_profile_from_storage");
  client->global_state->callbacks->load_expired_prekey_profile(client);
  otrng_debug_exit("orchestration.load_expired_prekey_profile_from_storage");
}

tstatic void create_client_profile(otrng_client_s *client) {
  otrng_debug_enter("orchestration.create_client_profile");
  client->global_state->callbacks->create_client_profile(client);
  otrng_debug_exit("orchestration.create_client_profile");
}

tstatic void load_prekey_profile_from_storage(otrng_client_s *client) {
  otrng_debug_enter("orchestration.load_prekey_profile_from_storage");
  client->global_state->callbacks->load_prekey_profile(client);
  otrng_debug_exit("orchestration.load_prekey_profile_from_storage");
}

tstatic void create_prekey_profile(otrng_client_s *client) {
  otrng_debug_enter("orchestration.create_prekey_profile");
  client->global_state->callbacks->create_prekey_profile(client);
  otrng_debug_exit("orchestration.create_prekey_profile");
}

tstatic void clean_client_profile(otrng_client_s *client) {
  if (client->client_profile != NULL) {
    otrng_client_profile_free(client->client_profile);
    client->client_profile = NULL;
  }
}

tstatic void clean_expired_client_profile(otrng_client_s *client) {
  if (client->exp_client_profile != NULL) {
    otrng_client_profile_free(client->exp_client_profile);
    client->exp_client_profile = NULL;
  }
}

tstatic void clean_expired_prekey_profile(otrng_client_s *client) {
  if (client->exp_prekey_profile != NULL) {
    otrng_prekey_profile_free(client->exp_prekey_profile);
    client->exp_prekey_profile = NULL;
  }
}

tstatic void clean_prekey_profile(otrng_client_s *client) {
  if (client->prekey_profile != NULL) {
    otrng_prekey_profile_free(client->prekey_profile);
    client->prekey_profile = NULL;
  }
}

tstatic otrng_bool verify_valid_long_term_key(otrng_client_s *client) {
  if (client->keypair == NULL) {
    return otrng_false;
  }
  return otrng_true;
}

tstatic otrng_bool verify_valid_forging_key(otrng_client_s *client) {
  if (client->forging_key == NULL) {
    return otrng_false;
  }
  return otrng_true;
}

tstatic otrng_bool ensure_valid_long_term_key(otrng_client_s *client) {
  if (verify_valid_long_term_key(client)) {
    return otrng_true;
  }

  load_long_term_keys_from_storage(client);

  if (verify_valid_long_term_key(client)) {
    return otrng_true;
  }

  create_long_term_keys(client);

  if (verify_valid_long_term_key(client)) {
    clean_client_profile(client);
    clean_prekey_profile(client);
    client->global_state->callbacks->store_privkey_v4(client);
    return otrng_true;
  }

  signal_error_in_state_management(client, "No long term key pair");
  return otrng_false;
}

tstatic otrng_bool ensure_valid_forging_key(otrng_client_s *client) {
  if (verify_valid_forging_key(client)) {
    return otrng_true;
  }

  load_forging_key_from_storage(client);

  if (verify_valid_forging_key(client)) {
    return otrng_true;
  }

  create_forging_key(client);

  if (verify_valid_forging_key(client)) {
    clean_client_profile(client);
    client->global_state->callbacks->store_forging_key(client);
    return otrng_true;
  }

  signal_error_in_state_management(client, "No forging key");
  return otrng_false;
}

tstatic otrng_bool verify_valid_client_profile(otrng_client_s *client) {
  uint32_t instag;

  if (client->client_profile == NULL) {
    return otrng_false;
  }

  if (!otrng_ec_point_eq(client->keypair->pub,
                         client->client_profile->long_term_pub_key)) {
    return otrng_false;
  }

  if (!otrng_ec_point_eq(*client->forging_key,
                         client->client_profile->forging_pub_key)) {
    return otrng_false;
  }

  instag = otrng_client_get_instance_tag(client);
  return otrng_client_profile_fast_valid(client->client_profile, instag);
}

tstatic otrng_bool verify_valid_expired_client_profile(otrng_client_s *client) {
  uint32_t instag;

  if (client->exp_client_profile == NULL) {
    return otrng_false;
  }

  if (!otrng_ec_point_eq(client->keypair->pub,
                         client->exp_client_profile->long_term_pub_key)) {
    return otrng_false;
  }

  if (!otrng_ec_point_eq(*client->forging_key,
                         client->exp_client_profile->forging_pub_key)) {
    return otrng_false;
  }

  instag = otrng_client_get_instance_tag(client);
  return otrng_client_profile_fast_valid(client->exp_client_profile, instag) ||
         otrng_client_profile_is_expired_but_valid(
             client->exp_client_profile, instag,
             client->profiles_extra_valid_time);
}

tstatic otrng_bool verify_valid_expired_prekey_profile(otrng_client_s *client) {
  uint32_t instag;

  if (client->exp_prekey_profile == NULL) {
    return otrng_false;
  }

  instag = otrng_client_get_instance_tag(client);
  return otrng_prekey_profile_fast_valid(client->exp_prekey_profile, instag,
                                         client->keypair->pub) ||
         otrng_prekey_profile_is_expired_but_valid(
             client->exp_prekey_profile, instag,
             client->profiles_extra_valid_time, client->keypair->pub);
}

tstatic otrng_bool verify_valid_prekey_profile(otrng_client_s *client) {
  uint32_t instag;

  if (client->prekey_profile == NULL) {
    return otrng_false;
  }

  instag = otrng_client_get_instance_tag(client);
  return otrng_prekey_profile_fast_valid(client->prekey_profile, instag,
                                         client->keypair->pub);
}

tstatic void move_client_profile_to_expired(otrng_client_s *client) {
  otrng_debug_enter("move_client_profile_to_expired");
  clean_expired_client_profile(client);
  client->exp_client_profile = client->client_profile;
  client->client_profile = NULL;

  client->global_state->callbacks->store_expired_client_profile(client);

  otrng_debug_exit("move_client_profile_to_expired");
}

tstatic void move_prekey_profile_to_expired(otrng_client_s *client) {
  otrng_debug_enter("move_prekey_profile_to_expired");

  if (client->exp_prekey_profile) {
    otrng_prekey_profile_free(client->exp_prekey_profile);
    client->exp_prekey_profile = NULL;
  }
  client->exp_prekey_profile = client->prekey_profile;
  client->prekey_profile = NULL;

  client->global_state->callbacks->store_expired_prekey_profile(client);

  otrng_debug_exit("move_prekey_profile_to_expired");
}

tstatic void check_if_expired_client_profile(otrng_client_s *client) {
  uint32_t instag;
  if (client->client_profile) {
    instag = otrng_client_get_instance_tag(client);
    if (otrng_client_profile_is_expired_but_valid(
            client->client_profile, instag,
            client->profiles_extra_valid_time)) {
      move_client_profile_to_expired(client);
    }
  }
}

tstatic void check_if_expired_prekey_profile(otrng_client_s *client) {
  uint32_t instag;
  if (client->prekey_profile) {
    instag = otrng_client_get_instance_tag(client);
    if (otrng_prekey_profile_is_expired_but_valid(
            client->prekey_profile, instag, client->profiles_extra_valid_time,
            client->keypair->pub)) {
      move_prekey_profile_to_expired(client);
    }
  }
}

tstatic otrng_bool
check_if_not_close_to_expired_client_profile(otrng_client_s *client) {
  if (otrng_client_profile_is_close_to_expiry(client->client_profile,
                                              client->profiles_buffer_time)) {
    move_client_profile_to_expired(client);
    return otrng_false;
  }
  return otrng_true;
}

tstatic otrng_bool
check_if_not_close_to_expired_prekey_profile(otrng_client_s *client) {
  if (otrng_prekey_profile_is_close_to_expiry(client->prekey_profile,
                                              client->profiles_buffer_time)) {
    move_prekey_profile_to_expired(client);
    return otrng_false;
  }
  return otrng_true;
}

tstatic otrng_bool ensure_valid_client_profile(otrng_client_s *client) {
  check_if_expired_client_profile(client);

  if (verify_valid_client_profile(client)) {
    if (check_if_not_close_to_expired_client_profile(client)) {
      return otrng_true;
    }
  }

  clean_client_profile(client);
  load_client_profile_from_storage(client);
  check_if_expired_client_profile(client);

  if (verify_valid_client_profile(client)) {
    if (check_if_not_close_to_expired_client_profile(client)) {
      return otrng_true;
    }
  }

  clean_client_profile(client);
  create_client_profile(client);

  if (verify_valid_client_profile(client)) {
    client->client_profile->should_publish = otrng_true;
    client->should_publish = otrng_true;

    client->global_state->callbacks->store_client_profile(client);
    return otrng_true;
  }

  clean_client_profile(client);
  signal_error_in_state_management(client, "No Client Profile");
  return otrng_false;
}

tstatic void ensure_valid_expired_client_profile(otrng_client_s *client) {
  if (verify_valid_expired_client_profile(client)) {
    return;
  }

  clean_expired_client_profile(client);
  load_expired_client_profile_from_storage(client);

  if (verify_valid_expired_client_profile(client)) {
    return;
  }

  clean_expired_client_profile(client);
  client->global_state->callbacks->store_expired_client_profile(client);
}

tstatic void ensure_valid_expired_prekey_profile(otrng_client_s *client) {
  if (verify_valid_expired_prekey_profile(client)) {
    return;
  }

  clean_expired_prekey_profile(client);
  load_expired_prekey_profile_from_storage(client);

  if (verify_valid_expired_prekey_profile(client)) {
    return;
  }

  clean_expired_prekey_profile(client);
  client->global_state->callbacks->store_expired_prekey_profile(client);
}

tstatic otrng_bool ensure_valid_prekey_profile(otrng_client_s *client) {
  check_if_expired_prekey_profile(client);

  if (verify_valid_prekey_profile(client)) {
    if (check_if_not_close_to_expired_prekey_profile(client)) {
      return otrng_true;
    }
  }

  clean_prekey_profile(client);
  load_prekey_profile_from_storage(client);
  check_if_expired_prekey_profile(client);

  if (verify_valid_prekey_profile(client)) {
    if (check_if_not_close_to_expired_prekey_profile(client)) {
      return otrng_true;
    }
  }

  clean_prekey_profile(client);
  create_prekey_profile(client);

  if (verify_valid_prekey_profile(client)) {
    client->prekey_profile->should_publish = otrng_true;
    client->should_publish = otrng_true;

    client->global_state->callbacks->store_prekey_profile(client);
    return otrng_true;
  }

  clean_prekey_profile(client);
  signal_error_in_state_management(client, "No Prekey Profile");
  return otrng_false;
}

tstatic void create_new_prekey_messages(otrng_client_s *client) {
  prekey_message_s **messages;
  size_t ix;
  size_t to_publish =
      client->max_published_prekey_msg - otrng_list_len(client->our_prekeys);

  if (client->prekey_msgs_num_to_publish > to_publish) {
    to_publish = client->prekey_msgs_num_to_publish;
  }

  if (to_publish > 0) {
    otrng_debug_enter("create_new_prekey_messages > 0");
    client->prekey_msgs_num_to_publish = 0;

    messages = otrng_client_build_prekey_messages(to_publish, client);
    for (ix = 0; ix < to_publish; ix++) {
      messages[ix]->should_publish = otrng_true;
    }
    otrng_free(messages);

    otrng_debug_exit("create_new_prekey_messages > 0");
  }
}

tstatic void load_prekey_messages_from_storage(otrng_client_s *client) {
  otrng_debug_enter("orchestration.load_prekey_messages_from_storage");
  client->global_state->callbacks->load_prekey_messages(client);
  otrng_debug_exit("orchestration.load_prekey_messages_from_storage");
}

tstatic otrng_bool verify_enough_prekey_messages(otrng_client_s *client) {
  if (otrng_list_len(client->our_prekeys) >=
      client->minimum_stored_prekey_msg) {
    return otrng_true;
  }
  return otrng_false;
}

tstatic otrng_bool ensure_enough_prekey_messages(otrng_client_s *client) {
  if (verify_enough_prekey_messages(client)) {
    return otrng_true;
  }

  load_prekey_messages_from_storage(client);

  if (verify_enough_prekey_messages(client)) {
    return otrng_true;
  }

  create_new_prekey_messages(client);

  if (verify_enough_prekey_messages(client)) {
    client->should_publish = otrng_true;
    client->global_state->callbacks->store_prekey_messages(client);
    return otrng_true;
  }

  signal_error_in_state_management(client, "No Prekey Messages");
  return otrng_false;
}

tstatic otrng_bool verify_valid_long_term_key_v3(otrng_client_s *client) {
  if (otrl_privkey_find(client->global_state->user_state_v3,
                        client->client_id.account,
                        client->client_id.protocol) != NULL) {
    return otrng_true;
  }
  return otrng_false;
}

tstatic otrng_bool ensure_valid_long_term_key_v3(otrng_client_s *client) {
  if (verify_valid_long_term_key_v3(client)) {
    return otrng_true;
  }

  load_long_term_keys_v3_from_storage(client);

  if (verify_valid_long_term_key_v3(client)) {
    return otrng_true;
  }

  create_long_term_keys_v3(client);

  if (verify_valid_long_term_key_v3(client)) {
    clean_client_profile(client);
    client->global_state->callbacks->store_privkey_v3(client);
    return otrng_true;
  }

  signal_error_in_state_management(client, "No long term v3 key pair");
  return otrng_false;
}

/* Note, the ensure_ family of functions will check whether the
   values are there and correct, and try to fix them if not.
   The verify_ family of functions will just check that the values
   are correct and return otrng_false if not. */
/* TODO: this function should be called from the plugin every X amount of time,
   by default every 67'th minute. This way we don't have to set specific
   timers to check for expiry of prekey profiles and client profiles */
API void otrng_client_ensure_correct_state(otrng_client_s *client) {
  otrng_debug_enter("otrng_client_ensure_correct_state");
  otrng_debug_fprintf(stderr, "client=%s\n", client->client_id.account);

  if (!ensure_valid_long_term_key(client)) {
    otrng_debug_exit("otrng_client_ensure_correct_state");
    return;
  }

  if (!ensure_valid_long_term_key_v3(client)) {
    otrng_debug_exit("otrng_client_ensure_correct_state");
    return;
  }

  if (!ensure_valid_forging_key(client)) {
    otrng_debug_exit("otrng_client_ensure_correct_state");
    return;
  }

  if (!ensure_valid_client_profile(client)) {
    otrng_debug_exit("otrng_client_ensure_correct_state");
    return;
  }

  ensure_valid_expired_client_profile(client);

  if (!ensure_valid_prekey_profile(client)) {
    otrng_debug_exit("otrng_client_ensure_correct_state");
    return;
  }

  ensure_valid_expired_prekey_profile(client);

  if (!ensure_enough_prekey_messages(client)) {
    otrng_debug_exit("otrng_client_ensure_correct_state");
    return;
  }

  otrng_debug_exit("otrng_client_ensure_correct_state");
}

API otrng_bool otrng_client_verify_correct_state(otrng_client_s *client) {
  if (!verify_valid_long_term_key(client)) {
    return otrng_false;
  }

  if (!verify_valid_long_term_key_v3(client)) {
    return otrng_false;
  }

  if (!verify_valid_forging_key(client)) {
    return otrng_false;
  }

  if (!verify_valid_client_profile(client)) {
    return otrng_false;
  }

  if (!verify_valid_prekey_profile(client)) {
    return otrng_false;
  }

  return otrng_true;
}
