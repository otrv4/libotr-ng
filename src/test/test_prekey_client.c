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

void test_prekey_ensemble_publishing(void) {
  otrng_client_state_s *alice_client_state =
      otrng_client_state_new(ALICE_IDENTITY);
  // otrng_client_state_s *bob_client_state =
  // otrng_client_state_new(BOB_IDENTITY);

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_assert(!alice->conversations);

  alice->prekey_client = otrng_prekey_client_new(
      "prekey@localhost", "alice@localhost",
      otrng_client_state_get_instance_tag(alice->state),
      otrng_client_state_get_keypair_v4(alice->state),
      otrng_client_state_get_client_profile(alice->state),
      otrng_client_state_get_prekey_profile(alice->state));

  char *message = NULL;
  message = otrng_prekey_client_publish_prekeys(alice->prekey_client);

  free(message);

  otrl_userstate_free(alice_client_state->user_state);
  otrng_client_state_free(alice_client_state);
}
