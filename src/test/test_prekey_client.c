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

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_assert(!alice->conversations);

  alice->prekey_client = otrng_prekey_client_new(
      "prekey@localhost", "alice@localhost",
      otrng_client_state_get_instance_tag(alice->state),
      otrng_client_state_get_keypair_v4(alice->state),
      otrng_client_state_get_client_profile(alice->state),
      otrng_client_state_get_prekey_profile(alice->state));

  char *dake_1 = NULL;
  dake_1 = otrng_prekey_client_publish_prekeys(alice->prekey_client);

  otrng_assert(dake_1);
  free(dake_1);

  otrl_userstate_free(alice_client_state->user_state);
  otrng_client_state_free(alice_client_state);
  otrng_client_free(alice);
}

void test_receive_prekey_server_messages(void) {
  otrng_client_state_s *alice_client_state =
      otrng_client_state_new(ALICE_IDENTITY);

  otrng_client_s *alice = set_up_client(alice_client_state, ALICE_IDENTITY, 1);
  otrng_assert(!alice->conversations);

  alice->prekey_client = otrng_prekey_client_new(
      "prekey@localhost", "alice@localhost",
      otrng_client_state_get_instance_tag(alice->state),
      otrng_client_state_get_keypair_v4(alice->state),
      otrng_client_state_get_client_profile(alice->state),
      otrng_client_state_get_prekey_profile(alice->state));

  char *dake_2 = otrng_strndup(
      "AAQ2bQJzmAAAABFwcmVrZXlzLmxvY2FsaG9zdAAQrC8mmPzxUoSAeFBbBBeR40JJ+"
      "wKa13H392zJMcy1LdsHAYqWsSjOm0HtipeiNtb06vTmtS0eCuSAFOnQ3NGhoDG0o+"
      "LAdCMHrcz9TUACdMkMK4ikUa49KYexpGDrsVRLNiH8ts8P/"
      "hC2NxqMjLdk472AqUco6fGEmR2xAHQt7zgfYs1vHJYgFjGYvvdDtqhvOHl5ZT7BSz2F2KU97"
      "piYkyt5mKGQkhLgwTmHdvDtblcPVydZIvmhsNxMNQh/"
      "1wNoR6VwRppufi1rD56gI2ZQPs13PJaRM6FfF4Ds6ymTAPsDI02wiyqNtdHYjZEEtJ+"
      "LxvBXHexnLvTZ1XIvgwAhZD/7ecLmDqBoqHB/p/"
      "9TdiQ8vJy8XqUwfvIQYQtJYrje6iB6rT+"
      "bGf0lW0wIMLIRPvy5SWVnsFNuZILllsxDesb5wKuS9LgSyhiS04YQ/"
      "OTzyjnjDV3JNh2uCEjGWmZSmu04GaxcNwapbELZTyCWlmDhMWqJ96UNbPsHiCVD86uuPlNw5"
      "Cxb9O09MWwGEo664TMwzFc+"
      "vYjSTFISps6lIicYbx4qQt6wii5gwqgZssouuxMD6Ubv7GzLVixS5evkfuA0.",
      642);

  char *to_send = NULL;
  otrng_assert_is_success(otrng_prekey_client_receive(
      &to_send, "prekey@localhost", dake_2, alice->prekey_client));

  otrng_assert(!to_send); /* wrong instance tag */

  free(dake_2);

  char *success = otrng_strndup("AAQGbQJzmIlxG+O+"
                                "2z7bcBMm5pWSQ2FqVbIrXLiJTaDsgfETk59Dnxa5US0avH"
                                "pUD6qTyooaIh2Mqg6PXojQOmWKnj3LqBM=.",
                                98);

  otrng_assert_is_success(otrng_prekey_client_receive(
      &to_send, "prekey@localhost", success, alice->prekey_client));

  otrng_assert(!to_send); /* wrong instance tag */

  free(success);

  otrl_userstate_free(alice_client_state->user_state);
  otrng_client_state_free(alice_client_state);
  otrng_client_free(alice);
}
