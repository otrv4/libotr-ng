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

#include <glib.h>

#include "test_helpers.h"

#include "test_fixtures.h"

#include "prekey_ensemble.h"

#include "randomness.h"

static const char *fixed_domain_for_account(otrng_client_s *client, void *ctx) {
  (void)client;
  (void)ctx;

  return "otr.im";
}

static void
test_prekey_manager__otrng_prekey_request_storage_information(void) {
  char *output = NULL;
  otrng_client_id_s client_id;
  otrng_client_s *client;
  uint8_t sym2[ED448_PRIVATE_BYTES] = {2};
  uint8_t sym3[ED448_PRIVATE_BYTES] = {3};
  uint8_t fpr[OTRNG_FPRINT_HUMAN_LEN] = {1, 2, 3, 4};
  otrng_keypair_s *long_term_key, *forging_key;
  otrng_result ret;

  otrng_global_state_s *gs = otrng_xmalloc_z(sizeof(otrng_global_state_s));

  client_id.protocol = otrng_xstrdup("test-otr");
  client_id.account = otrng_xstrdup("sita@otr.im");

  client = otrng_client_new(client_id);
  client->global_state = gs;
  gs->clients = otrng_list_add(client, gs->clients);

  set_up_fixed_randomness();

  long_term_key = otrng_keypair_new();
  otrng_keypair_generate(long_term_key, sym2);

  forging_key = otrng_keypair_new();
  otrng_keypair_generate(forging_key, sym3);

  client->client_profile = otrng_client_profile_build_with_custom_expiration(
      1234, "4", long_term_key, forging_key->pub, 20020);
  client->keypair = long_term_key;
  client->forging_key = &forging_key->pub;

  otrng_prekey_ensure_manager(client, "sita@otr.im");
  otrng_prekey_provide_server_identity_for(
      client, "otr.im", "testBLABLBALA_NOT CORRECT AT ALL", fpr);

  client->prekey_manager->callbacks->domain_for_account =
      fixed_domain_for_account;

  ret = otrng_prekey_request_storage_information(&output, client, NULL);

  tear_down_fixed_randomness();

  otrng_assert_is_success(ret);
  g_assert_cmpstr(
      output, ==,
      "AAQ1AAAAAAAAAAUAAQAABNIAAgAQmEycC/sKOxBSFw1oy8ODqJQ9fkUezE1yoMGiUHqaN//"
      "+Pgsc+hoSyHqSeT/BoFTOu+P/"
      "TmdG2cwAAAMAEpiXMe67ChulppBDyMElFrFovqEjdGVLBOiz04WTujcLBxpMvj8gjuHiDpd9"
      "YeUf/Mp/hxUMGKX8AAAEAAAAATQABQAAAAAAAE40vEWYcx/"
      "c++"
      "dAjYD5MlVT1T36swabFhgnzPmffhE2sMfcVwNcK2RNnAcJkelwGLCAO208wcAwz28AQ8kA6p"
      "Wb1AefcCHxb7nZc+eT1b0zcFXGQfC0daoogDLiTWLI/"
      "KtUskpwdrSSJcDVXO0V02FshCIAGNCnDkKnQt+1YSeYkzhQYde02tj2/"
      "u1HkeqrZrL0pPAvwJRiqL+xhC0LrGDoobPlW6JAfzMibzgA.");

  client->keypair = NULL;
  client->forging_key = NULL;

  otrng_free(output);
  otrng_client_free(client);
  otrng_list_free_nodes(gs->clients);
  otrng_free(gs);
  otrng_free((char *)client_id.protocol);
  otrng_free((char *)client_id.account);
}

void units_prekey_manager_add_tests(void) {
  g_test_add_func(
      "/prekey/manager/otrng_prekey_request_storage_information",
      test_prekey_manager__otrng_prekey_request_storage_information);
}
