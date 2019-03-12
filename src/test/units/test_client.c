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
#include <stdio.h>

#include "test_helpers.h"

#include "test_fixtures.h"

#include "client.h"
#include "fragment.h"
#include "instance_tag.h"
#include "messaging.h"
#include "serialize.h"
#include "shake.h"

static void test_client_get_our_fingerprint() {
  otrng_client_s *alice = otrng_client_new(ALICE_IDENTITY);
  set_up_client(alice, 1);

  otrng_fingerprint expected_fp = {0};
  otrng_assert(otrng_serialize_fingerprint(expected_fp, alice->keypair->pub,
                                           *alice->forging_key));

  otrng_fingerprint our_fp = {0};
  otrng_assert_is_success(otrng_client_get_our_fingerprint(our_fp, alice));
  otrng_assert_cmpmem(expected_fp, our_fp, sizeof(otrng_fingerprint));

  otrng_global_state_free(alice->global_state);
}

static void test_fingerprint_hash_to_human() {
  const char *expected_fp = "00010203 04050607 08090A0B 0C0D0E0F "
                            "10111213 14151617 18191A1B 1C1D1E1F "
                            "20212223 24252627 28292A2B 2C2D2E2F "
                            "30313233 34353637";

  uint8_t fp_hash[FPRINT_LEN_BYTES] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  };

  char fp_human[OTRNG_FPRINT_HUMAN_LEN];
  memset(fp_human, 0, sizeof fp_hash);

  otrng_fingerprint_hash_to_human(fp_human, fp_hash);

  g_assert_cmpint(0, ==,
                  strncmp(expected_fp, fp_human, OTRNG_FPRINT_HUMAN_LEN));
}

void units_client_add_tests(void) {
  g_test_add_func("/client/fingerprint_to_human",
                  test_fingerprint_hash_to_human);
  g_test_add_func("/client/get_our_fingerprint",
                  test_client_get_our_fingerprint);
}
