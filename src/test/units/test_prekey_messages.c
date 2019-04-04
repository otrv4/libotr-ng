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

#include "base64.h"
#include "prekey_message.h"

static void test_deserialize_prekey_success_message(void) {
  const char *prekey_success_message =
      "AAQGbQJzmFMujbgWDP1BjPZbsEO61+"
      "AmGPalm6QFnGugNXodeVM3MXxnMaWaLSxRkTfTPF3b+IDnuaOgnKIt8ckRvrjseEA=.";

  size_t len = strlen(prekey_success_message);
  uint8_t *decoded = NULL;
  size_t decoded_len = 0;

  decoded = otrng_xmalloc_z(((len - 1 + 3) / 4) * 3);
  decoded_len = otrl_base64_decode(decoded, prekey_success_message, len - 1);

  otrng_assert(decoded_len == OTRNG_PREKEY_SUCCESS_MSG_LEN);

  otrng_prekey_success_message_s dst;
  otrng_assert_is_success(
      otrng_prekey_success_message_deserialize(&dst, decoded, decoded_len));

  uint8_t expected_success_mac[HASH_BYTES] = {
      0x53, 0x2e, 0x8d, 0xb8, 0x16, 0x0c, 0xfd, 0x41, 0x8c, 0xf6, 0x5b,
      0xb0, 0x43, 0xba, 0xd7, 0xe0, 0x26, 0x18, 0xf6, 0xa5, 0x9b, 0xa4,
      0x05, 0x9c, 0x6b, 0xa0, 0x35, 0x7a, 0x1d, 0x79, 0x53, 0x37, 0x31,
      0x7c, 0x67, 0x31, 0xa5, 0x9a, 0x2d, 0x2c, 0x51, 0x91, 0x37, 0xd3,
      0x3c, 0x5d, 0xdb, 0xf8, 0x80, 0xe7, 0xb9, 0xa3, 0xa0, 0x9c, 0xa2,
      0x2d, 0xf1, 0xc9, 0x11, 0xbe, 0xb8, 0xec, 0x78, 0x40,
  };

  otrng_assert_cmpmem(dst.mac, expected_success_mac, HASH_BYTES);

  otrng_free(decoded);
}

void units_prekey_messages_add_tests(void) {
  g_test_add_func("/prekey_messages/deserialize_prekey_success_message",
                  test_deserialize_prekey_success_message);
}
