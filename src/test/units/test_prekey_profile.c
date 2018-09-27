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
#include "instance_tag.h"
#include "serialize.h"

static void test_prekey_profile_validates() {
  uint8_t sym[ED448_PRIVATE_BYTES] = {0xFA};
  otrng_keypair_s *long_term = otrng_keypair_new();
  otrng_keypair_generate(long_term, sym);

  uint8_t sym_shared[ED448_PRIVATE_BYTES] = {0xFB};
  otrng_shared_prekey_pair_s *shared_prekey = otrng_shared_prekey_pair_new();
  otrng_shared_prekey_pair_generate(shared_prekey, sym_shared);

  otrng_prekey_profile_s *profile = otrng_prekey_profile_build(
      OTRNG_MIN_VALID_INSTAG + 0x01, long_term, shared_prekey);

  otrng_assert(otrng_prekey_profile_valid(profile, profile->instance_tag,
                                          long_term->pub));

  otrng_assert(!otrng_prekey_profile_valid(profile, profile->instance_tag + 1,
                                           long_term->pub));

  time_t t = profile->expires;
  profile->expires = time(NULL) - 1;
  otrng_assert(!otrng_prekey_profile_valid(profile, profile->instance_tag,
                                           long_term->pub));
  profile->expires = t;

  // TODO: Create an invalid point

  // Change the profile to mess up with the signature
  profile->expires = profile->expires - 60;
  otrng_assert(!otrng_prekey_profile_valid(profile, profile->instance_tag,
                                           long_term->pub));

  otrng_keypair_free(long_term);
  otrng_shared_prekey_pair_free(shared_prekey);
  otrng_prekey_profile_free(profile);
}

static void test_prekey_profile_serialize() {
  uint32_t instance_tag = OTRNG_MIN_VALID_INSTAG + 0x01;
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  otrng_shared_prekey_pair_s *shared_prekey = otrng_shared_prekey_pair_new();
  otrng_shared_prekey_pair_generate(shared_prekey, sym);

  otrng_prekey_profile_s *profile =
      otrng_prekey_profile_build(instance_tag, keypair, shared_prekey);

  otrng_assert(profile != NULL);

  otrng_ec_point_copy(profile->shared_prekey, shared_prekey->pub);
  profile->expires = 15;
  memset(profile->signature, 0, ED448_SIGNATURE_BYTES);

  uint8_t expected_shared_prekey[ED448_SHARED_PREKEY_BYTES] = {0};
  otrng_serialize_shared_prekey(expected_shared_prekey, shared_prekey->pub);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_assert_is_success(
      otrng_prekey_profile_asprint(&serialized, &written, profile));
  g_assert_cmpint(written, ==, 185);

  char expected[] = {
      0x0, 0x0, 0x01, 0x01,                      /* Instance tag */
      0x0, 0x0, 0x0,  0x0,  0x0, 0x0, 0x0, 0x0F, /* Expiration */
  };

  otrng_assert_cmpmem(expected, serialized, sizeof(expected));

  uint8_t *cursor = serialized + sizeof(expected);
  otrng_assert_cmpmem(expected_shared_prekey, cursor,
                      ED448_SHARED_PREKEY_BYTES);
  cursor += ED448_SHARED_PREKEY_BYTES;

  char expected_signature[ED448_SIGNATURE_BYTES] = {0};
  otrng_assert_cmpmem(expected_signature, cursor, ED448_SIGNATURE_BYTES);

  free(serialized);
  otrng_prekey_profile_free(profile);
  otrng_shared_prekey_pair_free(shared_prekey);
}

static void test_prekey_profile_deserialize() {
  uint32_t instance_tag = OTRNG_MIN_VALID_INSTAG + 0x01;
  otrng_keypair_p keypair;
  uint8_t sym[ED448_PRIVATE_BYTES] = {1};
  otrng_keypair_generate(keypair, sym);

  otrng_shared_prekey_pair_s *shared_prekey = otrng_shared_prekey_pair_new();
  otrng_shared_prekey_pair_generate(shared_prekey, sym);

  otrng_prekey_profile_s *profile =
      otrng_prekey_profile_build(instance_tag, keypair, shared_prekey);

  otrng_assert(profile != NULL);

  size_t written = 0;
  uint8_t *serialized = NULL;
  otrng_prekey_profile_asprint(&serialized, &written, profile);

  otrng_prekey_profile_s *deserialized =
      otrng_xmalloc(sizeof(otrng_prekey_profile_s));

  otrng_assert_is_success(otrng_prekey_profile_deserialize(
      deserialized, serialized, written, NULL));
  otrng_assert_prekey_profile_eq(deserialized, profile);

  free(serialized);
  otrng_prekey_profile_free(profile);
  otrng_prekey_profile_free(deserialized);
  otrng_shared_prekey_pair_free(shared_prekey);
}

void units_prekey_profile_add_tests(void) {
  g_test_add_func("/prekey_profile/validates",
  test_prekey_profile_validates);
  g_test_add_func("/prekey_profile/serialize",
  test_prekey_profile_serialize);
  g_test_add_func("/prekey_profile/deserialize",
                  test_prekey_profile_deserialize);
}
