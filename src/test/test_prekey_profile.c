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

void test_prekey_profile_validates() {
  uint8_t sym[ED448_PRIVATE_BYTES] = {0xFA};
  otrng_keypair_s *p1 = otrng_keypair_new();
  otrng_keypair_generate(p1, sym);

  uint8_t sym_shared[ED448_PRIVATE_BYTES] = {0xFB};
  otrng_shared_prekey_pair_s *p2 = otrng_shared_prekey_pair_new();
  otrng_shared_prekey_pair_generate(p2, sym_shared);

  otrng_prekey_profile_s *profile = otrng_prekey_profile_build(1, 1, p1, p2);

  otrng_assert(otrng_prekey_profile_valid(profile));

  time_t t = profile->expires;
  profile->expires = time(NULL) - 1;
  otrng_assert(!otrng_prekey_profile_valid(profile));
  profile->expires = t;

  // TODO: Create an invalid point

  // Change the profile to mess up with the signature
  profile->expires = profile->expires - 60;
  otrng_assert(!otrng_prekey_profile_valid(profile));

  otrng_keypair_free(p1);
  otrng_shared_prekey_pair_free(p2);
  otrng_prekey_profile_free(profile);
}
