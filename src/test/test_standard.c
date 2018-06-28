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

void test_otrng_stpcpy(void) {
  char *dst = otrng_strdup("abcd");
  char *src = otrng_strdup("12");
  char *ret = otrng_stpcpy(dst, src);

  otrng_assert(ret == dst + 2);
  otrng_assert(dst[0] == '1');
  otrng_assert(dst[1] == '2');
  otrng_assert(dst[2] == 0);
  otrng_assert(dst[3] == 'd');
  otrng_assert(dst[4] == 0);

  free(dst);
  free(src);
}

void test_otrng_stpncpy(void) {
  char *dst = otrng_strdup("abcd");
  char *src = otrng_strdup("123");
  char *ret = otrng_stpncpy(dst, src, 2);

  otrng_assert(ret == dst + 2);
  otrng_assert(dst[0] == '1');
  otrng_assert(dst[1] == '2');
  otrng_assert(dst[2] == 'c');
  otrng_assert(dst[3] == 'd');
  otrng_assert(dst[4] == 0);

  free(dst);
  free(src);

  dst = otrng_strdup("abcde");
  src = otrng_strdup("12");
  ret = otrng_stpncpy(dst, src, 4);

  otrng_assert(ret == dst + 2);
  otrng_assert(dst[0] == '1');
  otrng_assert(dst[1] == '2');
  otrng_assert(dst[2] == 0);
  otrng_assert(dst[3] == 0);
  otrng_assert(dst[4] == 'e');
  otrng_assert(dst[5] == 0);

  free(dst);
  free(src);
}

void test_otrng_strnlen(void) {
  const char *src = "abc";
  otrng_assert(0 == otrng_strnlen(src, 0));
  otrng_assert(1 == otrng_strnlen(src, 1));
  otrng_assert(2 == otrng_strnlen(src, 2));
  otrng_assert(3 == otrng_strnlen(src, 3));
  otrng_assert(3 == otrng_strnlen(src, 4));
  otrng_assert(3 == otrng_strnlen(src, 5));
}
