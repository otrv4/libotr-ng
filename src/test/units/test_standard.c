/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2019, the libotr-ng contributors.
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

#include "str.h"

static void test_otrng_stpcpy(void) {
  char *dst = otrng_xstrdup("abcd");
  char *src = otrng_xstrdup("12");
  char *ret = otrng_stpcpy(dst, src);

  otrng_assert(ret == dst + 2);
  otrng_assert(dst[0] == '1');
  otrng_assert(dst[1] == '2');
  otrng_assert(dst[2] == 0);
  otrng_assert(dst[3] == 'd');
  otrng_assert(dst[4] == 0);

  otrng_free(dst);
  otrng_free(src);
}

static void test_otrng_stpncpy(void) {
  char *dst = otrng_xstrdup("abcd");
  char *src = otrng_xstrdup("123");
  char *ret = otrng_stpncpy(dst, src, 2);

  otrng_assert(ret == dst + 2);
  otrng_assert(dst[0] == '1');
  otrng_assert(dst[1] == '2');
  otrng_assert(dst[2] == 'c');
  otrng_assert(dst[3] == 'd');
  otrng_assert(dst[4] == 0);

  otrng_free(dst);
  otrng_free(src);

  dst = otrng_xstrdup("abcde");
  src = otrng_xstrdup("12");
  ret = otrng_stpncpy(dst, src, 4);

  otrng_assert(ret == dst + 2);
  otrng_assert(dst[0] == '1');
  otrng_assert(dst[1] == '2');
  otrng_assert(dst[2] == 0);
  otrng_assert(dst[3] == 0);
  otrng_assert(dst[4] == 'e');
  otrng_assert(dst[5] == 0);

  otrng_free(dst);
  otrng_free(src);
}

static void test_otrng_strnlen(void) {
  const char *src = "abc";
  otrng_assert(0 == otrng_strnlen(src, 0));
  otrng_assert(1 == otrng_strnlen(src, 1));
  otrng_assert(2 == otrng_strnlen(src, 2));
  otrng_assert(3 == otrng_strnlen(src, 3));
  otrng_assert(3 == otrng_strnlen(src, 4));
  otrng_assert(3 == otrng_strnlen(src, 5));
}

void units_standard_add_tests(void) {
  g_test_add_func("/standard/stpcpy", test_otrng_stpcpy);
  g_test_add_func("/standard/stpncpy", test_otrng_stpncpy);
  g_test_add_func("/standard/strnlen", test_otrng_strnlen);
}
