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

#include "str.h"

static void test_otrng_stpcpy(void) {
  char *destination = otrng_xstrdup("abcd");
  char *source = otrng_xstrdup("12");
  char *ret = otrng_stpcpy(destination, source);

  otrng_assert(ret == destination + 2);
  otrng_assert(destination[0] == '1');
  otrng_assert(destination[1] == '2');
  otrng_assert(destination[2] == 0);
  otrng_assert(destination[3] == 'd');
  otrng_assert(destination[4] == 0);

  free(destination);
  free(source);
}

static void test_otrng_stpncpy(void) {
  char *destination = otrng_xstrdup("abcd");
  char *source = otrng_xstrdup("123");
  char *ret = otrng_stpncpy(destination, source, 2);

  otrng_assert(ret == destination + 2);
  otrng_assert(destination[0] == '1');
  otrng_assert(destination[1] == '2');
  otrng_assert(destination[2] == 'c');
  otrng_assert(destination[3] == 'd');
  otrng_assert(destination[4] == 0);

  free(destination);
  free(source);

  destination = otrng_xstrdup("abcde");
  source = otrng_xstrdup("12");
  ret = otrng_stpncpy(destination, source, 4);

  otrng_assert(ret == destination + 2);
  otrng_assert(destination[0] == '1');
  otrng_assert(destination[1] == '2');
  otrng_assert(destination[2] == 0);
  otrng_assert(destination[3] == 0);
  otrng_assert(destination[4] == 'e');
  otrng_assert(destination[5] == 0);

  free(destination);
  free(source);
}

static void test_otrng_strnlen(void) {
  const char *source = "abc";
  otrng_assert(0 == otrng_strnlen(source, 0));
  otrng_assert(1 == otrng_strnlen(source, 1));
  otrng_assert(2 == otrng_strnlen(source, 2));
  otrng_assert(3 == otrng_strnlen(source, 3));
  otrng_assert(3 == otrng_strnlen(source, 4));
  otrng_assert(3 == otrng_strnlen(source, 5));
}

void units_standard_add_tests(void) {
  g_test_add_func("/standard/stpcpy", test_otrng_stpcpy);
  g_test_add_func("/standard/stpncpy", test_otrng_stpncpy);
  g_test_add_func("/standard/strnlen", test_otrng_strnlen);
}
