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

#include "otrng.h"
#include <gcrypt.h>
#include <glib.h>

#include "functionals/all.h"
#include "units/all.h"

int main(int argc, char **argv) {
  if (!gcry_check_version(GCRYPT_VERSION))
    return 2;

  gcry_control(GCRYCTL_INIT_SECMEM, 0); // disable secure memory for tests
  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
  gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED);

  OTRNG_INIT;

  g_test_init(&argc, &argv, NULL);

  REGISTER_UNITS;
  REGISTER_FUNCTIONALS;

  int ret = g_test_run();
  OTRNG_FREE;
  return ret;
}
