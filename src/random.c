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

#define OTRNG_RANDOM_PRIVATE

#include "random.h"

static /*@null@*/ random_bytes_generator otrng_global_randomness = NULL;

random_bytes_generator otrng_get_current_randomness(void) {
  return otrng_global_randomness;
}

random_bytes_generator
otrng_set_current_randomness(random_bytes_generator new_randomness) {
  random_bytes_generator old = otrng_global_randomness;
  otrng_global_randomness = new_randomness;
  return old;
}
