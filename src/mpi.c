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

#define OTRNG_MPI_PRIVATE

#include "mpi.h"
#include "alloc.h"
#include "deserialize.h"
#include "serialize.h" // just for memcpy

INTERNAL void otrng_mpi_set(otrng_mpi_s *destination, const uint8_t *src,
                            size_t len) {
  if (src == NULL || len == 0) {
    destination->len = 0;
    destination->data = NULL;
    return;
  }

  destination->len = len;
  destination->data = otrng_xmalloc_z(destination->len);

  memcpy(destination->data, src, destination->len);
}

INTERNAL void otrng_mpi_copy(otrng_mpi_s *destination, const otrng_mpi_s *src) {
  otrng_mpi_set(destination, src->data, src->len);
}

tstatic otrng_bool otr_mpi_read_len(otrng_mpi_s *destination,
                                    const uint8_t *src, size_t src_len,
                                    size_t *read) {
  size_t r = 0;
  if (!otrng_deserialize_uint32(&destination->len, src, src_len, &r)) {
    return otrng_false;
  }

  if (read != NULL) {
    *read = r;
  }

  if (destination->len > src_len - r) {
    return otrng_false;
  }

  return otrng_true;
}

INTERNAL otrng_result otrng_mpi_deserialize(otrng_mpi_s *destination,
                                            const uint8_t *src, size_t src_len,
                                            size_t *read) {
  if (!otr_mpi_read_len(destination, src, src_len, read)) {
    return OTRNG_ERROR;
  }

  if (destination->len == 0) {
    destination->data = NULL;
    return OTRNG_SUCCESS;
  }

  destination->data = otrng_xmalloc_z(destination->len);

  memcpy(destination->data, src + *read, destination->len);

  if (read != NULL) {
    *read += destination->len;
  }

  return OTRNG_SUCCESS;
}

INTERNAL otrng_result otrng_mpi_deserialize_no_copy(otrng_mpi_s *destination,
                                                    const uint8_t *src,
                                                    size_t src_len,
                                                    size_t *read) {
  size_t r = 0;
  if (!otr_mpi_read_len(destination, src, src_len, &r)) {
    return OTRNG_ERROR;
  }

  if (read) {
    *read = r;
  }

  if (destination->len == 0) {
    destination->data = NULL;
    return OTRNG_SUCCESS;
  }

  /* points to original buffer without copying */
  destination->data = (uint8_t *)src + r;

  return OTRNG_SUCCESS;
}

INTERNAL size_t otrng_mpi_memcpy(uint8_t *destination, const otrng_mpi_s *mpi) {
  memcpy(destination, mpi->data, mpi->len);
  return mpi->len;
}
