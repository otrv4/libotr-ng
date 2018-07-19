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

#ifndef OTRNG_MPI_H
#define OTRNG_MPI_H

#include <stdint.h>
#include <stdlib.h>

#include "error.h"
#include "shared.h"

typedef struct otrng_mpi_s {
  uint32_t len;
  uint8_t *data;
} otrng_mpi_s, otrng_mpi_p[1];

INTERNAL void otrng_mpi_init(otrng_mpi_p mpi);

INTERNAL void otrng_mpi_destroy(otrng_mpi_p mpi);

INTERNAL void otrng_mpi_set(otrng_mpi_p mpi, const uint8_t *src, size_t len);

INTERNAL void otrng_mpi_copy(otrng_mpi_p dst, const otrng_mpi_p src);

INTERNAL otrng_err otrng_mpi_deserialize(otrng_mpi_p dst, const uint8_t *src,
                                         size_t src_len, size_t *read);

INTERNAL otrng_err otrng_mpi_deserialize_no_copy(otrng_mpi_p dst,
                                                 const uint8_t *src,
                                                 size_t src_len, size_t *read);

INTERNAL size_t otrng_mpi_memcpy(uint8_t *dst, const otrng_mpi_p mpi);

#ifdef OTRNG_MPI_PRIVATE
#endif

#endif
