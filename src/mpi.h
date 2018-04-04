#ifndef OTRNG_MPI_H
#define OTRNG_MPI_H

#include <stdint.h>
#include <stdlib.h>

#include "error.h"
#include "shared.h"

typedef struct {
  uint32_t len;
  uint8_t *data;
} otrng_mpi_t[1];

INTERNAL void otrng_mpi_init(otrng_mpi_t mpi);

INTERNAL void otrng_mpi_free(otrng_mpi_t mpi);

INTERNAL void otrng_mpi_set(otrng_mpi_t mpi, const uint8_t *src, size_t len);

INTERNAL void otrng_mpi_copy(otrng_mpi_t dst, const otrng_mpi_t src);

INTERNAL otrng_err_t otrng_mpi_deserialize(otrng_mpi_t dst, const uint8_t *src,
                                           size_t src_len, size_t *read);

INTERNAL otrng_err_t otrng_mpi_deserialize_no_copy(otrng_mpi_t dst,
                                                   const uint8_t *src,
                                                   size_t src_len,
                                                   size_t *read);

INTERNAL size_t otrng_mpi_memcpy(uint8_t *dst, const otrng_mpi_t mpi);

#ifdef OTRNG_MPI_PRIVATE
#endif

#endif
