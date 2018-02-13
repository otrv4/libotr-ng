#ifndef OTRV4_MPI_H
#define OTRV4_MPI_H

#include <stdint.h>
#include <stdlib.h>

#include "error.h"
#include "shared.h"

typedef struct {
  uint32_t len;
  uint8_t *data;
} otrv4_mpi_t[1];

INTERNAL void otrv4_mpi_init(otrv4_mpi_t mpi);

INTERNAL void otrv4_mpi_free(otrv4_mpi_t mpi);

INTERNAL void otrv4_mpi_set(otrv4_mpi_t mpi, const uint8_t *src, size_t len);

INTERNAL void otrv4_mpi_copy(otrv4_mpi_t dst, const otrv4_mpi_t src);

INTERNAL otrv4_err_t otrv4_mpi_deserialize(otrv4_mpi_t dst, const uint8_t *src,
                                           size_t src_len, size_t *read);

INTERNAL otrv4_err_t otrv4_mpi_deserialize_no_copy(otrv4_mpi_t dst,
                                                   const uint8_t *src,
                                                   size_t src_len,
                                                   size_t *read);

INTERNAL size_t otrv4_mpi_memcpy(uint8_t *dst, const otrv4_mpi_t mpi);

#ifdef OTRV4_MPI_PRIVATE
#endif

#endif
