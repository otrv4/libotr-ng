#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef MPI_H
#define MPI_H

typedef struct {
	uint32_t len;
	uint8_t *data;
} otr_mpi_t[1];

void otr_mpi_init(otr_mpi_t mpi);

void otr_mpi_free(otr_mpi_t mpi);

void otr_mpi_set(otr_mpi_t mpi, const uint8_t * src, size_t len);

void otr_mpi_copy(otr_mpi_t dst, const otr_mpi_t src);

bool
otr_mpi_deserialize(otr_mpi_t dst, const uint8_t * src, size_t src_len,
		    size_t * read);

bool
otr_mpi_deserialize_no_copy(otr_mpi_t dst, const uint8_t * src,
			    size_t src_len, size_t * read);

size_t otr_mpi_memcpy(uint8_t * dst, const otr_mpi_t mpi);

#endif
