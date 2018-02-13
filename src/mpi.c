#define OTRV4_MPI_PRIVATE

#include "mpi.h"
#include "deserialize.h"
#include "serialize.h" // just for memcpy

INTERNAL void otr_mpi_init(otr_mpi_t mpi) {
  mpi->len = 0;
  mpi->data = NULL;
}

INTERNAL void otr_mpi_free(otr_mpi_t mpi) {
  free(mpi->data);
  mpi->data = NULL;
}

INTERNAL void otr_mpi_set(otr_mpi_t dst, const uint8_t *src, size_t len) {
  if (src == NULL || len == 0) {
    dst->len = 0;
    dst->data = NULL;
    return;
  }

  dst->len = len;
  dst->data = malloc(dst->len);
  if (!dst->data)
    return; // should it be an error?

  memcpy(dst->data, src, dst->len);
}

INTERNAL void otr_mpi_copy(otr_mpi_t dst, const otr_mpi_t src) {
  otr_mpi_set(dst, src->data, src->len);
}

tstatic otrv4_bool_t otr_mpi_read_len(otr_mpi_t dst, const uint8_t *src,
                                     size_t src_len, size_t *read) {
  size_t r = 0;
  if (otrv4_deserialize_uint32(&dst->len, src, src_len, &r))
    return otrv4_false;

  if (read != NULL)
    *read = r;

  if (dst->len > src_len - r)
    return otrv4_false;

  return otrv4_true;
}

INTERNAL otrv4_err_t otr_mpi_deserialize(otr_mpi_t dst, const uint8_t *src,
                                size_t src_len, size_t *read) {
  if (otr_mpi_read_len(dst, src, src_len, read) == otrv4_false)
    return ERROR;

  if (dst->len == 0) {
    dst->data = NULL;
    return SUCCESS;
  }

  dst->data = malloc(dst->len);
  if (dst->data == NULL) {
    return ERROR;
  }

  memcpy(dst->data, src + *read, dst->len);

  if (read != NULL)
    *read += dst->len;

  return SUCCESS;
}

INTERNAL otrv4_err_t otr_mpi_deserialize_no_copy(otr_mpi_t dst, const uint8_t *src,
                                        size_t src_len, size_t *read) {
  if (otr_mpi_read_len(dst, src, src_len, read) == otrv4_false)
    return ERROR;

  if (dst->len == 0) {
    dst->data = NULL;
    return SUCCESS;
  }
  /* points to original buffer without copying */
  dst->data = (uint8_t *)src + *read;
  return SUCCESS;
}

INTERNAL size_t otr_mpi_memcpy(uint8_t *dst, const otr_mpi_t mpi) {
  memcpy(dst, mpi->data, mpi->len);
  return mpi->len;
}
