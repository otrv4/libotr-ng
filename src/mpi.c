#include "mpi.h"
#include "serialize.h"
#include "deserialize.h"

void
otr_mpi_init(otr_mpi_t mpi) {
  mpi->len = 0;
  mpi->data = NULL;
}

void
otr_mpi_free(otr_mpi_t mpi) {
  free(mpi->data);
  mpi->data = NULL;
}

void
otr_mpi_set(otr_mpi_t dst, const uint8_t *src, size_t len) {
  if (src == NULL || len == 0) {
    dst->len = 0;
    dst->data = NULL;
    return;
  }

  dst->len = len;
  dst->data = malloc(dst->len);
  if (dst->data == NULL) {
    return; // should it be an error?
  }

  memcpy(dst->data, src, dst->len);
}

void
otr_mpi_copy(otr_mpi_t dst, const otr_mpi_t src) {
  otr_mpi_free(dst);
  otr_mpi_set(dst, src->data, src->len);
}

int
otr_mpi_serialize(uint8_t *dst, size_t len, const otr_mpi_t src) {
  uint8_t *cursor = dst;

  if (src->data == NULL) {
    len = 0;
  }

  cursor += serialize_uint32(cursor, len);
  cursor += serialize_bytes_array(cursor, src->data, len);

  return cursor - dst;
}

bool
otr_mpi_deserialize(otr_mpi_t dst, const uint8_t *src, size_t src_len, size_t *read) {
  size_t r = 0;
  if (!deserialize_uint32(&dst->len, src, src_len, &r)) {
    return false;
  }

  if (read != NULL) { *read = r; }

  if (dst->len == 0) {
    dst->data = NULL;
    return true;
  }

  if (dst->len > src_len - r) {
    return false;
  }

  dst->data = malloc(dst->len);
  if (dst->data == NULL) {
    return false;
  }

  memcpy(dst->data, src+r, dst->len);

  if (read != NULL) { *read += dst->len; }
  return true;
}

