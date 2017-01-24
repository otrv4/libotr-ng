#include <string.h>

#include "deserialize.h"

static int
deserialize_int(uint64_t *n, const uint8_t *data, size_t offset) {
  int i;
  int shift = offset;

  for (i=0; i < offset; i++) {
    shift--;
    uint64_t p = data[i];
    *n = *n | (p << shift*8);
  }

  return 0;
}

int
deserialize_uint64(uint64_t *n, const uint8_t serialized[8]) {
  return deserialize_int(n, serialized, sizeof(uint64_t));
}

int
deserialize_uint32(uint32_t *n, const uint8_t serialized[4]) {
  return deserialize_int(n, serialized, sizeof(uint32_t));
}

int
deserialize_uint16(uint16_t *n, const uint8_t serialized[2]) {
  return deserialize_int(n, serialized, sizeof(uint16_t));
}

int
deserialize_uint8(uint8_t *n, const uint8_t serialized[1]) {
  return deserialize_int(n, serialized, sizeof(uint8_t));
}

int
deserialize_bytes_array(uint8_t *target, const uint8_t data[], int len) {
  memcpy(target, data, len);
  return 0;
}

int
deserialize_mpi(uint8_t *target, const uint8_t *data, uint32_t len) {
  int data_len = 0;
  deserialize_uint32(&data_len, data);

  if (data_len != len) {
    return 1;
  }

  return deserialize_bytes_array(target, data, len);
}

int
deserialize_ec_point(ec_point_t point, const uint8_t *serialized) {
  return ec_point_deserialize(point, serialized);
}

int
deserialize_cs_public_key(cs_public_key_t *pub, const uint8_t *serialized, size_t ser_len) {
  if (ser_len < (3*DECAF_448_SER_BYTES + sizeof(uint16_t))) {
    return 1;
  }

  const uint8_t *cursor = serialized;

  uint16_t pubkey_type = 0;
  deserialize_uint16(&pubkey_type, cursor);
  if (CRAMER_SHOUP_PUBKEY_TYPE != pubkey_type) {
    return 1;
  }

  cursor += 2;
  if (!deserialize_ec_point(pub->c, cursor)) {
    return 1;
  }

  cursor += DECAF_448_SER_BYTES;
  if (!deserialize_ec_point(pub->d, cursor)) {
    return 1;
  }

  cursor += DECAF_448_SER_BYTES; 
  if (!deserialize_ec_point(pub->h, cursor)) {
    return 1;
  }

  return 0;
}
