#include <string.h>

#include "deserialize.h"

bool
deserialize_uint64(uint64_t *n, const uint8_t serialized[8]) {
  *n = ((uint64_t) serialized[7]) |
       ((uint64_t) serialized[6])<<8 |
       ((uint64_t) serialized[5])<<16 |
       ((uint64_t) serialized[4])<<24 |
       ((uint64_t) serialized[3])<<32 | 
       ((uint64_t) serialized[2])<<40 |
       ((uint64_t) serialized[1])<<48 |
       ((uint64_t) serialized[0])<<56;
  return true;
}

bool
deserialize_uint32(uint32_t *n, const uint8_t serialized[4]) {
  *n = serialized[3] | serialized[2]<<8 | serialized[1]<<16 | serialized[0]<<24;
  return true;
}

bool
deserialize_uint16(uint16_t *n, const uint8_t serialized[2]) {
  *n = serialized[1] | serialized[0]<<8;
  return true;
}

bool
deserialize_uint8(uint8_t *n, const uint8_t serialized[1]) {
  *n = serialized[0];
  return true;
}

bool
deserialize_bytes_array(uint8_t *target, const uint8_t data[], size_t len) {
  memcpy(target, data, len);
  return true;
}

bool
deserialize_mpi(uint8_t *target, const uint8_t *data, uint32_t len) {
  uint32_t data_len = 0;
  deserialize_uint32(&data_len, data);

  if (data_len != len) {
    return false;
  }

  return deserialize_bytes_array(target, data, len);
}

bool
deserialize_ec_point(ec_point_t point, const uint8_t *serialized) {
  return ec_point_deserialize(point, serialized);
}

bool
deserialize_cs_public_key(cs_public_key_t *pub, const uint8_t *serialized, size_t ser_len) {
  if (ser_len < (3*DECAF_448_SER_BYTES + sizeof(uint16_t))) {
    return false;
  }

  const uint8_t *cursor = serialized;

  uint16_t pubkey_type = 0;
  deserialize_uint16(&pubkey_type, cursor);
  cursor += 2;
  if (CRAMER_SHOUP_PUBKEY_TYPE != pubkey_type) {
    return false;
  }

  if (!deserialize_ec_point(pub->c, cursor)) {
    return false;
  }

  cursor += DECAF_448_SER_BYTES;
  if (!deserialize_ec_point(pub->d, cursor)) {
    return false;
  }

  cursor += DECAF_448_SER_BYTES; 
  if (!deserialize_ec_point(pub->h, cursor)) {
    return false;
  }

  return true;
}

