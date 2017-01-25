#include <string.h>

#include "deserialize.h"

bool
deserialize_uint64(uint64_t *n, const uint8_t *buffer, size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint64_t)) { return false; }

  *n = ((uint64_t) buffer[7]) |
       ((uint64_t) buffer[6])<<8 |
       ((uint64_t) buffer[5])<<16 |
       ((uint64_t) buffer[4])<<24 |
       ((uint64_t) buffer[3])<<32 | 
       ((uint64_t) buffer[2])<<40 |
       ((uint64_t) buffer[1])<<48 |
       ((uint64_t) buffer[0])<<56;

  if (nread != NULL) { *nread = sizeof(uint64_t); }
  return true;
}

bool
deserialize_uint32(uint32_t *n, const uint8_t *buffer, size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint32_t)) { return false; }

  *n = buffer[3] | buffer[2]<<8 | buffer[1]<<16 | buffer[0]<<24;

  if (nread != NULL) { *nread = sizeof(uint32_t); }
  return true;
}

bool
deserialize_uint16(uint16_t *n, const uint8_t *buffer, size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint16_t)) { return false; }

  *n = buffer[1] | buffer[0]<<8;

  if (nread != NULL) { *nread = sizeof(uint16_t); }
  return true;
}

bool
deserialize_uint8(uint8_t *n, const uint8_t *buffer, size_t buflen, size_t *nread) {
  if (buflen < sizeof(uint8_t)) { return false; }

  *n = buffer[0];

  if (nread != NULL) { *nread = sizeof(uint8_t); }
  return true;
}

bool
deserialize_bytes_array(uint8_t *target, const uint8_t data[], size_t len) {
  memcpy(target, data, len);
  return true;
}

bool
deserialize_mpi(uint8_t *target, const uint8_t *data, uint32_t len) {
  size_t read = 0;
  uint32_t data_len = 0;
  
  if(!deserialize_uint32(&data_len, data, len, &read)) {
    return false;
  }

  if (data_len != len) {
    return false;
  }

  return deserialize_bytes_array(target+read, data, len);
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
  size_t read = 0;

  uint16_t pubkey_type = 0;
  deserialize_uint16(&pubkey_type, cursor, ser_len, &read);
  cursor += read;
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

