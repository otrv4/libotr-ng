#include "cramer_shoup.h"
#include "ed448.h"

int
deserialize_uint64(uint64_t *n, const uint8_t serialized[8]);

int
deserialize_uint16(uint16_t *n, const uint8_t serialized[2]);

int
deserialize_uint8(uint8_t *n, const uint8_t serialized[1]);

int
deserialize_bytes_array(uint8_t *target, const uint8_t data[], int len);

int
deserialize_mpi(uint8_t *target, const uint8_t *data, uint32_t len);

int
deserialize_ec_point(ec_point_t point, const uint8_t *serialized);

int
deserialize_cs_public_key(cs_public_key_t *pub, const uint8_t *serialized, size_t ser_len);
