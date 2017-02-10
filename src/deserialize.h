#include "cramer_shoup.h"
#include "ed448.h"

bool
deserialize_uint64(uint64_t *n, const uint8_t *buffer, size_t buflen, size_t *nread);

bool
deserialize_uint32(uint32_t *n, const uint8_t *buffer, size_t buflen, size_t *nread);

bool
deserialize_uint16(uint16_t *n, const uint8_t *buffer, size_t buflen, size_t *nread);

bool
deserialize_uint8(uint8_t *n, const uint8_t *buffer, size_t buflen, size_t *nread);

bool
deserialize_data(uint8_t **dst, const uint8_t *buffer, size_t buflen, size_t *read);

bool
deserialize_mpi_data(uint8_t *dst, const uint8_t *buffer, size_t buflen, size_t *read);

bool
deserialize_ec_point(ec_point_t point, const uint8_t *serialized);

bool
deserialize_cs_public_key(cs_public_key_t *pub, const uint8_t *serialized, size_t ser_len);
