#include <stdint.h>

#include "dh.h"
#include "ed448.h"
#include "cramer_shoup.h"
#include "mpi.h"

int
serialize_uint64(uint8_t *dst, const uint64_t data);

int
serialize_uint32(uint8_t *dst, const uint32_t data);


int
serialize_uint16(uint8_t *dst, const uint16_t data);

int
serialize_uint8(uint8_t *dst, const uint8_t data);

int
serialize_bytes_array(uint8_t *target, const uint8_t data[], int len);

int
serialize_data(uint8_t *target, const uint8_t *data, int len);

int
serialize_mpi(uint8_t *dst, const otr_mpi_t mpi);

int
serialize_ec_public_key(uint8_t *dst, const ec_public_key_t pub);

int
serialize_ec_point(uint8_t *dst, const ec_point_t point);

int
serialize_dh_public_key(uint8_t *dst, const dh_public_key_t pub);

int
serialize_cs_public_key(uint8_t *dst, const cs_public_key_t *pub);

