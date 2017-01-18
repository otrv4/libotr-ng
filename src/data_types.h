#include <stdint.h>

#ifndef DATA_TYPES_H
#define DATA_TYPES_H

typedef struct {
  uint8_t data[56];
} ed448_point_t;

ed448_point_t *
ed448_point_new();

void
ed448_point_free(ed448_point_t *point);

#endif
