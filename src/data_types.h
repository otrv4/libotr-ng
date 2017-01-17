#include <stdint.h>

#ifndef __DATA_TYPES__
#define __DATA_TYPES__

typedef struct {
  uint8_t data[56];
} ed448_point_t;

ed448_point_t *
ed448_point_new();

void
ed448_point_free(ed448_point_t *point);

#endif
