#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "data_types.h"

ed448_point_t *
ed448_point_new() {
  ed448_point_t *p = malloc(sizeof(ed448_point_t));
  if (p == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  memset(p->data, 0, 56);

  return p;
}

void
ed448_point_free(ed448_point_t *point) {
  free(point);
}
