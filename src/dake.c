#include <stdlib.h>
#include <stdio.h>

#include "dake.h"

dake_pre_key_t *
dake_compute_pre_key() {
  dake_pre_key_t *pre_key = malloc(sizeof(dake_pre_key_t));
  if (pre_key == NULL) {
    fprintf(stderr, "Failed to allocate memory. Chao!\n");
    exit(EXIT_FAILURE);
  }

  return pre_key;
}
