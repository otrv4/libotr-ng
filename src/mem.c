#include <stdlib.h>
#include <stdio.h>

#include "mem.h"

/*@out@*/ void *
mem_alloc(size_t size) {
  void *p = malloc(size);

  if (p) {
    return p;
  }

  fprintf(stderr, "Failed to allocate memory. Chao!\n");
  exit(EXIT_FAILURE);
}
