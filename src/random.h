#include <sodium.h>

#ifndef RANDOM_H
#define RANDOM_H

//TODO this could be from gcrypt since we already use it for the DH
static void inline
random_bytes(void * const buf, const size_t size) {
  randombytes_buf(buf, size);
}

#endif
