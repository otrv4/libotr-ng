#include "mem.h"
#include "dake.h"

dake_pre_key_t *
dake_compute_pre_key() {
  dake_pre_key_t *pre_key = mem_alloc(sizeof(dake_pre_key_t));
  return pre_key;
}
