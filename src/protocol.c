#include <stdlib.h>
#include <stdarg.h>

#include "protocol.h"

otrv4_protocol_t *
protocol_start(int versions, ...) {
  otrv4_protocol_t *protocol = malloc(sizeof(otrv4_protocol_t));
  if(protocol == NULL) {
    return NULL;
  }

  protocol->state = OTRV4_STATE_START;
  
  va_list allowed;
  va_start(allowed, versions);

  protocol->supported_versions = OTRV4_ALLOW_NONE;
  int i = 0;
  for (; i < versions; i++) {
    protocol->supported_versions |= va_arg(allowed, int);
  }

  va_end(allowed);

  return protocol;
}
