/**
 * TODO: This is where we are going to delegate execution of
 * OTR v3 messages. Fot this to work we (think) need to:
 * 1. include libotr's libraries. See usage here
 * https://bugs.otr.im/lib/libotr/blob/master/README
 * 2. (maybe) rename the otr_t structure to otrv4_t to avoid name conflicts
 * with the libotr library.
 * 3. Include libotr in the Makefile as a dependency
 */
#include <stdio.h>

#include "otrv3.h"

void
otrv3_receive_message(const char *message) {
  return; // TODO
}
