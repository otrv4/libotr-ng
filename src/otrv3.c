#include <string.h>

#include "otrv3.h"
#include "mem.h"

void
otrv3_receive_message(char **response, const char *message) {
  *response = mem_alloc(strlen(message));
  strcpy(*response, message);
}
