#include "otrv3.h"

void
otrv3_receive_message(char **response, const char *message) {
  *response = strdup(message);
}
