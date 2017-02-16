#include <stdlib.h>
#include <string.h>

#include "str.h"

/*@null@*/ char *
otrv4_strndup(const char *s, size_t s_len) {
  if (s == NULL)
    return NULL;

  void *new = malloc (s_len + 1);

  if (new == NULL)
    return NULL;

  return (char *) memcpy (new, s, s_len + 1);
}
