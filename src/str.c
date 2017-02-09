#include <stdlib.h>
#include <string.h>

#include "str.h"

/*@null@*/ char *
otrv4_strdup(const char *s) {
  if (s == NULL)
    return NULL;

  size_t len = strlen (s) + 1;
  void *new = malloc (len);

  if (new == NULL)
    return NULL;

  return (char *) memcpy (new, s, len);
}
