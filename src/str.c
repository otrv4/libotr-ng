#include <stdlib.h>
#include <string.h>

#define OTRNG_STR_PRIVATE

#include "str.h"

INTERNAL /*@null@*/ char *otrng_strndup(const char *s, size_t s_len) {
  if (s == NULL)
    return NULL;

  if (strlen(s) < s_len)
    s_len = strlen(s);

  void *new = malloc(s_len + 1);
  if (new == NULL)
    return NULL;

  char *ret = memcpy(new, s, s_len + 1);
  ret[s_len] = 0;

  return ret;
}

INTERNAL /*@null@*/ char *otrng_strdup(const char *s) {
  if (!s)
    return NULL;

  return otrng_strndup(s, strlen(s));
}
