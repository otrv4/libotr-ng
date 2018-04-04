#ifndef OTRNG_STR_H
#define OTRNG_STR_H

#include <stddef.h>

#include "shared.h"

#define string_t char *

INTERNAL /*@null@*/ char *otrng_strndup(const char *s, size_t s_len);

INTERNAL char *otrng_strdup(const char *s);

#ifdef OTRNG_STR_PRIVATE
#endif

#endif
