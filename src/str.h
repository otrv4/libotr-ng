#ifndef STR_H
#define STR_H

#include <stddef.h>

#define string_t char*

/*@null@*/ char *
 otrv4_strndup(const char *s, size_t s_len);

char *otrv4_string_duplicate(const char *s);

#endif
