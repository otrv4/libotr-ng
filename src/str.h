#ifndef STR_H
#define STR_H

typedef char *string_t;

/*@null@*/ char *
otrv4_strndup(const char *s, size_t s_len);

char*
otrv4_strdup(const char *s);

#endif
