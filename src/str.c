#include <stdlib.h>
#include <string.h>

#include "str.h"

/*@null@*/ char *
otrv4_strndup(const char *s, size_t s_len)
{
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

/*@null@*/ char *
otrv4_string_duplicate(const char *s)
{
	return otrv4_strndup(s, strlen(s));
}
