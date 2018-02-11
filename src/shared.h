#ifndef OTRV4_SHARED_H
#define OTRV4_SHARED_H

#ifdef OTRV4_TESTS
#define tstatic
#else
#define tstatic static
#endif

// Marker macro for internal functions - expands to nothing
#define INTERNAL

// Marker macro for API functions - expands to nothing - but will be used later to remind ourselves on what to expose, and where to change naming
#define API

#endif
