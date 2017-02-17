#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "otrv4.h"
#include "dh.h"

#define OTR4_INIT do { \
  dh_init(); \
} while (0);

#define OTR4_FREE do { \
  dh_free(); \
} while (0);


#endif
