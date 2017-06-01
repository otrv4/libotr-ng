#ifndef ERROR_H
#define ERROR_H

typedef enum {
  OTR4_SUCCESS = 0,
  OTR4_ERROR = 1,
  OTR4_STATE_NOT_ENCRYPTED = 0x1001,
} otr4_err_t;

#endif
