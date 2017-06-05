#ifndef _OTR3_H_
#define _OTR3_H_

// clang-format off
#include <libotr/proto.h>
#include <libotr/message.h>
// clang-format on
#include <stdbool.h>

#include "error.h"
#include "str.h"
#include "tlv.h"

typedef struct {
  char *protocol;
  char *account;
  char *peer;

  void *opdata; // OTRv4 conn for use in callbacks

  OtrlUserState userstate;
  OtrlMessageAppOps *ops;
  ConnContext *ctx;
} otr3_conn_t;

otr3_conn_t *otr3_conn_new(const char *protocol, const char *account,
                           const char *peer);

void otr3_conn_free(otr3_conn_t *conn);

otr4_err_t otrv3_send_message(char **newmessage, const char *message,
                              tlv_t *tlvs, otr3_conn_t *conn);
otr4_err_t otrv3_receive_message(string_t *to_send, string_t *to_display,
                                 tlv_t **tlvs, const string_t message,
                                 otr3_conn_t *conn);

void otrv3_close(string_t *to_send, otr3_conn_t *conn);

otr4_err_t otrv3_smp_start(string_t *to_send, const char *queston,
                           const uint8_t *secret, size_t secretlen,
                           otr3_conn_t *conn);

otr4_err_t otrv3_smp_continue(string_t *to_send, const uint8_t *secret,
                              const size_t secretlen, otr3_conn_t *conn);

#endif
