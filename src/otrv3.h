#ifndef OTRV4_OTR3_H
#define OTRV4_OTR3_H

// clang-format off
#include <libotr/proto.h>
#include <libotr/message.h>
// clang-format on

#include "shared.h"
#include "error.h"
#include "str.h"
#include "tlv.h"
#include "client_state.h"

typedef struct {
  otr4_client_state_t *state;
  char *peer;

  void *opdata; // OTRv4 conn for use in callbacks

  OtrlMessageAppOps *ops;
  ConnContext *ctx;
} otr3_conn_t;

INTERNAL otr3_conn_t *otrv4_v3_conn_new(otr4_client_state_t *state, const char *peer);

INTERNAL void otrv4_v3_conn_free(otr3_conn_t *conn);

INTERNAL otrv4_err_t otrv4_v3_send_message(char **newmessage, const char *message,
                               const tlv_t *tlvs, otr3_conn_t *conn);

INTERNAL otrv4_err_t otrv4_v3_receive_message(string_t *to_send, string_t *to_display,
                                  tlv_t **tlvs, const string_t message,
                                  otr3_conn_t *conn);

INTERNAL void otrv4_v3_close(string_t *to_send, otr3_conn_t *conn);

INTERNAL otrv4_err_t otrv4_v3_send_symkey_message(string_t *to_send, otr3_conn_t *conn,
                                      unsigned int use,
                                      const unsigned char *usedata,
                                      size_t usedatalen, unsigned char *symkey);

INTERNAL otrv4_err_t otrv4_v3_smp_start(string_t *to_send, const char *queston,
                            const uint8_t *secret, size_t secretlen,
                            otr3_conn_t *conn);

INTERNAL otrv4_err_t otrv4_v3_smp_continue(string_t *to_send, const uint8_t *secret,
                               const size_t secretlen, otr3_conn_t *conn);

INTERNAL otrv4_err_t otrv4_v3_smp_abort(otr3_conn_t *conn);


#ifdef OTRV4_OTRV3_PRIVATE
#endif

#endif
