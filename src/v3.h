#ifndef OTRNG_V3_H
#define OTRNG_V3_H

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
  otrng_client_state_t *state;
  char *peer;

  void *opdata; // v4 conn for use in callbacks

  OtrlMessageAppOps *ops;
  ConnContext *ctx;
} otrng_v3_conn_t;

INTERNAL otrng_v3_conn_t *otrng_v3_conn_new(otrng_client_state_t *state,
                                            const char *peer);

INTERNAL void otrng_v3_conn_free(otrng_v3_conn_t *conn);

INTERNAL otrng_err_t otrng_v3_send_message(char **newmessage,
                                           const char *message,
                                           const tlv_t *tlvs,
                                           otrng_v3_conn_t *conn);

INTERNAL otrng_err_t otrng_v3_receive_message(string_t *to_send,
                                              string_t *to_display,
                                              tlv_t **tlvs,
                                              const string_t message,
                                              otrng_v3_conn_t *conn);

INTERNAL void otrng_v3_close(string_t *to_send, otrng_v3_conn_t *conn);

INTERNAL otrng_err_t otrng_v3_send_symkey_message(
    string_t *to_send, otrng_v3_conn_t *conn, unsigned int use,
    const unsigned char *usedata, size_t usedatalen, unsigned char *symkey);

INTERNAL otrng_err_t otrng_v3_smp_start(string_t *to_send, const char *queston,
                                        const uint8_t *secret, size_t secretlen,
                                        otrng_v3_conn_t *conn);

INTERNAL otrng_err_t otrng_v3_smp_continue(string_t *to_send,
                                           const uint8_t *secret,
                                           const size_t secretlen,
                                           otrng_v3_conn_t *conn);

INTERNAL otrng_err_t otrng_v3_smp_abort(otrng_v3_conn_t *conn);

#ifdef OTRNG_V3_PRIVATE
#endif

#endif
