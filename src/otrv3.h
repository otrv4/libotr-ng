#ifndef _OTR3_H_
#define _OTR3_H_

#include <stdbool.h>
#include <libotr/proto.h>
#include <libotr/message.h>

#include "str.h"
#include "tlv.h"

typedef struct {
        char *protocol;
        char *account;
        char *peer;

        void *opdata; //OTRv4 conn for use in callbacks

        OtrlUserState userstate;
        OtrlMessageAppOps *ops;
        ConnContext *ctx;
} otr3_conn_t;

otr3_conn_t* otr3_conn_new(const char *protocol, const char *account, const char *peer);

void otr3_conn_free(otr3_conn_t* conn);

bool send_otrv3_message(char **newmessage, const char *message,
		 tlv_t * tlvs, otr3_conn_t * conn);

bool otrv3_receive_message(string_t *to_send, string_t *to_display, tlv_t **tlvs, const string_t message, otr3_conn_t *conn);

#endif
