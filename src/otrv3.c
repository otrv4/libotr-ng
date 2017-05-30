#include "otrv3.h"

static OtrlPolicy op_policy(void *opdata, ConnContext *context)
{
    return OTRL_POLICY_ALLOW_V3 | OTRL_POLICY_WHITESPACE_START_AKE;
    //return OTRL_POLICY_DEFAULT;
} 

static char *injected_to_send = NULL;

static void op_inject(void *opdata, const char *accountname,
        const char *protocol, const char *recipient, const char *message)
{
    if (injected_to_send) {
        printf("To send was not consumed\n");
        free(injected_to_send);
        injected_to_send = NULL;
    }

    if (message)
        injected_to_send = otrv4_strdup(message);
}

static OtrlMessageAppOps null_ops = {
    op_policy,
    NULL,
    NULL,
    op_inject,
    NULL, //op_notify,
    NULL, //op_display_otr_message,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL, //op_gone_secure,
    NULL, //op_gone_insecure,
    NULL, //op_still_secure,
    NULL
};

otr3_conn_t* otr3_conn_new(const char *protocol, const char *account, const char *peer)
{
    otr3_conn_t *ret = malloc(sizeof(otr3_conn_t));
    if (!ret)
        return NULL;

    ret->userstate = NULL;
    ret->ops = &null_ops; // This cant be null
    ret->ctx = NULL;

    ret->protocol = otrv4_strdup(protocol);
    ret->account = otrv4_strdup(account);
    ret->peer = otrv4_strdup(peer);

    return ret;
}

void otr3_conn_free(otr3_conn_t* conn)
{
    if (!conn)
        return;

    conn->ctx = NULL;
    conn->ops = NULL;
    conn->userstate = NULL;

    free(conn->protocol);
    conn->protocol = NULL;

    free(conn->account);
    conn->account = NULL;

    free(conn->peer);
    conn->peer = NULL;

    free(conn);
}

bool send_otrv3_message(char **newmessage, const char *message,
		 tlv_t * tlvs, otr3_conn_t * conn)
{
    //TODO: convert TLVs
    OtrlTLV *tlvsv3 = NULL;

    if (!conn)
        return false;

    int err = otrl_message_sending(conn->userstate,
        conn->ops, NULL /* opdata */,
        conn->account, conn->protocol, conn->peer,
        OTRL_INSTAG_BEST, message, tlvsv3,
        newmessage, OTRL_FRAGMENT_SEND_SKIP,
        &conn->ctx, NULL, NULL);

    return !err;
}

bool otrv3_receive_message(string_t *to_send, string_t *to_display, tlv_t **tlvs, const string_t message, otr3_conn_t *conn)
{
    int ignore_message;
    OtrlTLV *tlvsv3 = NULL; //TODO: convert to v4 tlvs

    if (!conn)
        return false;

    char *newmessage = NULL;
    ignore_message = otrl_message_receiving(conn->userstate,
        conn->ops, NULL,
        conn->account, conn->protocol, conn->peer,
        message, &newmessage,
        &tlvsv3, &conn->ctx, NULL, NULL);

    (void) ignore_message;

    if (to_send && injected_to_send) {
        *to_send = otrv4_strdup(injected_to_send);
        free(injected_to_send);
        injected_to_send = NULL;
    }

    if (to_display && newmessage)
        *to_display = otrv4_strdup(newmessage);

    otrl_tlv_free(tlvsv3);
    otrl_message_free(newmessage);

    //TODO: Here we can use contextp to get information we might need about the
    //state, for example (context->msgstate)

    return true;
}
