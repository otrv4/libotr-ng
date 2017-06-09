#include "client_callbacks.h"

void otrv4_client_callbacks_create_privkey(const otrv4_client_callbacks_t *cb,
                                           void *client_opdata) {
  if (!cb)
    return;
}

void otrv4_client_callbacks_gone_secure(
    const otrv4_client_callbacks_t *cb,
    const otr4_client_conversation_t *conv) {
  if (!cb || !cb->gone_secure)
    return;

  cb->gone_secure(conv);
}

void otrv4_client_callbacks_gone_insecure(
    const otrv4_client_callbacks_t *cb,
    const otr4_client_conversation_t *conv) {
  if (!cb || !cb->gone_insecure)
    return;

  cb->gone_insecure(conv);
}

void otrv4_client_callbacks_fingerprint_seen(
    const otrv4_client_callbacks_t *cb, const otrv4_fingerprint_t fp,
    const otr4_client_conversation_t *conv) {
  if (!cb)
    return;
}

void otrv4_client_callbacks_fingerprint_seen_otr3(
    const otrv4_client_callbacks_t *cb, const otrv3_fingerprint_t fp,
    const otr4_client_conversation_t *conv) {
  if (!cb)
    return;
}

void otrv4_client_callbacks_smp_ask_for_secret(
    const otrv4_client_callbacks_t *cb,
    const otr4_client_conversation_t *conv) {
  if (!cb)
    return;
}

void otrv4_client_callbacks_smp_ask_for_answer(
    const otrv4_client_callbacks_t *cb, const char *question,
    const otr4_client_conversation_t *conv) {
  if (!cb)
    return;
}

void otrv4_client_callbacks_smp_update(const otrv4_client_callbacks_t *cb,
                                       const otr4_smp_event_t event,
                                       const uint8_t progress_percent,
                                       const otr4_client_conversation_t *conv) {
  if (!cb)
    return;
}
