#define OTRNG_CLIENT_CALLBACKS_PRIVATE
#include "client_callbacks.h"

INTERNAL void
otrng_client_callbacks_create_privkey(const otrng_client_callbacks_t *cb,
                                      void *client_opdata) {
  if (!cb)
    return;
}

INTERNAL void
otrng_client_callbacks_gone_secure(const otrng_client_callbacks_t *cb,
                                   const otrng_client_conversation_t *conv) {
  if (!cb || !cb->gone_secure)
    return;

  cb->gone_secure(conv);
}

INTERNAL void
otrng_client_callbacks_gone_insecure(const otrng_client_callbacks_t *cb,
                                     const otrng_client_conversation_t *conv) {
  if (!cb || !cb->gone_insecure)
    return;

  cb->gone_insecure(conv);
}

INTERNAL void otrng_client_callbacks_fingerprint_seen(
    const otrng_client_callbacks_t *cb, const otrng_fingerprint_t fp,
    const otrng_client_conversation_t *conv) {
  if (!cb)
    return;
}

INTERNAL void otrng_client_callbacks_fingerprint_seen_v3(
    const otrng_client_callbacks_t *cb, const v3_fingerprint_t fp,
    const otrng_client_conversation_t *conv) {
  if (!cb)
    return;
}

INTERNAL void otrng_client_callbacks_smp_ask_for_secret(
    const otrng_client_callbacks_t *cb,
    const otrng_client_conversation_t *conv) {
  if (!cb)
    return;
}

INTERNAL void otrng_client_callbacks_smp_ask_for_answer(
    const otrng_client_callbacks_t *cb, const char *question,
    const otrng_client_conversation_t *conv) {
  if (!cb)
    return;
}

INTERNAL void otrng_client_callbacks_smp_update(
    const otrng_client_callbacks_t *cb, const otrng_smp_event_t event,
    const uint8_t progress_percent, const otrng_client_conversation_t *conv) {
  if (!cb)
    return;
}
