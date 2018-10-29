/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "smp.h"
#include "messaging.h"

tstatic void handle_smp_event_cb_v4(const otrng_smp_event event,
                                    const uint8_t progress_percent,
                                    const uint8_t *question, const size_t q_len,
                                    const otrng_s *conv) {
  if (!conv->client->global_state->callbacks->smp_ask_for_secret) {
    return;
  }

  if (!conv->client->global_state->callbacks->smp_ask_for_answer) {
    return;
  }

  if (!conv->client->global_state->callbacks->smp_update) {
    return;
  }

  switch (event) {
  case OTRNG_SMP_EVENT_ASK_FOR_SECRET:
    conv->client->global_state->callbacks->smp_ask_for_secret(conv);
    break;
  case OTRNG_SMP_EVENT_ASK_FOR_ANSWER:
    conv->client->global_state->callbacks->smp_ask_for_answer(question, q_len,
                                                              conv);
    break;
  case OTRNG_SMP_EVENT_CHEATED:
  case OTRNG_SMP_EVENT_IN_PROGRESS:
  case OTRNG_SMP_EVENT_SUCCESS:
  case OTRNG_SMP_EVENT_FAILURE:
  case OTRNG_SMP_EVENT_ABORT:
  case OTRNG_SMP_EVENT_ERROR:
    conv->client->global_state->callbacks->smp_update(event, progress_percent,
                                                      conv);
    break;
  default:
    /* OTRNG_SMP_EVENT_NONE. Should not be used. */
    break;
  }
}

tstatic tlv_s *otrng_process_smp(otrng_smp_event *ret, smp_protocol_s *smp,
                                 const tlv_s *tlv) {
  otrng_smp_event event = *ret;
  tlv_s *to_send = NULL;

  switch (tlv->type) {
  case OTRNG_TLV_SMP_MSG_1:
    event = otrng_process_smp_message1(tlv, smp);
    if (event == OTRNG_SMP_EVENT_ABORT) {
      smp->state_expect = SMP_STATE_EXPECT_1;
    } else if (event == OTRNG_SMP_EVENT_ERROR ||
               event == OTRNG_SMP_EVENT_FAILURE) {
      smp->state_expect = SMP_STATE_EXPECT_1;
    }
    break;

  case OTRNG_TLV_SMP_MSG_2:
    event = otrng_process_smp_message2(&to_send, tlv, smp);
    if (event == OTRNG_SMP_EVENT_ABORT) {
      smp->state_expect = SMP_STATE_EXPECT_1;
      smp->progress = SMP_ZERO_PROGRESS;
      to_send = otrng_tlv_new(OTRNG_TLV_SMP_ABORT, 0, NULL);
      if (!to_send) {
        return NULL;
      }
    } else if (event == OTRNG_SMP_EVENT_ERROR ||
               event == OTRNG_SMP_EVENT_FAILURE) {
      smp->state_expect = SMP_STATE_EXPECT_1;
    }
    break;

  case OTRNG_TLV_SMP_MSG_3:
    event = otrng_process_smp_message3(&to_send, tlv, smp);
    if (event == OTRNG_SMP_EVENT_ABORT) {
      smp->state_expect = SMP_STATE_EXPECT_1;
      to_send = otrng_tlv_new(OTRNG_TLV_SMP_ABORT, 0, NULL);
      if (!to_send) {
        return NULL;
      }
    } else if (event == OTRNG_SMP_EVENT_ERROR ||
               event == OTRNG_SMP_EVENT_FAILURE) {
      smp->state_expect = SMP_STATE_EXPECT_1;
    }
    break;

  case OTRNG_TLV_SMP_MSG_4:
    event = otrng_process_smp_message4(tlv, smp);
    if (event == OTRNG_SMP_EVENT_ABORT) {
      smp->state_expect = SMP_STATE_EXPECT_1;
      to_send = otrng_tlv_new(OTRNG_TLV_SMP_ABORT, 0, NULL);
      if (!to_send) {
        return NULL;
      }
    } else if (event == OTRNG_SMP_EVENT_ERROR ||
               event == OTRNG_SMP_EVENT_FAILURE) {
      smp->state_expect = SMP_STATE_EXPECT_1;
    }
    break;

  case OTRNG_TLV_SMP_ABORT:
    smp->state_expect = SMP_STATE_EXPECT_1;
    smp->progress = SMP_ZERO_PROGRESS;
    event = OTRNG_SMP_EVENT_ABORT;
    break;
  case OTRNG_TLV_NONE:
  case OTRNG_TLV_PADDING:
  case OTRNG_TLV_DISCONNECTED:
  case OTRNG_TLV_SYM_KEY:
    /* Ignore. They should not be passed to this function. */
    break;
  }

  if (!event) {
    event = OTRNG_SMP_EVENT_IN_PROGRESS;
  }

  *ret = event;
  return to_send;
}

INTERNAL tlv_s *otrng_process_smp_tlv(const tlv_s *tlv, otrng_s *otr) {
  // TODO: @smp: what happens with the error and failure?
  otrng_smp_event event = OTRNG_SMP_EVENT_NONE;
  tlv_s *out = otrng_process_smp(&event, otr->smp, tlv);
  handle_smp_event_cb_v4(
      event, otr->smp->progress,
      otr->smp->message1 ? otr->smp->message1->question : NULL,
      otr->smp->message1 ? otr->smp->message1->q_len : 0, otr);

  return out;
}

tstatic tlv_s *
otrng_smp_initiate(const otrng_client_profile_s *initiator_profile,
                   const otrng_client_profile_s *responder_profile,
                   const uint8_t *question, const size_t q_len,
                   const uint8_t *answer, const size_t answer_len,
                   uint8_t *ssid, smp_protocol_s *smp, otrng_s *conversation) {

  smp_message_1_s msg;
  uint8_t *to_send = NULL;
  size_t len = 0;
  tlv_s *tlv;
  otrng_fingerprint our_fp, their_fp;

  if (smp->state_expect != SMP_STATE_EXPECT_1) {
    tlv = otrng_tlv_new(OTRNG_TLV_SMP_ABORT, 0, NULL);
    return tlv;
  }

  if (!otrng_serialize_fingerprint(our_fp,
                                   initiator_profile->long_term_pub_key)) {
    return NULL;
  }

  if (!otrng_serialize_fingerprint(their_fp,
                                   responder_profile->long_term_pub_key)) {
    return NULL;
  }

  if (!otrng_generate_smp_secret(&smp->secret, our_fp, their_fp, ssid, answer,
                                 answer_len)) {
    return NULL;
  }

  do {
    if (!otrng_generate_smp_message_1(&msg, smp)) {
      continue;
    }

    msg.q_len = q_len;
    msg.question = otrng_xmemdup(question, q_len);

    if (!otrng_smp_message_1_serialize(&to_send, &len, &msg)) {
      continue;
    }

    smp->state_expect = SMP_STATE_EXPECT_2;
    smp->progress = 25;
    handle_smp_event_cb_v4(OTRNG_SMP_EVENT_IN_PROGRESS, smp->progress, question,
                           q_len, conversation);

    tlv = otrng_tlv_new(OTRNG_TLV_SMP_MSG_1, len, to_send);
    otrng_smp_message_1_destroy(&msg);
    free(to_send);
    return tlv;
  } while (0);

  otrng_smp_message_1_destroy(&msg);
  handle_smp_event_cb_v4(OTRNG_SMP_EVENT_ERROR, smp->progress,
                         smp->message1->question, smp->message1->q_len,
                         conversation);

  return NULL;
}

INTERNAL otrng_result otrng_smp_start(string_p *to_send,
                                      const uint8_t *question,
                                      const size_t q_len, const uint8_t *answer,
                                      const size_t answer_len, otrng_s *otr) {
  tlv_s *smp_start_tlv;
  tlv_list_s *tlvs;
  otrng_warning warn;
  otrng_result ret;

  if (!otr) {
    return OTRNG_ERROR;
  }

  switch (otr->running_version) {
  case 3:
    // FIXME: missing fragmentation
    return otrng_v3_smp_start(to_send, question, q_len, answer, answer_len,
                              otr->v3_conn);
  case 4:
    if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
      return OTRNG_ERROR;
    }

    smp_start_tlv = otrng_smp_initiate(
        get_my_client_profile(otr), otr->their_client_profile, question, q_len,
        answer, answer_len, otr->keys->ssid, otr->smp, otr);

    if (!smp_start_tlv) {
      return OTRNG_ERROR;
    }

    tlvs = otrng_tlv_list_one(smp_start_tlv);
    if (!tlvs) {
      return OTRNG_ERROR;
    }

    warn = OTRNG_WARN_NONE;
    // TODO: do something about warn
    ret = otrng_prepare_to_send_data_message(to_send, &warn, "", tlvs, otr,
                                             MSG_FLAGS_IGNORE_UNREADABLE);
    otrng_tlv_list_free(tlvs);
    return ret;
  case 0:
    return OTRNG_ERROR;
  }

  return OTRNG_ERROR;
}

tstatic tlv_s *
otrng_smp_provide_secret(otrng_smp_event *event, smp_protocol_s *smp,
                         const otrng_client_profile_s *our_profile,
                         const otrng_client_profile_s *their_client_profile,
                         uint8_t *ssid, const uint8_t *secret,
                         const size_t secret_len) {
  // TODO: @smp If state is not CONTINUE_SMP then error.
  tlv_s *smp_reply = NULL;

  otrng_fingerprint our_fp, their_fp;
  if (!otrng_serialize_fingerprint(our_fp, our_profile->long_term_pub_key)) {
    return NULL;
  }

  if (!otrng_serialize_fingerprint(their_fp,
                                   their_client_profile->long_term_pub_key)) {
    return NULL;
  }

  if (!otrng_generate_smp_secret(&smp->secret, their_fp, our_fp, ssid, secret,
                                 secret_len)) {
    return NULL;
  }

  *event = otrng_reply_with_smp_message_2(&smp_reply, smp);

  return smp_reply;
}

tstatic otrng_result smp_continue_v4(string_p *to_send, const uint8_t *secret,
                                     const size_t secret_len, otrng_s *otr) {
  otrng_smp_event event;
  tlv_list_s *tlvs;
  otrng_warning warn;
  otrng_result ret;

  if (!otr) {
    return OTRNG_ERROR;
  }

  event = OTRNG_SMP_EVENT_NONE;
  tlvs = otrng_tlv_list_one(otrng_smp_provide_secret(
      &event, otr->smp, get_my_client_profile(otr), otr->their_client_profile,
      otr->keys->ssid, secret, secret_len));

  if (!tlvs) {
    return OTRNG_ERROR;
  }

  if (!event) {
    event = OTRNG_SMP_EVENT_IN_PROGRESS;
  }

  handle_smp_event_cb_v4(event, otr->smp->progress,
                         otr->smp->message1->question,
                         otr->smp->message1->q_len, otr);

  warn = OTRNG_WARN_NONE;
  // TODO: warn
  ret = otrng_prepare_to_send_data_message(to_send, &warn, "", tlvs, otr,
                                           MSG_FLAGS_IGNORE_UNREADABLE);
  otrng_tlv_list_free(tlvs);

  return ret;
}

INTERNAL otrng_result otrng_smp_continue(string_p *to_send,
                                         const uint8_t *secret,
                                         const size_t secret_len,
                                         otrng_s *otr) {
  switch (otr->running_version) {
  case 3:
    // FIXME: @smp missing fragmentation
    return otrng_v3_smp_continue(to_send, secret, secret_len, otr->v3_conn);
  case 4:
    return smp_continue_v4(to_send, secret, secret_len, otr);
  case 0:
    return OTRNG_ERROR;
  }

  return OTRNG_ERROR; // TODO: @smp IMPLEMENT
}

tstatic otrng_result otrng_smp_abort_v4(string_p *to_send, otrng_s *otr) {
  tlv_list_s *tlvs =
      otrng_tlv_list_one(otrng_tlv_new(OTRL_TLV_SMP_ABORT, 0, NULL));
  otrng_warning warn;
  otrng_result ret;

  if (!tlvs) {
    return OTRNG_ERROR;
  }

  otr->smp->state_expect = SMP_STATE_EXPECT_1;
  warn = OTRNG_WARN_NONE;
  // TODO: warn
  ret = otrng_prepare_to_send_data_message(to_send, &warn, "", tlvs, otr,
                                           MSG_FLAGS_IGNORE_UNREADABLE);
  otrng_tlv_list_free(tlvs);
  return ret;
}

API otrng_result otrng_smp_abort(string_p *to_send, otrng_s *otr) {
  switch (otr->running_version) {
  case 3:
    return otrng_v3_smp_abort(otr->v3_conn);
  case 4:
    return otrng_smp_abort_v4(to_send, otr);
  case 0:
    return OTRNG_ERROR;
  }
  return OTRNG_ERROR;
}
