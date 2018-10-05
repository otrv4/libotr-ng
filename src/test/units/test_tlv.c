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

#include <glib.h>

#include "test_helpers.h"

#include "tlv.h"

static void assert_tlv_structure(tlv_list_s *tlvs, otrng_tlv_type type,
                                 uint16_t len, uint8_t *data, otrng_bool next) {
  otrng_assert(tlvs);
  otrng_assert(tlvs->data);
  otrng_assert(tlvs->data->type == type);
  otrng_assert(tlvs->data->len == len);
  if (next) {
    otrng_assert(tlvs->next != NULL);
  } else {
    otrng_assert(tlvs->next == NULL);
  }
  if (type != OTRNG_TLV_PADDING) {
    otrng_assert_cmpmem(tlvs->data->data, data, len);
  }
}

static void test_tlv_parse() {
  uint8_t message[22] = {0x00, 0x06, 0x00, 0x03, 0x08, 0x05, 0x09, 0x00,
                         0x02, 0x00, 0x04, 0xac, 0x04, 0x05, 0x06, 0x00,
                         0x05, 0x00, 0x03, 0x08, 0x05, 0x09};

  uint8_t data[3] = {0x08, 0x05, 0x09};
  uint8_t data2[4] = {0xac, 0x04, 0x05, 0x06};

  tlv_list_s *tlvs = otrng_parse_tlvs(message, sizeof(message));
  assert_tlv_structure(tlvs, OTRNG_TLV_SMP_ABORT, sizeof(data), data,
                       otrng_true);
  assert_tlv_structure(tlvs->next, OTRNG_TLV_SMP_MSG_1, sizeof(data2), data2,
                       otrng_true);
  assert_tlv_structure(tlvs->next->next, OTRNG_TLV_SMP_MSG_4, sizeof(data),
                       data, otrng_false);

  otrng_tlv_list_free(tlvs);
}

static void test_otrng_append_tlv() {
  uint8_t smp2_data[2] = {0x03, 0x04};
  uint8_t smp3_data[3] = {0x05, 0x04, 0x03};

  tlv_list_s *tlvs = NULL;
  tlv_s *smp_message2_tlv =
      otrng_tlv_new(OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data);
  tlv_s *smp_message3_tlv =
      otrng_tlv_new(OTRNG_TLV_SMP_MSG_3, sizeof(smp3_data), smp3_data);

  tlvs = otrng_append_tlv(tlvs, smp_message2_tlv);

  assert_tlv_structure(tlvs, OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data,
                       otrng_false);

  tlvs = otrng_append_tlv(tlvs, smp_message3_tlv);

  assert_tlv_structure(tlvs, OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data,
                       otrng_true);
  assert_tlv_structure(tlvs->next, OTRNG_TLV_SMP_MSG_3, sizeof(smp3_data),
                       smp3_data, otrng_false);

  assert_tlv_structure(tlvs, OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data,
                       otrng_true);

  otrng_tlv_list_free(tlvs);
}

// TODO: Add this test to receive message
static void test_otrng_append_padding_tlv() {
  return;
  // uint8_t smp2_data[2] = {0x03, 0x04};

  // tlv_list_s *tlvs = otrng_tlv_list_one(
  //    otrng_tlv_new(OTRNG_TLV_SMP_MESSAGE_2, sizeof(smp2_data), smp2_data));
  // tlvs = otrng_append_padding_tlv(tlvs, 6);
  // otrng_assert(tlvs);
  // assert_tlv_structure(tlvs->next, OTRNG_TLV_PADDING, 245, smp2_data, false);
  // otrng_tlv_list_free(tlvs);

  // tlvs = otrng_tlv_list_one(
  //    otrng_tlv_new(OTRNG_TLV_SMP_MESSAGE_2, sizeof(smp2_data), smp2_data));
  // tlvs = otrng_append_padding_tlv(tlvs, 500);
  // assert_tlv_structure(tlvs->next, OTRNG_TLV_PADDING, 7, smp2_data, false);
  // otrng_tlv_list_free(tlvs);

  // tlvs = otrng_append_padding_tlv(NULL, 500);
  // otrng_assert(tlvs);
  // otrng_tlv_list_free(tlvs);
}

void units_tlv_add_tests(void) {
  g_test_add_func("/tlv/parse", test_tlv_parse);
  g_test_add_func("/tlv/append", test_otrng_append_tlv);
  g_test_add_func("/tlv/append_padding", test_otrng_append_padding_tlv);
}
