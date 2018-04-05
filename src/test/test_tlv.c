/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
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

#include "../tlv.h"

void assert_tlv_structure(tlv_t *tlv, tlv_type_t type, uint16_t len,
                          uint8_t *data, bool next) {
  otrng_assert(tlv);
  otrng_assert(tlv->type == type);
  otrng_assert(tlv->len == len);
  if (next) {
    otrng_assert(tlv->next != NULL);
  } else {
    otrng_assert(tlv->next == NULL);
  }
  if (type != OTRNG_TLV_PADDING) {
    otrng_assert_cmpmem(tlv->data, data, len);
  }
}

void test_tlv_parse() {
  uint8_t msg[22] = {0x00, 0x06, 0x00, 0x03, 0x08, 0x05, 0x09, 0x00,
                     0x02, 0x00, 0x04, 0xac, 0x04, 0x05, 0x06, 0x00,
                     0x05, 0x00, 0x03, 0x08, 0x05, 0x09};

  uint8_t data[3] = {0x08, 0x05, 0x09};
  uint8_t data2[4] = {0xac, 0x04, 0x05, 0x06};

  tlv_t *tlv = otrng_parse_tlvs(msg, sizeof(msg));
  assert_tlv_structure(tlv, OTRNG_TLV_SMP_ABORT, sizeof(data), data, true);
  assert_tlv_structure(tlv->next, OTRNG_TLV_SMP_MSG_1, sizeof(data2), data2,
                       true);
  assert_tlv_structure(tlv->next->next, OTRNG_TLV_SMP_MSG_4, sizeof(data), data,
                       false);

  otrng_tlv_free(tlv);
}

void test_otrng_append_tlv() {
  uint8_t smp2_data[2] = {0x03, 0x04};
  uint8_t smp3_data[3] = {0x05, 0x04, 0x03};

  tlv_t *tlvs = NULL;
  tlv_t *smp_msg2_tlv =
      otrng_tlv_new(OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data);
  tlv_t *smp_msg3_tlv =
      otrng_tlv_new(OTRNG_TLV_SMP_MSG_3, sizeof(smp3_data), smp3_data);

  tlvs = otrng_append_tlv(tlvs, smp_msg2_tlv);

  assert_tlv_structure(tlvs, OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data,
                       false);

  tlvs = otrng_append_tlv(tlvs, smp_msg3_tlv);

  assert_tlv_structure(tlvs, OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data,
                       true);
  assert_tlv_structure(tlvs->next, OTRNG_TLV_SMP_MSG_3, sizeof(smp3_data),
                       smp3_data, false);

  assert_tlv_structure(tlvs, OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data,
                       true);

  otrng_tlv_free(tlvs);
}

void test_otrng_append_padding_tlv() {
  uint8_t smp2_data[2] = {0x03, 0x04};

  tlv_t *tlv = otrng_tlv_new(OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data);
  otrng_err_t err = otrng_append_padding_tlv(&tlv, 6);
  otrng_assert(err == SUCCESS);
  assert_tlv_structure(tlv->next, OTRNG_TLV_PADDING, 245, smp2_data, false);
  otrng_tlv_free(tlv);

  tlv = otrng_tlv_new(OTRNG_TLV_SMP_MSG_2, sizeof(smp2_data), smp2_data);
  err = otrng_append_padding_tlv(&tlv, 500);
  assert_tlv_structure(tlv->next, OTRNG_TLV_PADDING, 7, smp2_data, false);
  otrng_tlv_free(tlv);

  tlv = NULL;
  err = otrng_append_padding_tlv(&tlv, 500);
  otrng_assert(err == SUCCESS);
  otrng_assert(tlv);
  otrng_tlv_free(tlv);
}
