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

/**
 * The functions in this file only operate on their arguments, and doesn't touch
 * any global state. It is safe to call these functions concurrently from
 * different threads, as long as arguments pointing to the same memory areas are
 * not used from different threads.
 */

#ifndef OTRNG_TLV_H
#define OTRNG_TLV_H

#include <stddef.h>
#include <stdint.h>

#include "shared.h"

typedef enum {
  OTRNG_TLV_NONE = -1,
  OTRNG_TLV_PADDING = 0,
  OTRNG_TLV_DISCONNECTED = 1,
  OTRNG_TLV_SMP_MSG_1 = 2,
  OTRNG_TLV_SMP_MSG_2 = 3,
  OTRNG_TLV_SMP_MSG_3 = 4,
  OTRNG_TLV_SMP_MSG_4 = 5,
  OTRNG_TLV_SMP_ABORT = 6,
  OTRNG_TLV_SYM_KEY = 7
} otrng_tlv_type;

/**
 * @brief The tlv_s structure represents one TLV from a data message.
 *
 *  [type] this will always be one of the valid types from otrng_tlv_type
 *  [len]  the length of the associated data
 *  [data] if there is associated data, this buffer will be [len] bytes long
 *         if [len] is zero, the buffer can be NULL or a zero length pointer
 **/
typedef struct tlv_s {
  otrng_tlv_type type;
  uint16_t len;
  uint8_t *data;
} tlv_s;

/**
 * @brief The tlv_list_s structure represents one link in a linked list of TLVs.
 *
 *  [data] the TLV this list node points to. should never be NULL.
 *  [next] the next node of the list. can be NULL.
 **/
typedef struct tlv_list_s {
  tlv_s *data;
  struct tlv_list_s *next;
} tlv_list_s;

/**
 * @brief Frees the given list of TLVs
 *
 * @param [tlvs] the first node of the list of TLVs to be freed. can be NULL.
 *
 * @warning It is NOT safe to call this twice with the same argument, since
 *    after freeing each TLV, the [data] attribute of the list nodes will be
 *    set to NULL.
 *
 * @warning It is NOT safe to call this on a node that is not first in the list,
 *    unless you explicitly NULL out the [next] pointer of the previous entry.
 **/
INTERNAL void otrng_tlv_list_free(tlv_list_s *tlvs);

/**
 * @brief Returns a new list with one entry, the given [tlv] argument
 *
 * @param [tlv] the TLV to put as the only entry. If given NULL, the function
 *              returns NULL.
 *
 * @return the newly created list, if successful. it is the callers
 *    responsibility to free it after use.
 *    returns NULL if something goes wrong, or if [tlv] is NULL.
 **/
/*@null@*/ INTERNAL tlv_list_s *otrng_tlv_list_one(tlv_s *tlv);

/**
 * @brief Returns a newly created disconnected TLV
 *
 * @return the newly TLV, if successful. it is the callers
 *    responsibility to free it after use.
 *    returns NULL if something goes wrong.
 **/
/*@null@*/ INTERNAL tlv_s *otrng_tlv_disconnected_new(void);

/**
 * @brief Tries to extract as many TLVs as possible in the memory region from
 *    [src] to [src]+[len].
 *
 * @param [src] the pointer to where to start parsing. can't be NULL
 * @param [len] the amount of data to parse. can be 0.
 *
 * @return the TLV list, if successful. it is the callers
 *    responsibility to free it after use.
 *    returns NULL if no TLVs can be found.
 **/
/*@null@*/ INTERNAL tlv_list_s *otrng_parse_tlvs(const uint8_t *src,
                                                 size_t len);

/**
 * @brief creates a new TLV from the given data.
 *
 * @param [type] the type of the TLV to create. should be one of
 *               otrng_tlv_type
 * @param [len]  the amount of data to associate with this TLV. can be 0
 * @param [data] the data to put in the TLV. [len] bytes from this buffer will
 *                be copied into the TLV. can be NULL, but only if [len] is 0.
 *
 * @return the newly created TLV, if successful. It is the callers
 *         responsibility to free it after use.
 *         returns NULL if something goes wrong, if [data] is NULL when [len]
           is > 0.
 **/
/*@null@*/ INTERNAL tlv_s *otrng_tlv_new(const uint16_t type,
                                         const uint16_t len,
                                         /*@null@*/ const uint8_t *data);

/**
 * @brief appends the given TLV to the list of TLVs
 *
 * @param [tlvs] the list of TLVs to add the TLV to. Can be NULL. If given
 *               the last nodes next-pointer will be modified.
 * @param [tlv]  the TLV to add.
 *
 * @return if given [tlvs], returns it - otherwise a newly created TLV list.
 *         It is the callers responsibility to free it after use.
 *         Returns NULL if something goes wrong, or if [tlv] is NULL
 **/
/*@null@*/ INTERNAL tlv_list_s *otrng_append_tlv(/*@null@*/ tlv_list_s *tlvs,
                                                 tlv_s *tlv);

/*@null@*/ INTERNAL tlv_s *otrng_tlv_padding_new(size_t len);

INTERNAL void otrng_tlv_free(tlv_s *tlv);

INTERNAL size_t otrng_tlv_serialize(uint8_t *dst, const tlv_s *tlv);

#endif
