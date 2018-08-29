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

#ifndef OTRNG_PERSISTENCE_H
#define OTRNG_PERSISTENCE_H

#include "client_state.h"

#ifdef OTRNG_PERSISTENCE_PRIVATE

INTERNAL otrng_result otrng_client_state_private_key_v4_read_FILEp(
    otrng_client_state_s *state, FILE *privf);

INTERNAL otrng_result otrng_client_state_private_key_v4_write_FILEp(
    const otrng_client_state_s *state, FILE *privf);

INTERNAL otrng_result otrng_client_state_instance_tag_read_FILEp(
    otrng_client_state_s *state, FILE *instag);

INTERNAL otrng_result otrng_client_state_instance_tag_write_FILEp(
    otrng_client_state_s *state, FILE *instagf);

INTERNAL otrng_result otrng_client_state_private_key_v3_write_FILEp(
    const otrng_client_state_s *state, FILE *privf);

INTERNAL otrng_result otrng_client_state_client_profile_read_FILEp(
    otrng_client_state_s *state, FILE *privf);

INTERNAL otrng_result otrng_client_state_client_profile_write_FILEp(
    const otrng_client_state_s *state, FILE *privf);

INTERNAL otrng_result otrng_client_state_prekeys_write_FILEp(
    const otrng_client_state_s *state, FILE *privf);

INTERNAL otrng_result
otrng_client_state_prekey_messages_read_FILEp(otrng_client_state_s *state,
                                              FILE *privf);

INTERNAL otrng_result serialize_and_store_prekey(
    const otrng_stored_prekeys_s *prekey, const char *storage_id, FILE *privf);

#endif

#endif
