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

#ifndef OTRNG_PERSISTENCE_H
#define OTRNG_PERSISTENCE_H

#ifdef OTRNG_PERSISTENCE_PRIVATE

#include "messaging.h"

INTERNAL otrng_result
otrng_client_private_key_v4_read_from(otrng_client_s *client, FILE *privf);

INTERNAL otrng_result otrng_client_forging_key_read_from(otrng_client_s *client,
                                                         FILE *forgingf);

INTERNAL otrng_result
otrng_client_private_key_v4_write_to(const otrng_client_s *client, FILE *privf);

INTERNAL otrng_result
otrng_client_forging_key_write_to(const otrng_client_s *client, FILE *forgingf);

INTERNAL otrng_result
otrng_client_instance_tag_read_from(otrng_client_s *client, FILE *instagf);

INTERNAL otrng_result otrng_client_instance_tag_write_to(otrng_client_s *client,
                                                         FILE *instagf);

INTERNAL otrng_result
otrng_client_private_key_v3_write_to(const otrng_client_s *client, FILE *privf);

INTERNAL otrng_result otrng_client_private_key_v3_read_from(
    const otrng_client_s *client, FILE *privf);

INTERNAL otrng_result
otrng_client_client_profile_read_from(otrng_client_s *client, FILE *profilef);

INTERNAL otrng_result otrng_client_expired_client_profile_read_from(
    otrng_client_s *client, FILE *exp_profilef);

INTERNAL otrng_result otrng_client_client_profile_write_to(
    const otrng_client_s *client, FILE *profilef);

INTERNAL otrng_result otrng_client_expired_client_profile_write_to(
    const otrng_client_s *client, FILE *profilef);

INTERNAL otrng_result
otrng_client_prekeys_write_to(const otrng_client_s *client, FILE *prekeyf);

INTERNAL otrng_result
otrng_client_prekey_messages_read_from(otrng_client_s *client, FILE *prekeyf);

INTERNAL otrng_result
otrng_client_prekey_profile_read_from(otrng_client_s *client, FILE *profilef);

INTERNAL otrng_result otrng_client_expired_prekey_profile_read_from(
    otrng_client_s *client, FILE *expired_profilef);

INTERNAL otrng_result
otrng_client_prekey_profile_write_to(otrng_client_s *client, FILE *profilef);

INTERNAL otrng_result otrng_client_expired_prekey_profile_write_to(
    otrng_client_s *client, FILE *profilef);

INTERNAL otrng_result otrng_client_fingerprint_v4_read_from(
    otrng_global_state_s *gs, FILE *fp,
    otrng_client_s *(*get_client)(otrng_global_state_s *,
                                  const otrng_client_id_s));

INTERNAL otrng_result
otrng_client_fingerprints_v4_write_to(const otrng_client_s *client, FILE *fp);

/* This function will export the private identity necessary to reform it on
   another device in a standard format.
   It will export the private v4 long term key, and the public forging key. The
   format is a simple delimited format, where each entry is separated by a
   colon. The format looks like this: "v4:privatekey:forgingkey:hash". The last
   three entries are all hexadecimal representations of their data. The hash is
   SHAKE-256 with output length 256 of the two bytes "v4", followed by the raw
   bytes of the privatekey and forgingkey (not their hexadecimal
   representation). */
API otrng_result otrng_client_export_v4_identity(otrng_client_s *client,
                                                 FILE *fp);

/* This function imports data that is in the same format as specified for
 * otrng_client_export_v4_identity */
API otrng_result otrng_client_import_v4_identity(otrng_client_s *client,
                                                 FILE *fp);

#endif

#endif
