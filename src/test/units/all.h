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

#ifndef __TEST_UNIT_ALL_H__
#define __TEST_UNIT_ALL_H__

void units_auth_add_tests(void);
void units_client_add_tests(void);
void units_client_profile_add_tests(void);
void units_dake_add_tests(void);
void units_data_message_add_tests(void);
void units_dh_add_tests(void);
void units_ed448_add_tests(void);
void units_fragment_add_tests(void);
void units_identity_message_add_tests(void);
void units_instance_tag_add_tests(void);
void units_key_management_add_tests(void);
void units_list_add_tests(void);
void units_messaging_add_tests(void);
void units_non_interactive_messages_add_tests(void);
void units_otrng_add_tests(void);
void units_prekey_ensemble_add_tests(void);
void units_prekey_messages_add_tests(void);
void units_prekey_profile_add_tests(void);
void units_prekey_proofs_add_tests(void);
void units_prekey_server_client_add_tests(void);
void units_serialize_add_tests(void);
void units_standard_add_tests(void);
void units_tlv_add_tests(void);

#define REGISTER_UNITS do { \
  units_auth_add_tests(); \
  units_client_add_tests(); \
  units_client_profile_add_tests(); \
  units_dake_add_tests(); \
  units_data_message_add_tests(); \
  units_dh_add_tests(); \
  units_ed448_add_tests(); \
  units_fragment_add_tests(); \
  units_identity_message_add_tests(); \
  units_instance_tag_add_tests(); \
  units_key_management_add_tests(); \
  units_list_add_tests(); \
  units_messaging_add_tests(); \
  units_non_interactive_messages_add_tests(); \
  units_otrng_add_tests(); \
  units_prekey_ensemble_add_tests(); \
  units_prekey_messages_add_tests(); \
  units_prekey_profile_add_tests(); \
  units_prekey_proofs_add_tests(); \
  units_prekey_server_client_add_tests(); \
  units_serialize_add_tests(); \
  units_standard_add_tests(); \
  units_tlv_add_tests(); \
  } while(0);


#endif // __TEST_UNIT_ALL_H__
