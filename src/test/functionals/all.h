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

#ifndef __TEST_FUNCTIONALS_ALL_H__
#define __TEST_FUNCTIONALS_ALL_H__

void functionals_api_add_tests(void);
void functionals_auth_add_tests(void);
void functionals_client_add_tests(void);
void functionals_client_profile_add_tests(void);
void functionals_dake_add_tests(void);
void functionals_data_message_add_tests(void);
void functionals_dh_add_tests(void);
void functionals_double_ratchet_add_tests(void);
void functionals_ed448_add_tests(void);
void functionals_fragment_add_tests(void);
void functionals_identity_message_add_tests(void);
void functionals_instance_tag_add_tests(void);
void functionals_key_management_add_tests(void);
void functionals_list_add_tests(void);
void functionals_messaging_add_tests(void);
void functionals_non_interactive_messages_add_tests(void);
void functionals_otrng_add_tests(void);
void functionals_prekey_client_add_tests(void);
void functionals_prekey_ensemble_add_tests(void);
void functionals_prekey_messages_add_tests(void);
void functionals_prekey_profile_add_tests(void);
void functionals_prekey_proofs_add_tests(void);
void functionals_prekey_server_client_add_tests(void);
void functionals_serialize_add_tests(void);
void functionals_smp_add_tests(void);
void functionals_standard_add_tests(void);
void functionals_tlv_add_tests(void);

#define REGISTER_FUNCTIONALS do { \
    functionals_api_add_tests(); \
    functionals_auth_add_tests(); \
    functionals_client_add_tests(); \
    functionals_client_profile_add_tests(); \
    functionals_dake_add_tests(); \
    functionals_data_message_add_tests(); \
    functionals_dh_add_tests(); \
    functionals_double_ratchet_add_tests(); \
    functionals_ed448_add_tests(); \
    functionals_fragment_add_tests(); \
    functionals_identity_message_add_tests(); \
    functionals_instance_tag_add_tests(); \
    functionals_key_management_add_tests(); \
    functionals_list_add_tests(); \
    functionals_messaging_add_tests(); \
    functionals_non_interactive_messages_add_tests(); \
    functionals_otrng_add_tests(); \
    functionals_prekey_client_add_tests(); \
    functionals_prekey_ensemble_add_tests(); \
    functionals_prekey_messages_add_tests(); \
    functionals_prekey_profile_add_tests(); \
    functionals_prekey_proofs_add_tests(); \
    functionals_prekey_server_client_add_tests(); \
    functionals_serialize_add_tests(); \
    functionals_smp_add_tests(); \
    functionals_standard_add_tests(); \
    functionals_tlv_add_tests(); \
  } while(0);


#endif // __TEST_FUNCTIONALS_ALL_H__
