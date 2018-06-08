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

#include <glib.h>
#include <goldilocks.h>

#define OTRNG_DAKE_PRIVATE
#define OTRNG_DH_PRIVATE
#define OTRNG_KEY_MANAGEMENT_PRIVATE
#define OTRNG_LIST_PRIVATE
#define OTRNG_OTRNG_PRIVATE
#define OTRNG_SMP_PRIVATE
#define OTRNG_TLV_PRIVATE
#define OTRNG_USER_PROFILE_PRIVATE

#include "../otrng.h"

// clang-format off
#include "test_helpers.h"
#include "test_fixtures.h"
// clang-format on

#include "test_api.c"
#include "test_client.c"
#include "test_dake.c"
#include "test_data_message.c"
#include "test_dh.c"
#include "test_double_ratchet.c"
#include "test_ed448.c"
#include "test_fragment.c"
#include "test_identity_message.c"
#include "test_instance_tag.c"
#include "test_key_management.c"
#include "test_list.c"
#include "test_non_interactive_messages.c"
#include "test_otrng.c"
#include "test_prekey_ensemble.c"
#include "test_prekey_profile.c"
#include "test_serialize.c"
#include "test_smp.c"
#include "test_tlv.c"
#include "test_client_profile.c"
#include "test_messaging.c"
#include "test_auth.c"

int main(int argc, char **argv) {
  if (!gcry_check_version(GCRYPT_VERSION))
    return 2;

  // TODO: we are using gcry_mpi_snew, so we might need this
  // gcry_control (GCRYCTL_INIT_SECMEM, 1);
  // gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
  // gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  /* Set to quick random so we don't wait on /dev/random. */
  gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  OTRNG_INIT;

  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/otrng/instance_tag/generates_when_file_empty",
                  test_instance_tag_generates_tag_when_file_empty);
  g_test_add_func("/otrng/instance_tag/generates_when_file_is_full",
                  test_instance_tag_generates_tag_when_file_is_full);

  g_test_add_func("/user_state/key_management", test_user_state_key_management);

  g_test_add_func("/edwards448/eddsa_serialization",
                  ed448_test_eddsa_serialization);
  g_test_add_func("/edwards448/eddsa_keygen", ed448_test_eddsa_keygen);
  g_test_add_func("/edwards448/scalar_serialization",
                  ed448_test_scalar_serialization);
  g_test_add_func("/edwards448/signature", ed448_test_signature);

  g_test_add_func("/list/add", test_otrng_list_add);
  g_test_add_func("/list/insert_at_n", test_otrng_list_insert_at_n);
  g_test_add_func("/list/get", test_otrng_list_get_last);
  g_test_add_func("/list/get_by_value", test_otrng_list_get_by_value);
  g_test_add_func("/list/length", test_otrng_list_len);
  g_test_add_func("/list/empty_size", test_list_empty_size);

  g_test_add_func("/dh/api", dh_test_api);
  g_test_add_func("/dh/serialize", dh_test_serialize);
  g_test_add_func("/dh/shared-secret/leading-zeroes",
                  dh_test_shared_secret_adds_leading_zeroes);
  g_test_add_func("/dh/destroy",
                  dh_test_keypair_destroy); // TODO: check this one

  g_test_add_func("/ring-signature/rsig_auth", test_rsig_auth);
  g_test_add_func("/ring-signature/calculate-c", test_rsig_calculate_c);

  g_test_add_func("/serialize_and_deserialize/uint", test_ser_deser_uint);
  g_test_add_func("/serialize_and_deserialize/data",
                  test_serialize_otrng_deserialize_data);

  g_test_add_func("/serialize/dh-public-key",
                  test_otrng_serialize_dh_public_key);
  g_test_add_func("/serialize_and_deserialize/ed448-public-key",
                  test_ser_des_otrng_public_key);
  g_test_add_func("/serialize_and_deserialize/ed448-shared-prekey",
                  test_ser_des_otrng_shared_prekey);
  g_test_add_func("/serialize/otrng-symmetric-key",
                  test_serialize_otrng_symmetric_key);
  g_test_add_func("/serialize/fingerprint", test_serializes_fingerprint);

  g_test_add_func("/client_profile/create", test_client_profile_create);
  g_test_add_func("/client_profile/serialize_body",
                  test_client_profile_serializes_body);
  g_test_add_func("/client_profile/serialize", test_client_profile_serializes);
  g_test_add_func("/client_profile/deserializes",
                  test_otrng_client_profile_deserializes);
  g_test_add_func("/client_profile/sign_and_verifies",
                  test_client_profile_signs_and_verify);
  g_test_add_func("/client_profile/build_client_profile",
                  test_otrng_client_profile_build);

  g_test_add_func("/dake/build_interactive_rsign_tag",
                  test_build_interactive_rsign_tag);
  g_test_add_func("/dake/xzdh_encrypted_message_asprintf",
                  test_xzdh_encrypted_message_asprintf);
  g_test_add_func("/dake/xzdh_encrypted_message_deserialize",
                  test_xzdh_encrypted_message_deserialize);

  WITH_DAKE_FIXTURE("/dake/non_interactive_auth_message/serialize",
                    test_dake_non_interactive_auth_message_serializes);
  WITH_DAKE_FIXTURE("/dake/non_interactive_auth_message/deserialize",
                    test_otrng_dake_non_interactive_auth_message_deserializes);
  WITH_DAKE_FIXTURE(
      "/dake/non_interactive_auth_message_with_encrypted_message/serialize",
      test_dake_non_interactive_auth_message_with_encrypted_message_serializes);

  WITH_DAKE_FIXTURE("/dake/identity_message/serializes",
                    test_dake_identity_message_serializes);
  WITH_DAKE_FIXTURE("/dake/identity_message/deserializes",
                    test_otrng_dake_identity_message_deserializes);
  WITH_DAKE_FIXTURE("/dake/identity_message/valid",
                    test_dake_identity_message_valid);

  g_test_add_func("/dake/prekey_message/serializes",
                  test_dake_prekey_message_serializes);
  g_test_add_func("/dake/prekey_message/deserializes",
                  test_otrng_dake_prekey_message_deserializes);
  WITH_DAKE_FIXTURE("/dake/prekey_message/valid",
                    test_dake_prekey_message_valid);

  g_test_add_func("/data_message/valid", test_data_message_valid);
  g_test_add_func("/data_message/serialize", test_data_message_serializes);
  g_test_add_func("/data_message/serialize_absent_dh",
                  test_data_message_serializes_absent_dh);
  g_test_add_func("/data_message/deserialize",
                  test_otrng_data_message_deserializes);

  g_test_add_func("/fragment/create_fragments", test_create_fragments);
  g_test_add_func("/fragment/defragment_message",
                  test_defragment_valid_message);
  g_test_add_func("/fragment/defragment_single_fragment",
                  test_defragment_single_fragment);
  g_test_add_func("/fragment/defragment_out_of_order_message",
                  test_defragment_out_of_order_message);
  g_test_add_func("/fragment/defragment_fails_without_comma",
                  test_defragment_without_comma_fails);
  g_test_add_func("/fragment/fails_for_invalid_tag",
                  test_defragment_fails_for_invalid_tag);
  g_test_add_func("/fragment/defragment_regular_otr_message",
                  test_defragment_regular_otr_message);

  g_test_add_func("/key_management/derive_ratchet_keys",
                  test_derive_ratchet_keys);
  g_test_add_func("/key_management/ssid", test_calculate_ssid);
  g_test_add_func("/key_management/extra_symm_key",
                  test_calculate_extra_symm_key);
  g_test_add_func("/key_management/brace_key", test_calculate_brace_key);

  g_test_add_func("/smp/state_machine", test_smp_state_machine);
  g_test_add_func("/smp/generate_secret", test_otrng_generate_smp_secret);
  g_test_add_func("/smp/msg_1_asprintf_null_question",
                  test_otrng_smp_msg_1_asprintf_null_question);
  g_test_add_func("/tlv/parse", test_tlv_parse);
  g_test_add_func("/tlv/append", test_otrng_append_tlv);
  g_test_add_func("/tlv/append_padding", test_otrng_append_padding_tlv);

  // TODO: why we have this?
  // g_test_add_func("/otrng/starts_protocol", test_otrng_starts_protocol);
  // g_test_add("/otrng/version_supports_v34", otrng_fixture_s, NULL,
  // otrng_fixture_set_up, test_otrng_version_supports_v34,
  // otrng_fixture_teardown );
  g_test_add("/otrng/builds_query_message", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_builds_query_message,
             otrng_fixture_teardown);
  g_test_add("/otrng/builds_query_message_v34", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_builds_query_message_v34,
             otrng_fixture_teardown);
  g_test_add("/otrng/builds_whitespace_tag", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_builds_whitespace_tag,
             otrng_fixture_teardown);
  g_test_add("/otrng/builds_whitespace_tag_v34", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_builds_whitespace_tag_v34,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_without_ws_tag_on_start",
             otrng_fixture_s, NULL, otrng_fixture_set_up,
             test_otrng_receives_plaintext_without_ws_tag_on_start,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_without_ws_tag_not_on_start",
             otrng_fixture_s, NULL, otrng_fixture_set_up,
             test_otrng_receives_plaintext_without_ws_tag_not_on_start,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_with_ws_tag", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_receives_plaintext_with_ws_tag,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_with_ws_tag_after_text",
             otrng_fixture_s, NULL, otrng_fixture_set_up,
             test_otrng_receives_plaintext_with_ws_tag_after_text,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_plaintext_with_ws_tag_v3", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_receives_plaintext_with_ws_tag_v3,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_query_message", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_receives_query_message,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_query_message_v3", otrng_fixture_s, NULL,
             otrng_fixture_set_up, test_otrng_receives_query_message_v3,
             otrng_fixture_teardown);
  g_test_add("/otrng/receives_invalid_instance_tag_on_identity_message",
             otrng_fixture_s, NULL, otrng_fixture_set_up,
             test_otrng_receives_identity_message_validates_instance_tag,
             otrng_fixture_teardown);
  g_test_add_func("/otrng/destroy", test_otrng_destroy);

  g_test_add_func("/otrng/build_prekey_ensemble",
                  test_otrng_build_prekey_ensemble);

  g_test_add_func("/prekey_profile/validates", test_prekey_profile_validates);
  g_test_add_func("/prekey_ensemble/validate", test_prekey_ensemble_validate);

  g_test_add_func("/client/conversation_api", test_client_conversation_api);
  g_test_add_func("/client/api", test_client_api);
  g_test_add_func("/client/get_our_fingerprint",
                  test_client_get_our_fingerprint);
  g_test_add_func("/client/fingerprint_to_human",
                  test_fingerprint_hash_to_human);
  g_test_add_func("/client/sends_fragments",
                  test_client_sends_fragmented_message);
  g_test_add_func("/client/receives_fragments",
                  test_client_receives_fragmented_message);

  g_test_add_func("/client/conversation_data_message_multiple_locations",
                  test_conversation_with_multiple_locations);
  g_test_add_func("/client/identity_message_in_waiting_auth_i",
                  test_valid_identity_msg_in_waiting_auth_i);
  g_test_add_func("/client/identity_message_in_waiting_auth_r",
                  test_valid_identity_msg_in_waiting_auth_r);
  g_test_add_func("/client/invalid_auth_r_msg_in_not_waiting_auth_r",
                  test_invalid_auth_r_msg_in_not_waiting_auth_r);
  g_test_add_func("/client/invalid_auth_i_msg_in_not_waiting_auth_i",
                  test_invalid_auth_i_msg_in_not_waiting_auth_i);

  // API are supposed to test the public API.
  // They go to the end because they are integration tests, and we only should
  // care about them after all the unit tests are working.
  // TODO: There is TOO MUCH /api tests. They are TOO BIG and hard to
  // understand (by nature, I think). Let's reconsider what should be here.

  g_test_add_func("/double_ratchet/in_order/new_sending_ratchet/v4",
                  test_api_new_sending_ratchet_in_order);
  g_test_add_func("/double_ratchet/out_of_order/same_ratchet/v4",
                  test_api_same_ratchet_out_of_order);
  g_test_add_func("/double_ratchet/out_of_order/new_ratchet/v4",
                  test_api_new_ratchet_out_of_order);

  g_test_add_func("/api/interactive_conversation/v4",
                  test_api_interactive_conversation);
  g_test_add_func("/api/send_offline_message", test_otrng_send_offline_message);

  // g_test_add_func("/api/non_interactive_conversation/v4",
  //                test_api_non_interactive_conversation);
  // g_test_add_func("/api/non_interactive_conversation_enc_msg_1/v4",
  //                test_api_non_interactive_conversation_with_enc_msg_1);
  // g_test_add_func("/api/non_interactive_conversation_enc_msg_2/v4",
  //                test_api_non_interactive_conversation_with_enc_msg_2);

  g_test_add_func("/api/multiple_clients", test_api_multiple_clients);
  g_test_add_func("/api/conversation_errors_1", test_api_conversation_errors_1);
  g_test_add_func("/api/conversation_errors_2", test_api_conversation_errors_2);
  g_test_add_func("/api/conversation/v3", test_api_conversation_v3);
  g_test_add_func("/api/smp", test_api_smp);
  g_test_add_func("/api/smp_abort", test_api_smp_abort);
  /* g_test_add_func("/api/messaging", test_api_messaging); */
  g_test_add_func("/api/instance_tag", test_instance_tag_api);
  g_test_add_func("/api/extra_symm_key", test_api_extra_sym_key);
  g_test_add_func("/api/unreadable", test_unreadable_flag);
  g_test_add_func("/api/heartbeat", test_heartbeat_messages);

  int ret = g_test_run();
  OTRNG_FREE;
  return ret;
}
