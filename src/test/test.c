#include <glib.h>

#include "test_helpers.h"
#include "test_fixtures.h"

#include "test_api.c"
#include "test_otrv4.c"
#include "test_identity_message.c"
#include "test_dake.c"
#include "test_user_profile.c"
#include "test_ed448.c"
#include "test_dh.c"
#include "test_cramershoup.c"
#include "test_serialize.c"
#include "test_key_management.c"
#include "test_data_message.c"
#include "test_client.c"
#include "test_list.c"
#include "test_smp.c"

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/dake/dread", test_dread);
	g_test_add_func("/dake/snizkpk", test_snizkpk_auth);

	g_test_add_func("/list/add", test_list_add);

	g_test_add_func("/ed448/api", ed448_test_ecdh);
	g_test_add_func("/dh/api", dh_test_api);
	g_test_add_func("/dh/serialize", dh_test_serialize);

	g_test_add_func("/cramershoup/serialize_private_key",
			cramershoup_test_serialize_private_key);

	g_test_add_func("/serialize_and_deserialize/uint", test_ser_deser_uint);
	g_test_add_func("/serialize_and_deserialize/data",
			test_serialize_deserialize_data);
	g_test_add_func("/serialize_and_deserialize/cramer-shoup",
			test_ser_des_cs_public_key);

	g_test_add_func("/user_profile/create", test_user_profile_create);
	g_test_add_func("/user_profile/serialize_body",
			test_user_profile_serializes_body);
	g_test_add_func("/user_profile/serialize",
			test_user_profile_serializes);
	g_test_add_func("/user_profile/deserializes",
			test_user_profile_deserializes);
	g_test_add_func("/user_profile/sign_and_verifies",
			test_user_profile_signs_and_verify);
	g_test_add_func("/user_profile/build_user_profile",
			test_user_profile_build);

	WITH_FIXTURE("/dake/identity_message/new",
		     test_dake_identity_message_new, identity_message_fixture_t,
		     identity_message_fixture);
	WITH_FIXTURE("/dake/identity_message/serializes",
		     test_dake_identity_message_serializes,
		     identity_message_fixture_t, identity_message_fixture);
	WITH_FIXTURE("/dake/identity_message/deserializes",
		     test_dake_identity_message_deserializes,
		     identity_message_fixture_t, identity_message_fixture);
	WITH_FIXTURE("/dake/identity_message/valid",
		     test_dake_identity_message_valid,
		     identity_message_fixture_t, identity_message_fixture);

	g_test_add_func("/dake/dre_auth/generate_gamma_phi_sigma",
			test_dake_generate_gamma_phi_sigma);
	g_test_add_func("/dake/dre_auth/serialize",
			test_dake_dre_auth_serialize);
	g_test_add_func("/dake/protocol", test_dake_protocol);

	g_test_add_func("/data_message/serialize",
			test_data_message_serializes);

	g_test_add_func("/key_management/derive_ratchet_keys",
			test_derive_ratchet_keys);

	g_test_add_func("/smp/state_machine", test_smp_state_machine);

	//g_test_add_func("/otrv4/starts_protocol", test_otrv4_starts_protocol);
	//g_test_add("/otrv4/version_supports_v34", otrv4_fixture_t, NULL, otrv4_fixture_set_up, test_otrv4_version_supports_v34, otrv4_fixture_teardown );
	g_test_add("/otrv4/builds_query_message", otrv4_fixture_t, NULL,
		   otrv4_fixture_set_up, test_otrv4_builds_query_message,
		   otrv4_fixture_teardown);
	g_test_add("/otrv4/builds_query_message_v34", otrv4_fixture_t, NULL,
		   otrv4_fixture_set_up, test_otrv4_builds_query_message_v34,
		   otrv4_fixture_teardown);
	g_test_add("/otrv4/builds_whitespace_tag", otrv4_fixture_t, NULL,
		   otrv4_fixture_set_up, test_otrv4_builds_whitespace_tag,
		   otrv4_fixture_teardown);
	g_test_add("/otrv4/builds_whitespace_tag_v34", otrv4_fixture_t, NULL,
		   otrv4_fixture_set_up, test_otrv4_builds_whitespace_tag_v34,
		   otrv4_fixture_teardown);
	g_test_add("/otrv4/receives_plaintext_without_ws_tag_on_start",
		   otrv4_fixture_t, NULL, otrv4_fixture_set_up,
		   test_otrv4_receives_plaintext_without_ws_tag_on_start,
		   otrv4_fixture_teardown);
	g_test_add("/otrv4/receives_plaintext_without_ws_tag_not_on_start",
		   otrv4_fixture_t, NULL, otrv4_fixture_set_up,
		   test_otrv4_receives_plaintext_without_ws_tag_not_on_start,
		   otrv4_fixture_teardown);
	g_test_add("/otrv4/receives_plaintext_with_ws_tag", otrv4_fixture_t,
		   NULL, otrv4_fixture_set_up,
		   test_otrv4_receives_plaintext_with_ws_tag,
		   otrv4_fixture_teardown);
	g_test_add("/otrv4/receives_plaintext_with_ws_tag_v3", otrv4_fixture_t,
		   NULL, otrv4_fixture_set_up,
		   test_otrv4_receives_plaintext_with_ws_tag_v3,
		   otrv4_fixture_teardown);
	g_test_add("/otrv4/receives_query_message", otrv4_fixture_t, NULL,
		   otrv4_fixture_set_up, test_otrv4_receives_query_message,
		   otrv4_fixture_teardown);
	g_test_add("/otrv4/receives_query_message_v3", otrv4_fixture_t, NULL,
		   otrv4_fixture_set_up, test_otrv4_receives_query_message_v3,
		   otrv4_fixture_teardown);
	g_test_add_func("/otrv4/destroy", test_otrv4_destroy);

	g_test_add_func("/client/conversation_api",
			test_client_conversation_api);
	g_test_add_func("/client/api", test_client_api);
	g_test_add_func("/client/get_our_fingerprint",
			test_client_get_our_fingerprint);
	g_test_add_func("/client/fingerprint_to_human",
			test_fingerprint_hash_to_human);

	g_test_add_func("/api/conversation", test_api_conversation);

	return g_test_run();
}
