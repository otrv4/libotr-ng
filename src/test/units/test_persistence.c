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

#include "persistence.h"

/* Expects the file pointer to be at the END of the file */
static char *read_full_file(FILE *fp) {
  long fsize = ftell(fp);
  char *buffer;
  size_t result;

  if (fsize < 0) {
    return NULL;
  }

  buffer = malloc(fsize + 1);

  rewind(fp);
  result = fread(buffer, fsize, 1, fp);
  if (result < 1) {
    free(buffer);
    return NULL;
  }

  buffer[fsize] = 0;

  return buffer;
}

static void test_persistence_export_v4() {
  otrng_client_id_s client_id;
  otrng_client_s *client;
  otrng_keypair_s *forging_key;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1};
  uint8_t sym2[ED448_PRIVATE_BYTES] = {2};

  forging_key = otrng_keypair_new();
  otrng_keypair_generate(forging_key, sym2);

  client_id.protocol = otrng_xstrdup("test-otr");
  client_id.account = otrng_xstrdup("sita@otr.im");

  client = otrng_client_new(client_id);

  client->keypair = otrng_keypair_new();
  otrng_keypair_generate(client->keypair, sym1);
  client->forging_key = &forging_key->pub;

  FILE *fp = tmpfile();
  otrng_assert_is_success(otrng_client_export_v4_identity(client, fp));
  char *content = read_full_file(fp);
  fclose(fp);

  g_assert_cmpstr(
      content, ==,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00:"
      "23cc3480363c69eaa3de50523ef085998b17321dca8f31187b5e14d2f37dc10a");
  otrng_free(content);

  client->forging_key = NULL;
  otrng_secure_free(forging_key);
  otrng_client_free(client);
}

static void test_persistence_export_v4_failure1() {
  otrng_client_id_s client_id;
  otrng_client_s *client;
  otrng_keypair_s *forging_key;
  uint8_t sym2[ED448_PRIVATE_BYTES] = {2};

  forging_key = otrng_keypair_new();
  otrng_keypair_generate(forging_key, sym2);

  client_id.protocol = otrng_xstrdup("test-otr");
  client_id.account = otrng_xstrdup("sita@otr.im");

  client = otrng_client_new(client_id);

  client->forging_key = &forging_key->pub;

  FILE *fp = tmpfile();
  otrng_assert_is_error(otrng_client_export_v4_identity(client, fp));
  fclose(fp);

  client->forging_key = NULL;
  otrng_secure_free(forging_key);
  otrng_client_free(client);
}

static void test_persistence_export_v4_failure2() {
  otrng_client_id_s client_id;
  otrng_client_s *client;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1};

  client_id.protocol = otrng_xstrdup("test-otr");
  client_id.account = otrng_xstrdup("sita@otr.im");

  client = otrng_client_new(client_id);

  client->keypair = otrng_keypair_new();
  otrng_keypair_generate(client->keypair, sym1);

  FILE *fp = tmpfile();
  otrng_assert_is_error(otrng_client_export_v4_identity(client, fp));
  fclose(fp);

  otrng_client_free(client);
}

static void test_persistence_export_v4_failure3() {
  otrng_client_id_s client_id;
  otrng_client_s *client;
  otrng_keypair_s *forging_key;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {1};
  uint8_t sym2[ED448_PRIVATE_BYTES] = {2};

  forging_key = otrng_keypair_new();
  otrng_keypair_generate(forging_key, sym2);

  client_id.protocol = otrng_xstrdup("test-otr");
  client_id.account = otrng_xstrdup("sita@otr.im");

  client = otrng_client_new(client_id);

  client->keypair = otrng_keypair_new();
  otrng_keypair_generate(client->keypair, sym1);
  client->forging_key = &forging_key->pub;

  otrng_assert_is_error(otrng_client_export_v4_identity(client, NULL));

  client->forging_key = NULL;
  otrng_secure_free(forging_key);
  otrng_client_free(client);
}

static void test_persistence_import_v4() {
  otrng_client_id_s client_id;
  otrng_client_s *client;
  otrng_keypair_s *forging_key, *forging_key_compare;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {3};
  uint8_t sym2[ED448_PRIVATE_BYTES] = {4};
  uint8_t sym1_compare[ED448_PRIVATE_BYTES] = {1};
  uint8_t sym2_compare[ED448_PRIVATE_BYTES] = {2};

  forging_key = otrng_keypair_new();
  otrng_keypair_generate(forging_key, sym2);

  forging_key_compare = otrng_keypair_new();
  otrng_keypair_generate(forging_key_compare, sym2_compare);

  client_id.protocol = otrng_xstrdup("test-otr");
  client_id.account = otrng_xstrdup("sita@otr.im");

  client = otrng_client_new(client_id);

  client->keypair = otrng_keypair_new();
  otrng_keypair_generate(client->keypair, sym1);

  client->forging_key = otrng_xmalloc_z(sizeof(otrng_public_key));
  otrng_ec_point_copy(*client->forging_key, forging_key->pub);

  FILE *fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00:"
      "23cc3480363c69eaa3de50523ef085998b17321dca8f31187b5e14d2f37dc10a");
  rewind(fp);
  otrng_assert_is_success(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  otrng_assert_cmpmem(sym1_compare, client->keypair->sym, ED448_PRIVATE_BYTES);
  otrng_assert(
      otrng_ec_point_eq(forging_key_compare->pub, *client->forging_key));

  otrng_ec_point_destroy(*client->forging_key);
  otrng_free(client->forging_key);
  client->forging_key = NULL;
  otrng_secure_free(forging_key);
  otrng_secure_free(forging_key_compare);
  otrng_client_free(client);
}

static void test_persistence_import_v4_failures() {
  otrng_client_id_s client_id;
  otrng_client_s *client;
  otrng_keypair_s *forging_key, *forging_key_compare;
  uint8_t sym1[ED448_PRIVATE_BYTES] = {3};
  uint8_t sym2[ED448_PRIVATE_BYTES] = {4};
  /* uint8_t sym1_compare[ED448_PRIVATE_BYTES] = {1}; */
  uint8_t sym2_compare[ED448_PRIVATE_BYTES] = {2};

  forging_key = otrng_keypair_new();
  otrng_keypair_generate(forging_key, sym2);

  forging_key_compare = otrng_keypair_new();
  otrng_keypair_generate(forging_key_compare, sym2_compare);

  client_id.protocol = otrng_xstrdup("test-otr");
  client_id.account = otrng_xstrdup("sita@otr.im");

  client = otrng_client_new(client_id);

  client->keypair = otrng_keypair_new();
  otrng_keypair_generate(client->keypair, sym1);

  client->forging_key = otrng_xmalloc_z(sizeof(otrng_public_key));
  otrng_ec_point_copy(*client->forging_key, forging_key->pub);

  /* Wrong version tag */
  FILE *fp = tmpfile();
  fprintf(
      fp,
      "v3:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00:"
      "23cc3480363c69eaa3de50523ef085998b17321dca8f31187b5e14d2f37dc10a");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* No content */
  fp = tmpfile();
  //  fprintf(fp, "");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Wrong version tag */
  fp = tmpfile();
  fprintf(fp, "xxxxx");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* No field separator */
  fp = tmpfile();
  fprintf(fp, "v4");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Wrong field separator */
  fp = tmpfile();
  fprintf(fp, "v4!");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Too short */
  fp = tmpfile();
  fprintf(fp, "v4:010101");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Uneven hex */
  fp = tmpfile();
  fprintf(fp, "v4:0101010");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Not hex */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "00000000000000000000000000000000000000000x");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* No field separator*/
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Wrong field separator*/
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000!");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Too short */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "010101");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Not hex */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "0101010");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Not hex */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc0x");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* No field separator */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Wrong field separator */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00!");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* No field following */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00:");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Too short */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00:"
      "010101");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Uneven hex */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00:"
      "0101010");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Not hex */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00:"
      "23cc3480363c69eaa3de50523ef085998b17321dca8f31187b5e14d2f37dc10x");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  /* Incorrect hash */
  fp = tmpfile();
  fprintf(
      fp,
      "v4:"
      "010000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000:"
      "984c9c0bfb0a3b1052170d68cbc383a8943d7e451ecc4d72a0c1a2507a9a37fffe3e0b1c"
      "fa1a12c87a92793fc1a054cebbe3ff4e6746d9cc00:"
      "999c3480363c69eaa3de50523ef085998b17321dca8f31187b5e14d2f37dc10a");
  rewind(fp);
  otrng_assert_is_error(otrng_client_import_v4_identity(client, fp));
  fclose(fp);

  otrng_ec_point_destroy(*client->forging_key);
  otrng_free(client->forging_key);
  client->forging_key = NULL;
  otrng_secure_free(forging_key);
  otrng_secure_free(forging_key_compare);
  otrng_client_free(client);
}

void units_persistence_add_tests(void) {
  g_test_add_func("/persistence/v4/export", test_persistence_export_v4);
  g_test_add_func("/persistence/v4/export_failure1",
                  test_persistence_export_v4_failure1);
  g_test_add_func("/persistence/v4/export_failure2",
                  test_persistence_export_v4_failure2);
  g_test_add_func("/persistence/v4/export_failure3",
                  test_persistence_export_v4_failure3);
  g_test_add_func("/persistence/v4/import", test_persistence_import_v4);
  g_test_add_func("/persistence/v4/import_failures",
                  test_persistence_import_v4_failures);
}
