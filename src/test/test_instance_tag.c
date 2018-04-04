#include <string.h>

#include "../instance_tag.h"

void test_instance_tag_generates_tag_when_file_empty() {

  char *alice_coy_account = "alice@coy.im";
  char *xmpp_protocol = "XMPP";

  FILE *tmpFILEp;
  tmpFILEp = tmpfile();

  otrng_instag_t *instag = malloc(sizeof(otrng_instag_t));
  otrng_bool_t err =
      otrng_instag_get(instag, alice_coy_account, xmpp_protocol, tmpFILEp);

  fclose(tmpFILEp);

  g_assert_cmpint(err, ==, 0);
  g_assert_cmpint(instag->value, !=, 0);
  g_assert_cmpint(instag->value, >, 0x100);

  g_assert_cmpstr(instag->account, ==, alice_coy_account);
  g_assert_cmpstr(instag->protocol, ==, xmpp_protocol);

  otrng_instag_free(instag);
}

void test_instance_tag_generates_tag_when_file_is_full() {

  char *icq_alice_account = "alice_icq";
  char *icq_protocol = "ICQ";
  char *xmpp_alice_account = "alice_xmpp";
  char *xmpp_protocol = "XMPP";
  char *irc_alice_account = "alice_irc";
  char *irc_protocol = "IRC";
  unsigned int icq_instag_value = 0x9abcdef0;

  int err;
  FILE *tmpFILEp;
  tmpFILEp = tmpfile();

  fprintf(tmpFILEp, "%s\t%s\t%08x\n", icq_alice_account, icq_protocol,
          icq_instag_value);

  rewind(tmpFILEp);

  otrng_instag_t *first_instag = malloc(sizeof(otrng_instag_t));
  err =
      otrng_instag_get(first_instag, icq_alice_account, icq_protocol, tmpFILEp);
  g_assert_cmpint(err, ==, 0);

  otrng_instag_t *second_instag = malloc(sizeof(otrng_instag_t));
  err = otrng_instag_get(second_instag, xmpp_alice_account, xmpp_protocol,
                         tmpFILEp);
  g_assert_cmpint(err, ==, 0);

  otrng_instag_t *third_instag = malloc(sizeof(otrng_instag_t));
  err =
      otrng_instag_get(third_instag, irc_alice_account, irc_protocol, tmpFILEp);
  g_assert_cmpint(err, ==, 0);

  fclose(tmpFILEp);

  char sone[9];
  snprintf(sone, sizeof(sone), "%08x", first_instag->value);

  g_assert_cmpstr(first_instag->account, ==, icq_alice_account);
  g_assert_cmpstr(first_instag->protocol, ==, icq_protocol);
  g_assert_cmpint(first_instag->value, !=, 0);
  g_assert_cmpint(first_instag->value, >, 0x100);
  g_assert_cmpstr(sone, ==, "9abcdef0");

  g_assert_cmpstr(second_instag->account, ==, xmpp_alice_account);
  g_assert_cmpstr(second_instag->protocol, ==, xmpp_protocol);
  g_assert_cmpint(second_instag->value, !=, 0);
  g_assert_cmpint(second_instag->value, >, 0x100);

  g_assert_cmpstr(third_instag->account, ==, irc_alice_account);
  g_assert_cmpstr(third_instag->protocol, ==, irc_protocol);
  g_assert_cmpint(third_instag->value, !=, 0);
  g_assert_cmpint(third_instag->value, >, 0x100);

  otrng_instag_free(first_instag);
  otrng_instag_free(second_instag);
  otrng_instag_free(third_instag);
}
