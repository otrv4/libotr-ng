
void test_instance_tag_generates_tag_when_file_empty() {

  char *alice_coy_account = "alice@coy.im";
  char *xmpp_protocol = "XMPP";

  FILE *tmpFILEp;
  tmpFILEp = tmpfile();

  otrv4_instag_t *instag = malloc(sizeof(otrv4_instag_t));
  int err = otrv4_instag_get(instag, alice_coy_account, xmpp_protocol, tmpFILEp);

  fclose(tmpFILEp);

  g_assert_cmpint(err, ==, 0);
  g_assert_cmpint(instag->value, !=, 0);
  g_assert_cmpint(instag->value, >, 0x100);

  g_assert_cmpstr(instag->account, ==, alice_coy_account);
  g_assert_cmpstr(instag->protocol, ==, xmpp_protocol);

  otr4_instag_free(instag);
}

void test_instance_tag_generates_tag_when_file_is_full() {

  char *irc_alice_account = "alice_irc";
  char *irc_protocol = "IRC";
  char *xmpp_alice_account = "alice_xmpp";
  char *xmpp_protocol = "XMPP";

  FILE *tmpFILEp;
  tmpFILEp = tmpfile();

  otrv4_instag_t *first_instag = malloc(sizeof(otrv4_instag_t));
  int err = otrv4_instag_get(first_instag, irc_alice_account, irc_protocol,
                             tmpFILEp);
  g_assert_cmpint(err, ==, 0);

  otrv4_instag_t *second_instag = malloc(sizeof(otrv4_instag_t));
  err = otrv4_instag_get(second_instag, xmpp_alice_account, xmpp_protocol,
                         tmpFILEp);

  g_assert_cmpint(err, ==, 0);

  fclose(tmpFILEp);

  g_assert_cmpstr(first_instag->account, ==, irc_alice_account);
  g_assert_cmpstr(first_instag->protocol, ==, irc_protocol);
  g_assert_cmpint(first_instag->value, !=, 0);
  g_assert_cmpint(first_instag->value, >, 0x100);

  g_assert_cmpstr(second_instag->account, ==, xmpp_alice_account);
  g_assert_cmpstr(second_instag->protocol, ==, xmpp_protocol);
  g_assert_cmpint(second_instag->value, !=, 0);
  g_assert_cmpint(second_instag->value, >, 0x100);

  otr4_instag_free(first_instag);
  otr4_instag_free(second_instag);
}
