
void test_instance_tag_generates_tag_when_file_empty() {

  char *account = "alice@coy.im";
  char *protocol = "XMPP";

  FILE *tmpFILEp;
  tmpFILEp = tmpfile();

  otrv4_instag_t *instag = malloc(sizeof(otrv4_instag_t));
  int err = otrv4_instag_get(instag, account, protocol, tmpFILEp);

  fclose(tmpFILEp);

  g_assert_cmpint(err, ==, 0);
  g_assert_cmpint(instag->value, !=, 0);
  g_assert_cmpint(instag->value, >, 0x100);

  g_assert_cmpstr(instag->account, ==, account);
  g_assert_cmpstr(instag->protocol, ==, protocol);

  otr4_instag_free(instag);
}

void test_instance_tag_generates_tag_when_file_is_full() {

  char *account = "alice_irc";
  char *protocol = "XMPP";

  FILE *tmpFILEp;
  tmpFILEp = tmpfile();

  otrv4_instag_t *instag = malloc(sizeof(otrv4_instag_t));
  int err = otrv4_instag_get(instag, account, protocol, tmpFILEp);

  fclose(tmpFILEp);

  g_assert_cmpint(err, ==, 0);

  g_assert_cmpstr(instag->account, ==, account);
  g_assert_cmpstr(instag->protocol, ==, protocol);

  g_assert_cmpint(instag->value, !=, 0);
  g_assert_cmpint(instag->value, >, 0x100);

  otr4_instag_free(instag);
}
