void
otr_string_cpy(char *target, const char *source, const int start, const int size) {
  int char_at = 0;
  for (int i = start; i < start + size; i ++) {
    target[char_at] = source[i];
    char_at++;
  }
  target[char_at] = '\0';
}
