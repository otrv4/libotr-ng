#include <glib.h>
#include <stdio.h>
#include "otr_assert.h"

static const char OTR_CONTAINS_ERROR_SIZE[] = "Loop broke reading element %i when the expexted number of elements was %i, value in actual was %i and value in expected was %i. ";
static const char OTR_CONTAINS_ERROR_FOUND[] = "Element %i is not contained in the expected array. ";

void
otr_assert_contains(const int actual[], const int expected[], const int elements) {
  for (int i = 0; i < elements; i++) {
    if (actual[i] == '\0' || expected[i] == '\0') {
      g_test_fail();
      fprintf(stderr, OTR_CONTAINS_ERROR_SIZE, i, elements, actual[i], expected[i]);
      break;
    }

    int found = 0;
    for (int j = i; j < elements; j++) {
      found = 0;
      if (actual[i] == expected[j]) {
        found = 1;
        break;
      }
    }
    if (!found) {
      g_test_fail();
      fprintf(stderr, OTR_CONTAINS_ERROR_FOUND, actual[1]);
      break;
    }
  }
}
