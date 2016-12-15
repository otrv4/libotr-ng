#Library
P = libotr

#Paths
SRC = src
SRC_TEST = $(SRC)/test

#Target objects
OBJECTS = $(SRC)/otr.o
TEST_OBJECTS = $(SRC_TEST)/test_otr.o

#Compilation and linkage flags
CFLAGS = -g -Wall `pkg-config --cflags glib-2.0`
LDLIBS = `pkg-config --libs glib-2.0`
CC = c99

#Executables
TESTS = $(SRC_TEST)/test_$(P)

#Targets
default: $(P) test

ci: $(P) test mem-check

$(P): $(OBJECTS)

test: $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -o $(TESTS) $(OBJECTS) $(TEST_OBJECTS) $(LDLIBS)
	./$(TESTS)

mem-check:
	valgrind --leak-check=full ./$(TESTS)

clean:
	$(RM) $(OBJECTS) $(TEST_OBJECTS) $(TESTS)

