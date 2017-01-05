#Library
P = libotrv4

#Paths
SRC = src
SRC_TEST = $(SRC)/test

#Target objects
OBJECTS = $(SRC)/otr.o $(SRC)/dake.o $(SRC)/mem.o $(SRC)/otrv3.o $(SRC)/str.o
TEST_OBJECTS = $(SRC_TEST)/test_otr.o

#Compilation and linkage flags
CFLAGS = -std=c99 -g -Wall `pkg-config --cflags glib-2.0`
LDLIBS = `pkg-config --libs glib-2.0`
CC = gcc

#Executables
TESTS = $(SRC_TEST)/test_$(P)

#Targets
default: $(P) test

ci: $(P) test mem-check

$(P): $(OBJECTS)

test: $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -o $(TESTS) $(OBJECTS) $(TEST_OBJECTS) $(LDLIBS)
	./$(TESTS)

code-check:
	splint +trytorecover src/*.h src/**.c `pkg-config --cflags glib-2.0`

mem-check:
	valgrind --leak-check=full ./$(TESTS)

clean:
	$(RM) $(OBJECTS) $(TEST_OBJECTS) $(TESTS)

