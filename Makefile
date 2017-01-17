#Library
P = libotrv4

#Paths
SRC = src
SRC_TEST = $(SRC)/test

#Target objects
OBJECTS = $(SRC)/otrv4.o $(SRC)/dake.o $(SRC)/otrv3.o $(SRC)/str.o $(SRC)/user_profile.o $(SRC)/data_types.o $(SRC)/serialize.o
TEST_OBJECTS_OTRV4 = $(SRC_TEST)/test_otrv4.o
TEST_OBJECTS_DAKE = $(SRC_TEST)/test_dake.o
TEST_OBJECTS_USER_PROFILE = $(SRC_TEST)/test_user_profile.o

#Compilation and linkage flags
CFLAGS = -std=c99 -g -Wall `pkg-config --cflags glib-2.0`
LDLIBS = `pkg-config --libs glib-2.0`
CC = gcc

#Executables
TESTS_OTRV4 = $(SRC_TEST)/test_$(P)
TESTS_DAKE = $(SRC_TEST)/test_dake
TESTS_USER_PROFILE = $(SRC_TEST)/test_user_profile

#Targets
default: $(P) test

ci: $(P) test mem-check

$(P): $(OBJECTS)

test: test-otrv4 test-dake test-user-profile

test-otrv4: $(TEST_OBJECTS_OTRV4)
	$(CC) $(CFLAGS) -o $(TESTS_OTRV4) $(OBJECTS) $(TEST_OBJECTS_OTRV4) $(LDLIBS)
	./$(TESTS_OTRV4)

test-dake: $(TEST_OBJECTS_DAKE)
	$(CC) $(CFLAGS) -o $(TESTS_DAKE) $(OBJECTS) $(TEST_OBJECTS_DAKE) $(LDLIBS)
	./$(TESTS_DAKE)

test-user-profile: $(TEST_OBJECTS_USER_PROFILE)
	$(CC) $(CFLAGS) -o $(TESTS_USER_PROFILE) $(OBJECTS) $(TEST_OBJECTS_USER_PROFILE) $(LDLIBS)
	./$(TESTS_USER_PROFILE)

code-check:
	splint +trytorecover src/*.h src/**.c `pkg-config --cflags glib-2.0`

mem-check: default
	valgrind --leak-check=full ./$(TESTS_OTRV4)
	valgrind --leak-check=full ./$(TESTS_DAKE)
	valgrind --leak-check=full ./$(TESTS_USER_PROFILE)

clean:
	$(RM) $(OBJECTS)
	$(RM) $(TEST_OBJECTS_OTRV4) $(TESTS_OTRV4)
	$(RM) $(TEST_OBJECTS_DAKE) $(TESTS_DAKE)
	$(RM) $(TEST_OBJECTS_USER_PROFILE) $(TESTS_USER_PROFILE)

