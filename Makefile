# Makefile for AWS SigV4 C implementation

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -fPIC $(shell pkg-config --cflags libssl)
LIB_NAME = libsigv4.so
LIB_SRC = sigv4.c
LIB_HDR = sigv4.h
EXAMPLE_SRC = example.c
EXAMPLE_BIN = example
TEST_SRC = test.c
TEST_BIN = test
OPENSSL_LIBS = $(shell pkg-config --libs libssl,libcrypto)
CHECK_LIBS = $(shell pkg-config --libs check)

all: $(LIB_NAME) $(EXAMPLE_BIN)

$(LIB_NAME): $(LIB_SRC) $(LIB_HDR)
	$(CC) $(CFLAGS) -shared -o $@ $(LIB_SRC) $(OPENSSL_LIBS)

$(EXAMPLE_BIN): $(EXAMPLE_SRC) $(LIB_NAME)
	$(CC) -Wall -Wextra -std=c99 $(shell pkg-config --cflags libssl) -o $@ $(EXAMPLE_SRC) -L. -lsigv4 $(OPENSSL_LIBS)

$(TEST_BIN): $(TEST_SRC) $(LIB_NAME)
	$(CC) -Wall -Wextra -std=c99 $(shell pkg-config --cflags libssl,check) -o $@ $(TEST_SRC) -L. -lsigv4 $(OPENSSL_LIBS) $(CHECK_LIBS)

clean:
	rm -f $(LIB_NAME) $(EXAMPLE_BIN) $(TEST_BIN) *.o