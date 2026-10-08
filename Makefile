CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c99 -D_BSD_SOURCE
LDLIBS  = -lpcap -lsqlite3 -lpthread
AR      = ar
PREFIX  = /usr/local
DESTDIR =

CHECK_CFLAGS := $(shell pkg-config --cflags check)
CHECK_LIBS   := $(shell pkg-config --libs check)

SRCDIR   = src
LIB_SRCS = $(filter-out $(SRCDIR)/main.c,$(wildcard $(SRCDIR)/*.c))
LIB_OBJS = $(LIB_SRCS:.c=.o)
LIB      = libbwopt.a
TARGET   = bwopt

TEST_SRCS   = $(wildcard tests/test_*.c) tests/run_tests.c
TEST_RUNNER = tests/run_tests
INTEGRATION = $(wildcard tests/integration/test_*.sh)

all: $(TARGET)

$(LIB): $(LIB_OBJS)
	rm -f $@
	$(AR) rcs $@ $(LIB_OBJS)

$(TARGET): $(SRCDIR)/main.o $(LIB)
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/main.o $(LIB) $(LDLIBS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c $(wildcard $(SRCDIR)/*.h)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_RUNNER): $(TEST_SRCS) $(wildcard tests/*.h) $(LIB)
	$(CC) $(CFLAGS) $(CHECK_CFLAGS) -o $@ $(TEST_SRCS) $(LIB) $(CHECK_LIBS) $(LDLIBS)

unit: $(TEST_RUNNER)
	./$(TEST_RUNNER)

integration: $(TARGET)
	@set -e; for t in $(INTEGRATION); do \
		echo "== $$t"; \
		bash -e $$t; \
	done

test: unit integration

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	install -d $(DESTDIR)/etc/bandwidth_optimizer
	install -m 0644 config/policies.conf $(DESTDIR)/etc/bandwidth_optimizer/policies.conf

clean:
	rm -f $(SRCDIR)/*.o $(LIB) $(TARGET) $(TEST_RUNNER)

.PHONY: all unit integration test install clean
