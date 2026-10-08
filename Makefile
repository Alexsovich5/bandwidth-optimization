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

GEN_PCAP     = tests/gen_pcap
FIXTURE_DIR  = tests/fixtures/out
FIXTURES     = $(FIXTURE_DIR)/.stamp

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

$(GEN_PCAP): tests/gen_pcap.c
	$(CC) $(CFLAGS) -o $@ $< -lpcap

$(FIXTURES): $(GEN_PCAP)
	mkdir -p $(FIXTURE_DIR)
	./$(GEN_PCAP) $(FIXTURE_DIR)
	touch $@

fixtures: $(FIXTURES)

unit: $(TEST_RUNNER)
	./$(TEST_RUNNER)

integration: $(TARGET)
	@set -e; for t in $(INTEGRATION); do \
		echo "== $$t"; \
		bash -e $$t; \
	done

test: fixtures unit integration

VALGRIND = valgrind --error-exitcode=1 --leak-check=full --suppressions=tests/valgrind.supp

memcheck: fixtures $(TEST_RUNNER) $(TARGET)
	CK_FORK=no $(VALGRIND) ./$(TEST_RUNNER)
	$(VALGRIND) ./$(TARGET) classify -r $(FIXTURE_DIR)/mixed.pcap > /dev/null

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	install -d $(DESTDIR)/etc/bandwidth_optimizer
	install -m 0644 config/policies.conf $(DESTDIR)/etc/bandwidth_optimizer/policies.conf

clean:
	rm -f $(SRCDIR)/*.o $(LIB) $(TARGET) $(TEST_RUNNER) $(GEN_PCAP)
	rm -rf $(FIXTURE_DIR)

.PHONY: all fixtures unit integration test memcheck install clean
