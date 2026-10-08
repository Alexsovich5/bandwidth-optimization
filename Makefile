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

test: fixtures unit integration memcheck asan

VALGRIND = valgrind --error-exitcode=1 --leak-check=full --suppressions=tests/valgrind.supp

# The unit suites (including the packet-path fuzz suite) and the commands
# that read untrusted capture files, under valgrind memcheck.
memcheck: fixtures $(TEST_RUNNER) $(TARGET)
	CK_FORK=no $(VALGRIND) ./$(TEST_RUNNER)
	@set -e; for f in $(FIXTURE_DIR)/*.pcap; do \
		echo "== memcheck classify $$f"; \
		$(VALGRIND) -q ./$(TARGET) classify -r $$f > /dev/null; \
		$(VALGRIND) -q ./$(TARGET) mark -r $$f -w /tmp/bwopt_memcheck.pcap > /dev/null; \
	done
	rm -f /tmp/bwopt_memcheck.db /tmp/bwopt_memcheck.pcap
	$(VALGRIND) -q ./$(TARGET) monitor -r $(FIXTURE_DIR)/mixed.pcap --interval 1 \
		--db /tmp/bwopt_memcheck.db > /dev/null
	$(VALGRIND) -q ./$(TARGET) report --db /tmp/bwopt_memcheck.db > /dev/null
	rm -f /tmp/bwopt_memcheck.db

# The same under AddressSanitizer. GCC 4.7 has no ASan, so the image carries
# GCC 4.8.1 with its own glibc in the $(ASAN_ROOT) sysroot (see Dockerfile):
# sources are compiled inside it with chroot, and the binaries run from
# /src through the sysroot's dynamic loader and libraries.
ASAN_ROOT   = /opt/asan
ASAN_BUILD  = $(ASAN_ROOT)/build
ASAN_CFLAGS = -Wall -Wextra -O1 -g -std=c99 -D_BSD_SOURCE \
              -fsanitize=address -fno-omit-frame-pointer
ASAN_LDLIBS = -lcheck_pic -lpcap -lsqlite3 -lpthread -lrt -lm
ASAN_RUN    = ASAN_OPTIONS=abort_on_error=0:exitcode=1:detect_leaks=0 \
              $(ASAN_ROOT)/lib/x86_64-linux-gnu/ld-2.17.so \
              --library-path $(ASAN_ROOT)/lib/x86_64-linux-gnu:$(ASAN_ROOT)/usr/lib/x86_64-linux-gnu

asan: fixtures
	rm -rf $(ASAN_BUILD)
	mkdir -p $(ASAN_BUILD)
	cp -R src tests $(ASAN_BUILD)/
	chroot $(ASAN_ROOT) gcc-4.8 $(ASAN_CFLAGS) -o /build/run_tests \
		$(addprefix /build/,$(LIB_SRCS) $(TEST_SRCS)) $(ASAN_LDLIBS)
	chroot $(ASAN_ROOT) gcc-4.8 $(ASAN_CFLAGS) -o /build/bwopt \
		$(addprefix /build/,$(wildcard $(SRCDIR)/*.c)) $(ASAN_LDLIBS)
	CK_FORK=no $(ASAN_RUN) $(ASAN_BUILD)/run_tests
	@set -e; for f in $(FIXTURE_DIR)/*.pcap; do \
		echo "== asan classify $$f"; \
		$(ASAN_RUN) $(ASAN_BUILD)/bwopt classify -r $$f > /dev/null; \
		$(ASAN_RUN) $(ASAN_BUILD)/bwopt mark -r $$f -w /tmp/bwopt_asan.pcap > /dev/null; \
	done
	rm -f /tmp/bwopt_asan.db /tmp/bwopt_asan.pcap
	$(ASAN_RUN) $(ASAN_BUILD)/bwopt monitor -r $(FIXTURE_DIR)/mixed.pcap --interval 1 \
		--db /tmp/bwopt_asan.db > /dev/null
	$(ASAN_RUN) $(ASAN_BUILD)/bwopt report --db /tmp/bwopt_asan.db > /dev/null
	rm -f /tmp/bwopt_asan.db

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	install -d $(DESTDIR)/etc/bwopt
	install -m 0644 config/policies.conf $(DESTDIR)/etc/bwopt/policies.conf

clean:
	rm -f $(SRCDIR)/*.o $(LIB) $(TARGET) $(TEST_RUNNER) $(GEN_PCAP)
	rm -rf $(FIXTURE_DIR)

.PHONY: all fixtures unit integration test memcheck asan install clean
