# Bandwidth Optimization Engine: Implementation Plan

Each task below is one commit, in order. Every task must leave
`docker compose run --rm bwopt make test` green. See `docs/SPEC.md` for formats, schemas, and
pinned versions.

Common conventions:
- Everything lives in the `bwopt` compose service (image built from `debian:wheezy`, repo
  mounted at `/src`, `cap_add: [NET_ADMIN]`).
- `make test` = `make unit` (Check runner) + `make integration` (every
  `tests/integration/test_*.sh`, run with `bash -e`; wheezy's `/bin/sh` is dash, which has no
  `/dev/udp`).
- From T6 on, every task's acceptance is
  `docker compose run --rm bwopt sh -c 'make test && make memcheck'`.
- Check 0.9.8 API only: `ck_assert`, `ck_assert_msg`, `ck_assert_int_*`, `ck_assert_str_*`.
  There are no unsigned or 64-bit asserts, and `ck_assert_int_*` formats with `%d`, so
  `uint64_t` values are compared with `ASSERT_U64_EQ(a, b)` from `tests/test_util.h`
  (`ck_assert_msg((a) == (b), "%" PRIu64 " != %" PRIu64, …)`). The `.pc` file links
  `-lcheck_pic`; always take flags from `pkg-config`.
- Each new module `src/X.c` has `src/X.h` and a Check suite `tests/test_X.c`. The suite is
  registered in `tests/run_tests.c`.
- Write the tests first. Each task lists the tests that must exist, and fail, before the
  implementation.

---

## T1: Scaffold Docker image, Makefile and Check test harness

- **Goal**: Get a reproducible period build environment where `make test` runs from the very
  first commit, and make the existing `src/main.c` compile.
- **Files**:
  - create `Dockerfile`:
    - `FROM debian:wheezy`
    - `/etc/apt/sources.list` replaced with
      `deb http://archive.debian.org/debian wheezy main` and
      `deb http://archive.debian.org/debian-security wheezy/updates main` (the security line is
      required: the image's `libc6` is `2.13-38+deb7u12`, and `libc6-dev` must match it
      exactly), with `Check-Valid-Until=false`
    - pinned packages: `build-essential=11.5 gcc-4.7=4.7.2-5 make=3.81-8.2
      libc6-dev=2.13-38+deb7u12 libc-dev-bin=2.13-38+deb7u12 libc6-dbg=2.13-38+deb7u12
      libpcap0.8-dev=1.3.0-1 libsqlite3-0=3.7.13-1+deb7u2 libsqlite3-dev=3.7.13-1+deb7u2
      sqlite3=3.7.13-1+deb7u2 check=0.9.8-2 iproute=20120521-3+b3 iptables=1.4.14-3.1
      pkg-config=0.26-1 valgrind=1:3.7.0-6 git=1:1.7.10.4-1+wheezy3
      git-man=1:1.7.10.4-1+wheezy3`
    - the same `RUN` then runs `gcc --version && valgrind --version && iptables -V && git
      --version` as a build-time smoke check
    - `WORKDIR /src`
  - create `docker-compose.yml`: top-level `name: bandwidth-optimization`; service `bwopt`
    builds `.` as image `bandwidth-optimization:dev`, mounts the repo at `/src`, sets
    `cap_add: [NET_ADMIN]`, and uses `command: make test`; the default network is pinned to
    subnet `172.43.0.0/24` (no host ports are published)
  - create `.gitignore`: `*.o`, `*.a`, `bwopt`, `tests/run_tests`, `tests/gen_pcap`,
    `tests/fixtures/out/`, `*.db`
  - create `src/version.h`: `#define BWOPT_VERSION "0.1.0"`
  - create `tests/run_tests.c`: Check `SRunner` that aggregates suites
  - create `tests/test_version.c`
  - create `tests/integration/test_cli.sh`
  - create `tests/integration/test_env.sh`
  - create `tests/test_util.h` (`ASSERT_U64_EQ`)
  - modify `Makefile`:
    - `CFLAGS=-Wall -Wextra -O2 -std=c99 -D_BSD_SOURCE`
    - build `libbwopt.a` from every `src/*.c` except `main.c`, then link `bwopt`
    - targets `unit`, `integration`, `test`, `clean`, `install` with `PREFIX`/`DESTDIR`
    - Check flags via `pkg-config --cflags --libs check`
  - modify `src/main.c`:
    - remove the includes and calls for the four headers that don't exist
    - keep the signal handler and the argument loop
    - add `--version` and `--help`
    - no subcommand prints usage and exits with 2
- **Tests first**:
  - `test_version.c`: `BWOPT_VERSION` is a non-empty semver string
  - `test_cli.sh`: `./bwopt --version` prints `bwopt 0.1.0` and exits 0, and `./bwopt` with
    no arguments exits 2
  - `test_env.sh`: `valgrind --error-exitcode=1 /bin/true` exits 0, and
    `iptables -t mangle -N BWTEST && iptables -t mangle -A BWTEST -j DSCP --set-dscp 46`
    succeeds (the chain is flushed and deleted on exit)
- **Acceptance**: `docker compose build bwopt` (runs the exact pinned apt line and the version
  smoke check) `&& docker compose run --rm bwopt make test`
- **Commit message**:
  ```
  Add wheezy build image, Makefile targets and Check test harness

  Builds bwopt and libbwopt.a with pinned wheezy toolchain packages and
  runs Check unit tests plus shell integration tests via make test.
  ```

## T2: Parse and validate the policy configuration

- **Goal**: Implement `bw_config_load()` for the existing `config/policies.conf` format,
  including the optional `[autotune]` section with its defaults, and add
  `bwopt check-config`.
- **Files**:
  - create `src/config.c`, `src/config.h`, `tests/test_config.c`
  - create `tests/fixtures/conf/` with one `.conf` per error case: `bad_dscp.conf`,
    `over_100.conf`, `unknown_class.conf`, `unknown_key.conf`, `bad_range.conf`,
    `no_default.conf`, `dup_dscp.conf` (two classes with DSCP 34), `dscp0_nondefault.conf`
    (a non-default class with DSCP 0)
  - modify `src/main.c` to add the `check-config` subcommand, with `-c`/`--config` as
    equivalent forms
  - modify `tests/run_tests.c` and `tests/integration/test_cli.sh`
- **Tests first**:
  - the shipped config parses to 4 classes and 8 apps, `total_bps`=100000000, default
    `best_effort`, rate for `high_priority` = 30000000, `rtp` range 10000–20000, and the
    `[autotune]` defaults applied
  - inline `#` comments and whitespace are ignored
  - `32k`/`1m` bursts are accepted and `32x` is rejected
  - each error fixture fails with a message that contains the line number
  - `--config FILE` behaves like `-c FILE`
  - `test_cli.sh`: `bwopt check-config -c config/policies.conf` exits 0 and prints the
    class table, and `-c tests/fixtures/conf/bad_dscp.conf` exits 2
- **Acceptance**: `docker compose run --rm bwopt make test`
- **Commit message**:
  ```
  Parse and validate policies.conf with check-config command

  Supports global, classes, applications, monitoring and autotune
  sections, with line-numbered errors for invalid values.
  ```

## T3: Decode link, IPv4 and transport headers from raw frames

- **Goal**: `bw_packet_decode()` for DLT_EN10MB (with 802.1Q) and DLT_LINUX_SLL, IPv4 with
  IHL/options, fragment offset handling (ports only on the first fragment), TCP/UDP
  ports, and the payload pointer.
- **Files**: create `src/packet.c`, `src/packet.h`, `tests/test_packet.c`, and
  `tests/frames.h` (static byte arrays). Modify `tests/run_tests.c`.
- **Tests first**:
  - Ethernet+IPv4+UDP 5060 decodes the ports, proto 17, and DSCP 0
  - the VLAN-tagged variant decodes the same
  - SLL frame
  - IPv4 with a 4-byte option: the payload offset is correct
  - a non-first fragment has no ports
  - truncated IP and TCP headers return -1
  - ARP and IPv6 give `ethertype` set and `ip_proto` = 0
  - TCP data offset of 8 words gives the right payload offset
- **Acceptance**: `docker compose run --rm bwopt make test`
- **Commit message**:
  ```
  Add packet decoder for Ethernet, VLAN, SLL, IPv4, TCP and UDP

  Bounds-checked decoding into struct bw_packet, exercised with
  hand-built frames including truncated and fragmented cases.
  ```

## T4: Classify packets by port rules and payload signatures

- **Goal**: `bw_signature_match()` (HTTP methods, a SIP request or `SIP/2.0` status line, a TLS
  record header `0x16 0x03 0x0[0-3]`) and `bw_classify()`. The order is: non-IPv4 returns `-1`
  (unclassified), then signature app, then port or port range (either direction), then
  `default_class`. Signatures are userspace-only (see SPEC feature 3).
- **Files**:
  - create `src/signatures.c`, `src/signatures.h`, `src/classifier.c`, `src/classifier.h`,
    `tests/test_signatures.c`, `tests/test_classifier.c`
  - create `tests/fixtures/conf/signatures.conf` (shipped config plus `http.signature=http`,
    `sip.signature=sip`, `https.signature=tls`)
  - modify `tests/run_tests.c`
- **Tests first**:
  - signature positives and negatives (`GET /`, `POST `, `INVITE sip:`, `SIP/2.0 200`, the TLS
    ClientHello header, random bytes, payloads that are too short)
  - UDP dport 5060 goes to high_priority, and sport 5060 (the reply) also goes to high_priority
  - UDP 15000 falls inside the RTP range and goes to high_priority
  - TCP 22 goes to medium_priority
  - TCP 8080 carrying `GET /` with the signatures config goes to low_priority
  - TCP 9999 with no signature goes to best_effort
  - a non-IPv4 packet (ARP, IPv6) returns -1 (unclassified), not best_effort
- **Acceptance**: `docker compose run --rm bwopt make test`
- **Commit message**:
  ```
  Classify traffic by port rules and lightweight payload signatures

  Signature matches (HTTP, SIP, TLS) take precedence over port and
  port-range rules; unmatched traffic falls back to the default class.
  ```

## T5: Generate pcap fixtures and classify capture files via libpcap

- **Goal**:
  - `tests/gen_pcap.c` writes deterministic fixtures with `pcap_open_dead`/`pcap_dump`
  - `src/capture.c` wraps `pcap_open_offline`/`pcap_open_live` plus a callback loop
  - `bwopt classify -r FILE [--summary]`
- **Files**:
  - create `src/capture.c`, `src/capture.h`, `tests/gen_pcap.c`
  - create `tests/integration/test_classify.sh`, `tests/expected/mixed.summary`
  - modify `Makefile` (build `gen_pcap`; `fixtures` target writes `tests/fixtures/out/*.pcap`,
    and `test` depends on it)
  - modify `src/main.c`
- **Tests first**:
  - `test_classify.sh`: `bwopt classify -r tests/fixtures/out/mixed.pcap --summary` matches
    `tests/expected/mixed.summary` exactly (per class: packets and bytes, plus
    `unclassified`, in the format defined in the SPEC CLI section)
  - running without `--summary`, line count = packet count, and each line matches the SPEC
    per-packet format (including `dscp=`); non-IP frames print `class=unclassified`
  - `vlan.pcap` gives the same classes as the untagged equivalent
  - a missing file exits 1 with the pcap error message
- **Acceptance**: `docker compose run --rm bwopt make test`
- **Commit message**:
  ```
  Add libpcap capture wrapper and classify command for pcap files

  A fixture generator writes deterministic mixed, VLAN and non-IP
  captures at test time so no binary files are committed.
  ```

## T6: Add valgrind memcheck target

- **Goal**: `make memcheck` runs `tests/run_tests` with `CK_FORK=no` and
  `bwopt classify -r tests/fixtures/out/mixed.pcap` under valgrind 3.7
  (`--error-exitcode=1 --leak-check=full`), and any leaks found in the modules so far are
  fixed. Doing this now means leaks in the decoder, classifier and capture code are caught
  before more code depends on them.
- **Files**: modify `Makefile` (target `memcheck`, depends on `fixtures`) and `src/*.c` (only
  for leak fixes); create `tests/valgrind.supp`, passed with `--suppressions`. It holds a single
  entry for a leak inside libpcap 1.3.0 itself: `pcap_open_offline` on a rejected file (bad
  magic) loses a `strdup`'d string and returns NULL, so the caller has nothing to free. Leaks in
  this project's code are never suppressed.
- **Tests first**: `make memcheck` is run before any fix and must exit 0 after the fixes.
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Add valgrind memcheck target for unit tests and classify

  Runs the Check suites without forking and the classify command under
  memcheck with leak checking, failing on any reported error.
  ```

## T7: Mark DSCP with iptables rules, plus a pcap rewrite testing aid

- **Goal**:
  - `bw_dscp_script()`/`bw_dscp_clear_script()` emit the `BWOPT` mangle chain rules (tcp and
    udp, dport and sport, `a:b` ranges), from port rules only
  - `bw_dscp_rewrite()` sets the DSCP bits while keeping ECN, and recomputes the IPv4 header
    checksum
  - add `bwopt dscp-script` and the testing aid `bwopt mark -r IN -w OUT`
- **Files**:
  - create `src/dscp.c`, `src/dscp.h`, `tests/test_dscp.c`, `tests/golden/policies.iptables`,
    `tests/integration/test_mark.sh`
  - modify `src/main.c` and `tests/run_tests.c`
- **Tests first**:
  - the script for the shipped config equals the golden file
  - with `signatures.conf`, the script is identical to the shipped config's (signatures do not
    create iptables rules)
  - the clear script flushes, unhooks, and deletes the chain
  - rewriting DSCP 46 on a known header gives tos 0xb8 and a checksum that validates per
    RFC 1071
  - ECN bits are preserved
  - `test_mark.sh`: `mark` on `mixed.pcap`, then `classify` on the output shows the per-packet
    `dscp=` equal to the class DSCP. Non-IP packets are unchanged (`cmp` of the byte ranges).
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Add DSCP marking via iptables mangle rules and pcap rewrite

  Rules live in a dedicated BWOPT chain; the mark command rewrites
  DSCP in capture files and fixes the IPv4 header checksum so marking
  can be checked offline.
  ```

## T8: Generate the HTB shaping tree as a tc script

- **Goal**:
  - `bw_qos_script()` emits root HTB (`default` = default class minor), parent 1:1 at total,
    child classes 1:10.. with rate/ceil/burst/prio, SFQ leaves, and u32 `ip dsfield` filters
    for non-default classes
  - `bw_qos_clear_script()` emits `tc qdisc del dev IFACE root`
  - add `bwopt tc-script [-i|--interface IFACE]`
- **Files**: create `src/qos.c`, `src/qos.h`, `tests/test_qos.c`, `tests/golden/policies.tc`,
  `tests/integration/test_tc_script.sh` (CLI `-i`/`--interface` check), and the fixtures
  `tests/fixtures/conf/one_class.conf` and `tests/fixtures/conf/under_100.conf`.
  Modify `src/main.c` and `tests/run_tests.c`.
- **Tests first**:
  - the shipped config script equals `tests/golden/policies.tc` (matches the example in
    `SPEC.md`)
  - `-i bw0` and `--interface bw0` substitute the interface
  - shares that sum to less than 100% still set ceil = total
  - a 1-class config has no filters
  - the tos/mask for DSCP 34 is `0x88 0xfc`
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Generate HTB class tree and DSCP filters as a tc script

  Rates are derived from class shares of total_bandwidth, with SFQ
  leaves and u32 dsfield filters steering marked traffic.
  ```

## T9: Apply and clear the policy on a live interface

- **Goal**:
  - `src/exec.c`: `bw_exec_run(script, flags, dry_out)` runs generated scripts line by line
    through `/bin/sh -c`. In strict mode it stops at the first failure and reports the
    failing command. With `BW_EXEC_IGNORE_ERRORS` it runs every line, discards stderr, and
    returns 0. With `BW_EXEC_DRY_RUN` it prints the lines instead.
  - `bwopt apply` runs the tc and DSCP clear scripts with `BW_EXEC_IGNORE_ERRORS` (on a fresh
    interface there is no root qdisc and no BWOPT chain, so those commands fail), then the tc
    and DSCP scripts in strict mode. It can be run again safely.
  - `bwopt clear` runs the clear scripts in strict mode and reports errors
- **Files**:
  - create `src/exec.c`, `src/exec.h`, `tests/test_exec.c`
  - create `tests/integration/test_apply.sh` and `tests/integration/lib.sh`:
    - create and remove dummy `bw0` 10.99.0.1/24
    - best-effort `sysctl -w net.ipv6.conf.bw0.disable_ipv6=1 || true` to cut stray IPv6
      ND/MLD frames (`/proc/sys` may be read-only in the container)
    - a `send_udp PORT N` helper using bash `/dev/udp/10.99.0.2/PORT` (the scripts run under
      `bash -e`)
  - modify `src/main.c`
- **Tests first**:
  - `test_exec.c`:
    - dry-run writes the exact lines to a `FILE*`
    - strict mode: a failing command returns non-zero, and later lines don't run (a marker
      file is not created)
    - ignore-errors mode: a failing first line still lets the later line run (the marker file
      is created), and the call returns 0
  - `test_apply.sh`:
    - the first `apply -i bw0` on a freshly created bw0 (no root qdisc, no BWOPT chain) exits 0
    - `tc class show dev bw0` then lists 1:1, 1:10, 1:20, 1:30, and 1:40 with the expected
      rates, and `iptables -t mangle -S BWOPT` matches the golden rules
    - sending 5 packets each to 5060, 443, and 80 raises the packet counters of 1:10, 1:20,
      and 1:30 by exactly 5; 5 packets to 9999 raise the default class 1:40 by at least 5
      (stray non-IPv4 frames also land there)
    - running `apply` a second time succeeds
    - `clear` leaves no htb qdisc and no BWOPT chain, and a second `clear` exits non-zero
      with the failing command in the message
    - the script skips with a clear message only if `ip link add … type dummy` is not
      permitted
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Add apply and clear commands with dry-run support

  Apply clears previous state while ignoring errors, then runs the
  generated tc and iptables scripts, verified end to end on a dummy
  interface inside the container.
  ```

## T10: Count per-class traffic and compute interval rates

- **Goal**: `struct bw_monitor` with per-class (plus `unclassified`, for class index -1)
  packet and byte counters. `bw_monitor_flush(now)` produces samples with
  `bps = bytes*8 / elapsed`, then resets the counters. The first flush uses the start time.
- **Files**: create `src/monitor.c`, `src/monitor.h`, `tests/test_monitor.c`. Modify
  `tests/run_tests.c`.
- **Tests first** (64-bit values compared with `ASSERT_U64_EQ`):
  - 3 classes fed known byte counts over 10 s give the exact bps
  - class index -1 is counted as `unclassified`
  - zero-traffic classes still produce rows with 0
  - elapsed = 0 is guarded (no divide-by-zero, bps = 0)
  - counters reset after a flush
  - 64-bit counters do not overflow at 10 GB
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Add per-class traffic counters and interval rate calculation

  Monitor accumulates packets and bytes per class and flushes samples
  with bits per second for each update interval.
  ```

## T11: Persist samples and tuning events in SQLite

- **Goal**: `src/store.c`:
  - opens or creates the database with the schema in `SPEC.md` and `user_version` 1, inside a
    transaction
  - batches inserts of samples with prepared statements
  - inserts tuning events and reads the latest rate per class and interface
  - queries the average and peak bps per class over the last N samples or since a timestamp
- **Files**: create `src/store.c`, `src/store.h`, `tests/test_store.c`. Modify
  `tests/run_tests.c` and the `Makefile` (`-lsqlite3`).
- **Tests first** (64-bit values compared with `ASSERT_U64_EQ`):
  - opening a new temp file creates both tables and `user_version`=1
  - reopening does not fail
  - inserting 3 intervals × 5 classes and then querying gives the expected avg/peak
  - a duplicate `(ts, iface, class)` is rejected
  - the `tuning` insert and latest-rate read round-trip
  - opening `/nonexistent/dir/m.db` returns an error with the SQLite message (a missing
    directory fails even as root, unlike a permission-based check)
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Store per-class samples and tuning events in SQLite

  Creates a versioned schema and provides batched inserts plus
  average and peak rate queries used by report and autotune.
  ```

## T12: Run the offline monitor loop and report stored metrics

- **Goal**:
  - `bwopt monitor -r FILE [--db PATH] [--interval S]`: read the pcap, classify, count, and
    flush to SQLite every `--interval`/`update_interval` seconds using packet timestamps, not
    the wall clock, with a final flush at end of file
  - `--db` overrides `database`; a path that cannot be opened exits 1 with the error
  - `bwopt report --db PATH [--since] [--iface]` prints a per-class table
- **Files**:
  - modify `src/main.c` (subcommands) and `src/capture.c` (packet timestamps to the callback)
  - create `src/report.c`, `src/report.h`, `tests/test_report.c`,
    `tests/integration/test_monitor.sh`, `tests/expected/mixed.report`
- **Tests first**:
  - `test_report.c`: formatting a known result set gives the exact table text
  - `test_monitor.sh` (offline part):
    - `monitor -r mixed.pcap --interval 1 --db /tmp/m.db` gives rows whose per-class byte sum
      equals `tests/expected/mixed.summary`, including `unclassified`, and `report` matches
      `tests/expected/mixed.report`
    - `monitor -r mixed.pcap --db /nonexistent/dir/m.db` exits 1
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Add offline monitor loop with SQLite flushes and report command

  Replays a capture using packet timestamps, flushes per-class rates
  for each interval and summarises stored samples per class.
  ```

## T13: Add live capture with signals, duration and log file

- **Goal**: `bwopt monitor -i|--interface IFACE`:
  - live capture through `pcap_open_live` (snaplen 256, promisc off, timeout 100 ms), with
    wall-clock interval flushes
  - stop cleanly on SIGINT/SIGTERM or when `--duration` runs out (`pcap_breakloop`), with a
    final flush, reusing the existing `signal_handler`/`running` pattern in `src/main.c`
  - append log lines (start, each flush, stop) to `log_file`, overridable with `--log`
- **Files**: modify `src/main.c`, `src/capture.c` (breakloop) and
  `tests/integration/test_monitor.sh`.
- **Tests first** (`test_monitor.sh`, live part, using `lib.sh`):
  - with bw0 up, `monitor -i bw0 --interval 1 --duration 3 --db /tmp/l.db --log /tmp/l.log &`
    runs while `send_udp 5060 20`, after which `sqlite3` shows `high_priority` bytes > 0 and
    the log file has a start and a stop line
  - a `kill -TERM` during a live run still does the final flush (exit 0, rows present)
  - skipped with a clear message only if the dummy interface cannot be created
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Add live capture to monitor with signal handling and log file

  Captures from an interface until SIGINT, SIGTERM or the requested
  duration, always writing a final flush, and logs each interval.
  ```

## T14: Implement the auto-tuning re-balancing algorithm

- **Goal**: `bw_autotune()` as a pure function, implementing exactly the steps in SPEC
  "Auto-tuning algorithm": utilisation against the configured rate; donor target
  `min(C, max(floor, 1.2 × avg))`; pool split among receivers by configured share; drift back
  half-way to the configured rate (with snap) when there is no donor/receiver pair;
  hysteresis relative to the configured rate; then the Σ ≤ total clamp; rates rounded down to
  1000 bit/s.
- **Files**: create `src/autotune.c`, `src/autotune.h`, `tests/test_autotune.c`. Modify
  `tests/run_tests.c`.
- **Tests first** (shipped config: C = 30/40/20/10 Mbit, floor = 50%, `ASSERT_U64_EQ`):
  - all classes at 60% of configured, current = configured: no change
  - high_priority at 100% and best_effort at 0% (others 60%): best_effort → 5000000,
    high_priority → 35000000, return value 2
  - the same inputs with current rates already at 35000000/5000000: return value 0
    (idempotent)
  - high_priority and medium_priority saturated, best_effort idle: the 5 Mbit pool is split
    30:40, giving 32142000 and 42857000
  - no class goes below its floor
  - drift back: from current (35, 40, 20, 5) Mbit with all classes neutral, successive calls
    give high_priority 32.5 → 30 Mbit and best_effort 7.5 → 8.75 → 9.375 → 10 Mbit, then no
    further change
  - a target 3% of the configured rate away from the current rate is suppressed by hysteresis
  - a property loop over 1,000 pseudo-random inputs with a fixed seed never gets
    Σ > total or any rate < floor
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Add auto-tuning algorithm for HTB guaranteed rates

  Idle classes lend unused rate to saturated ones within floors and
  hysteresis, drift back to configured rates when load subsides, and
  never exceed the configured total bandwidth.
  ```

## T15: Wire auto-tuning into the CLI and the monitor loop

- **Goal**:
  - `bw_qos_change_line()` emits
    `tc class change dev IF parent 1:1 classid 1:N htb rate Rbit ceil Cbit burst B prio P`,
    with burst and prio from the config (without them, `tc class change` resets prio to 0 and
    burst to the default)
  - `bwopt autotune --db PATH [-i IFACE] [--apply]` reads the last `window` samples, runs
    `bw_autotune`, prints or executes the change lines, and records the changes in `tuning`
  - `monitor --autotune` does the same after each flush once `window` samples exist.
    `--dry-run` only logs.
  - current rates come from the db (the latest `tuning` row, or the configured rate)
- **Files**: modify `src/main.c`, `src/qos.c`, `src/qos.h`, and `tests/test_qos.c`. Create
  `tests/integration/test_autotune.sh`.
- **Tests first**:
  - `test_qos.c`: the change line for class 1:40 at 5 Mbit equals the SPEC example exactly,
    including `burst 256k prio 3`
  - `test_autotune.sh`:
    - apply on bw0, seed the db with `sqlite3` (10 samples: high_priority at 100% of 30 Mbit,
      medium_priority and low_priority at 60%, best_effort at 0)
    - `autotune --db … -i bw0 --apply`, then `tc class show dev bw0 classid 1:40` shows
      rate 5000Kbit (50% floor) and still shows `prio 3` and `burst 256Kb`, and 1:10 shows
      35000Kbit with `prio 0` and `burst 32Kb`
    - the `tuning` table has 2 rows
    - running it again with the same data changes nothing and adds no rows (targets are
      computed from configured rates, see the SPEC worked example)
    - `autotune` without `--apply` changes nothing in tc
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'`
- **Commit message**:
  ```
  Wire auto-tuning into autotune command and monitor loop

  Applies computed rates with full-parameter tc class change commands
  that keep burst and priority, and records each adjustment in the
  tuning table.
  ```

## T16: Add install layout and Docker demo

- **Goal**:
  - `make install` installs `bwopt` to `$(DESTDIR)$(PREFIX)/sbin` and the config to
    `$(DESTDIR)/etc/bwopt/`
  - `scripts/demo.sh` creates bw0, applies the policy, sends mixed UDP traffic, runs the
    monitor for 5 s with `--db /tmp/demo.db --log /tmp/demo.log`, and prints `report` and
    `tc -s class show`
  - compose service `demo`: same image, repo at `/src`, `cap_add: [NET_ADMIN]`,
    `command: bash scripts/demo.sh`. The documented way to run it is
    `docker compose run --rm demo` (a bare `docker compose up` would also start the `bwopt`
    test service).
- **Files**: modify `Makefile` and `docker-compose.yml`. Create `scripts/demo.sh` and
  `tests/integration/test_install.sh`.
- **Tests first**:
  - `test_install.sh`: `make install DESTDIR=/tmp/stage PREFIX=/usr` puts files at
    `/tmp/stage/usr/sbin/bwopt` and `/tmp/stage/etc/bwopt/policies.conf`, and the staged
    binary prints the version
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck' && docker compose run --rm demo`
- **Commit message**:
  ```
  Add install layout and dummy-interface demo script

  The demo applies the policy to a dummy interface, generates mixed
  traffic and prints the per-class report and tc counters.
  ```

## T17: Regenerate README from the template with honest status

- **Goal**: Rewrite `README.md` from `tools/readme_template.md`:
  - a one-paragraph description
  - "Personal project built on the 2013-era stack (C99, libpcap 1.3, SQLite 3.7, tc/HTB,
    iptables, Debian 7)"
  - **Implemented** bullets, each mapped to code and a test (spec features 1–11), with
    `bwopt mark` described as a testing aid
  - **Not implemented / known limitations** copied from the SPEC's "Out of scope" and
    "Known limitations". It must state that the WAN link is simulated with a dummy
    interface, traffic is synthetic, the kernel is the Docker host's, payload signatures do
    not affect live marking or shaping, and some Debian package revisions are later rebuilds
    of period upstream versions.
  - Built with (the pinned versions, with the Debian revision note)
  - Running it: `docker compose run --rm demo`
  - Tests: `docker compose run --rm bwopt make test`
  - Layout generated with `git ls-files`, rendered as a tree

  No employer, role, dates, badges, or metrics.
- **Files**: modify `README.md`.
- **Tests first**: extend `tests/integration/test_cli.sh` with a doc check:
  - every path shown in the README's Layout block exists (`git ls-files` equality, run
    from `/src` with the pinned git 1.7.10.4; skipped with a message only if `.git` is absent
    in the mount or `command -v git` fails)
  - the README has no `img.shields.io` and no `Status-Complete`
  - the README has no claimed efficiency figure: `grep -iE '[0-9]+% (bandwidth )?efficiency'
    README.md` finding a match fails the test
- **Acceptance**: `docker compose run --rm bwopt sh -c 'make test && make memcheck'` (the doc
  check in `test_cli.sh` fails if the README Layout tree and `git ls-files` disagree)
- **Commit message**:
  ```
  Rewrite README from template with implemented features and limits

  Documents the pinned wheezy stack, the simulated egress link and
  synthetic traffic, and a layout tree generated from git ls-files.
  ```
