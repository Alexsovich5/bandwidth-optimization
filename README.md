# Bandwidth Optimization Engine

`bwopt` is a small C99 command-line tool for QoS on a Linux egress interface. It reads one
policy file (`config/policies.conf`) that defines traffic classes and the applications that
belong to them, classifies packets from a live interface or a pcap file into those classes,
generates and applies iptables DSCP-marking rules and an HTB shaping tree with `tc`, records
per-class throughput in SQLite, and can re-balance the HTB guaranteed rates between classes
based on the observed usage.

Personal project built on the 2013-era stack (C99, libpcap 1.3, SQLite 3.7, tc/HTB, iptables, Debian 7).

## Status

**Implemented**

- Policy file parser and validator (`src/config.c`; `tests/test_config.c`,
  `tests/integration/test_cli.sh`): `[global]`, `[classes]`, `[applications]`, `[monitoring]`
  and an optional `[autotune]` section, inline comments, `k`/`m` suffixes, ports and port
  ranges. Checks that shares sum to at most 100%, DSCP values are 0–63 and unique, only the
  default class uses DSCP 0, and every application points to a defined class. Exposed as
  `bwopt check-config`.
- Packet decoder for Ethernet II, 802.1Q VLAN and Linux cooked capture (SLL), IPv4 with
  options and fragments, and TCP/UDP ports and payload offset (`src/packet.c`;
  `tests/test_packet.c`). Every read is checked against the captured length; frames that do
  not decode are printed as `undecoded` from the pcap record lengths. `tests/test_packet_path.c`
  feeds every truncation of the fixture frames and 4000 fixed-seed random frames through
  decode, classify, print and DSCP rewrite, and runs under valgrind and AddressSanitizer.
- Classifier using port and port-range rules in either direction, a payload-signature
  matcher for HTTP request methods, SIP and TLS handshake records, a fallback to the default
  class, and `unclassified` for non-IPv4 frames (`src/classifier.c`, `src/signatures.c`;
  `tests/test_classifier.c`, `tests/test_signatures.c`).
- Offline classification of pcap files through libpcap, per packet or as a per-class summary:
  `bwopt classify -r FILE` (`src/capture.c`, `src/main.c`; `tests/test_capture.c`,
  `tests/integration/test_classify.sh`).
- DSCP marking: `iptables -t mangle` rules in a dedicated `BWOPT` chain, generated from the
  port rules (`src/dscp.c`; `tests/test_dscp.c`, `tests/golden/policies.iptables`).
  `bwopt mark` is a testing aid, not a product feature: it rewrites the DSCP field of IPv4
  packets in a pcap file and recomputes the header checksum, so marking can be checked offline
  (`tests/integration/test_mark.sh`).
- HTB shaping tree as a `tc` script: root qdisc with the default class, a parent class at the
  total bandwidth, one child class per traffic class, an SFQ leaf per class, and u32 filters
  on the DSCP field (`src/qos.c`; `tests/test_qos.c`, `tests/golden/policies.tc`,
  `tests/integration/test_tc_script.sh`).
- `bwopt apply` and `bwopt clear`, with `--dry-run` printing the commands instead of running
  them (`src/exec.c`; `tests/test_exec.c`, `tests/integration/test_apply.sh`). Interface
  names from the policy file or `-i` are limited to `[A-Za-z0-9_.-]` (1-15 characters, no
  leading `-`) before they reach a shell command line (`tests/test_config.c`,
  `tests/integration/test_tc_script.sh`).
- Monitoring: per-class packet and byte counters fed from a live interface or a pcap file,
  bits per second per interval written to SQLite, a log file, and a clean stop on
  SIGINT/SIGTERM or after `--duration` (`src/monitor.c`, `src/store.c`;
  `tests/test_monitor.c`, `tests/test_store.c`, `tests/integration/test_monitor.sh`).
- `bwopt report --db PATH`: per-class totals and average/peak bps over a time window
  (`src/report.c`; `tests/test_report.c`, `tests/integration/test_monitor.sh` against
  `tests/expected/mixed.report`).
- Auto-tuning: a deterministic re-balancing of HTB guaranteed rates over the last N samples,
  with a floor per class, hysteresis, drift back to configured rates, and the sum of rates
  kept at or below the total. Changes are issued as full-parameter `tc class change` lines
  and logged to SQLite; available as `bwopt autotune` and `bwopt monitor --autotune`
  (`src/autotune.c`; `tests/test_autotune.c`, `tests/integration/test_autotune.sh`).
- Build and install: `make`, `make install PREFIX=... DESTDIR=...`, `make test`, and the
  `make memcheck` (valgrind) and `make asan` (AddressSanitizer) targets that `make test` also
  runs (`Makefile`; `tests/integration/test_install.sh`).
- Image packages are downloaded over HTTPS from `snapshot.debian.org` and verified (Release
  signature with `gpgv` against the Debian archive keyrings, then `Packages` and `.deb`
  SHA256) before the wheezy stage installs them with `dpkg`; the image has no apt sources
  (`docker/apt/fetch-debs.sh`; `tests/integration/test_apt_sources.sh`).

**Not implemented / known limitations**

- The WAN uplink is simulated with a Linux `dummy` interface (`bw0`) inside the container.
  It accepts and discards packets, so the HTB and iptables counters work, but no real link
  is ever saturated.
- All traffic is synthetic: deterministic pcap fixtures written by `tests/gen_pcap.c` and
  UDP datagrams sent through bash `/dev/udp`. No real user traffic is captured.
- Shaping and marking run on the Docker host's kernel, not a kernel from the period, and have
  not been validated against a real router or a saturated WAN link. They need `sch_htb`,
  `sch_sfq`, `cls_u32`, `xt_DSCP` and the `dummy` driver in the host kernel.
- Payload signatures only affect userspace classification (`classify`, `monitor`, `mark`).
  They do not affect live marking or shaping: the iptables rules and tc filters are generated
  from port rules only. The shipped `policies.conf` defines no signatures.
- No full deep packet inspection: the "DPI" is three payload signatures, so encrypted or
  obfuscated traffic on non-standard ports falls into the default class.
- No signature-based marking of live traffic (iptables `-m string`/`-m u32` rules).
- IPv4 only. IPv6 is not classified or shaped and is counted as `unclassified`; there is no
  ICMP/GRE-specific handling.
- Egress shaping only. There is no ingress shaping (IFB device or policing), so downloads are
  not shaped unless the tool runs on the LAN-side interface of a router.
- No kernel-bypass packet path (PF_RING, zero-copy); plain libpcap is used.
- No web dashboard; `bwopt report` is the only read-out.
- No deployment scripts for real routers; `scripts/demo.sh` only drives the Docker demo.
- No daemonising (fork/setsid, pid files, init scripts); `bwopt monitor` runs in the
  foreground.
- Auto-tuning is a heuristic over the average bps per window. It does not measure latency or
  queue delay, and no efficiency gain is measured or claimed.
- The image build needs `snapshot.debian.org`; if it is unreachable, or an index or package
  no longer matches its signature or checksum, the build fails.
- AddressSanitizer uses GCC 4.8.1 and glibc 2.17 from a jessie snapshot, unpacked into
  `/opt/asan` beside the wheezy toolchain, because GCC 4.7 has no ASan. The shipped binary is
  still built with GCC 4.7.
- Some Debian package revisions are later rebuilds of period upstream versions (libc6
  `2.13-38+deb7u12`, sqlite3 `3.7.13-1+deb7u2`, git `1:1.7.10.4-1+wheezy3`), because the only
  pullable wheezy image and archive are the 7.11 point release. The period state is
  `snapshot.debian.org/archive/debian/20130930T000000Z`.
- `docker-compose.yml` is a modern convenience for running the image.

## Built with

All dependencies are Debian 7 (wheezy) packages pinned to exact versions in
`docker/apt/period.lock`.
Every upstream version was released on or before 2013-09-30; the Debian revisions marked
"rebuild" are later security rebuilds of the same upstream version.

- **C99** with GCC 4.7.2 (`gcc-4.7=4.7.2-5`, `build-essential=11.5`) and GNU Make 3.81
  (`make=3.81-8.2`)
- **GNU C library** 2.13 (`libc6-dev=2.13-38+deb7u12`, rebuild)
- **libpcap** 1.3.0 (`libpcap0.8-dev=1.3.0-1`)
- **SQLite** 3.7.13 (`libsqlite3-dev=3.7.13-1+deb7u2`, `sqlite3=3.7.13-1+deb7u2`, rebuild)
- **iproute** (`tc`) 20120521 (`iproute=20120521-3+b3`) and **iptables** 1.4.14
  (`iptables=1.4.14-3.1`)
- **Check** 0.9.8 (`check=0.9.8-2`), **pkg-config** 0.26 (`pkg-config=0.26-1`) and
  **Valgrind** 3.7.0 (`valgrind=1:3.7.0-6`) for the tests
- **git** 1.7.10.4 (`git=1:1.7.10.4-1+wheezy3`, rebuild), used only by the README layout check
- **GCC** 4.8.1 (`gcc-4.8=4.8.1-10` from the jessie snapshot of 2013-09-30, `docker/apt/asan.lock`),
  used only by `make asan`
- Base image `debian:wheezy` (the 7.11 point release)

## Running it

Everything runs in a Debian 7 image built from the `Dockerfile`, so nothing needs installing
locally beyond Docker. The demo creates the dummy interface `bw0`, applies the policy, sends
mixed UDP traffic while `bwopt monitor` runs for 5 seconds, and prints the per-class report
and the HTB class counters:

```bash
docker compose build
docker compose run --rm demo
```

## Tests

```bash
docker compose run --rm bwopt make test
```

`make test` runs the unit suites, the integration scripts, `make memcheck` and `make asan`.

The Check unit suites cover the parser, decoder, classifier, signatures, tc and iptables
generation, exec modes, counters, SQLite store, report and auto-tuning; the integration
scripts apply the policy to the dummy interface and check the tc and iptables state, but no
test runs against a real link or real traffic.

## Layout

```
.gitignore
Dockerfile
Makefile
README.md
config/
  policies.conf
docker/
  apt/
    asan.lock
    fetch-debs.sh
    period.lock
    sources.conf
docker-compose.yml
docs/
  IMPLEMENTATION_PLAN.md
  SPEC.md
scripts/
  demo.sh
src/
  autotune.c
  autotune.h
  capture.c
  capture.h
  classifier.c
  classifier.h
  config.c
  config.h
  dscp.c
  dscp.h
  exec.c
  exec.h
  main.c
  monitor.c
  monitor.h
  packet.c
  packet.h
  qos.c
  qos.h
  report.c
  report.h
  signatures.c
  signatures.h
  store.c
  store.h
  version.h
tests/
  expected/
    mixed.report
    mixed.summary
  fixtures/
    conf/
      bad_dscp.conf
      bad_range.conf
      dscp0_nondefault.conf
      dup_dscp.conf
      no_default.conf
      one_class.conf
      over_100.conf
      signatures.conf
      under_100.conf
      unknown_class.conf
      unknown_key.conf
  frames.h
  gen_pcap.c
  golden/
    policies.iptables
    policies.tc
  integration/
    lib.sh
    test_apply.sh
    test_apt_sources.sh
    test_autotune.sh
    test_classify.sh
    test_cli.sh
    test_env.sh
    test_install.sh
    test_mark.sh
    test_monitor.sh
    test_tc_script.sh
  run_tests.c
  test_autotune.c
  test_capture.c
  test_classifier.c
  test_config.c
  test_dscp.c
  test_exec.c
  test_monitor.c
  test_packet.c
  test_packet_path.c
  test_qos.c
  test_report.c
  test_signatures.c
  test_store.c
  test_util.h
  test_version.c
  valgrind.supp
```
