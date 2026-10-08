# Bandwidth Optimization Engine: Specification

Target period: 2013-07 to 2013-09. Everything below is limited to what a single developer
could build and test in C on a Debian 7 (wheezy) box in 2013.

## Problem

A Linux router's uplink gets saturated by bulk traffic (web, FTP, email), and latency-sensitive
traffic such as VoIP and SSH suffers. The kernel already provides the parts needed to fix this:
libpcap to see traffic, iptables to set DSCP, and `tc`/HTB to shape it. Setting these up by hand
means working out rates from percentages, keeping DSCP values and tc filters in sync, and
watching per-class usage over time.

`bwopt` is a small C99 tool that:

1. reads one policy file (`config/policies.conf`) describing traffic classes and applications,
2. classifies packets (live or from a pcap file) into those classes,
3. generates and applies DSCP-marking rules (iptables) and an HTB shaping tree (tc),
4. records per-class throughput in SQLite, and
5. can re-balance HTB guaranteed rates between classes based on the observed usage (auto-tuning).

## In scope

1. **Policy configuration parser**: an INI-style parser for the existing `config/policies.conf` format
   (`[global]`, `[classes]`, `[applications]`, `[monitoring]`, plus an optional `[autotune]`), with
   inline `#` comments, percentage shares, `k`/`m` size suffixes, port and port-range values. It
   validates the file: shares sum to 100% or less, DSCP is 0–63, DSCP values are unique across
   classes, only the default class may use DSCP 0 (a non-default class with DSCP 0 would catch
   all unmarked traffic in the u32 filters), every application points to a defined class, and
   the default class exists. `bwopt check-config` exposes this.
2. **Packet decoder**: decodes Ethernet II, 802.1Q VLAN, and Linux cooked capture (SLL) link
   layers, IPv4 (including options and the fragment offset), and TCP/UDP ports and payload offset,
   from raw bytes. Non-IPv4 frames (ARP, IPv6, …) decode with `ip_proto` = 0.
3. **Traffic classifier**:
   - non-IPv4 frames: `bw_classify()` returns `-1`, which the classify, monitor and report
     output name `unclassified`. In the kernel these frames still fall into the HTB `default`
     class, because the u32 filters only match `protocol ip`.
   - port rules (`<app>.port`, `<app>.port_range`, either direction, TCP and UDP)
   - a small payload-signature matcher, a lightweight stand-in for DPI (HTTP request methods,
     a SIP request or status line, a TLS handshake record header)
   - fallback to `default_class` for IPv4 packets that match nothing

   Rule order: non-IPv4 check, then signature, then port, then default. Signatures only affect
   userspace classification (`classify`, `monitor`, `mark`). The live kernel path (iptables
   DSCP rules and tc filters) is generated from port rules only, so a signature never changes
   how live traffic is shaped. The shipped `policies.conf` defines no signatures.
4. **Offline classification**: `bwopt classify -r file.pcap` reads a capture through libpcap
   and prints per-packet or summary classification.
5. **DSCP marking**:
   - (a) generates `iptables -t mangle` rules (`-j DSCP --set-dscp N`) for each application
     rule on the egress interface
   - (b) testing aid, not a product feature: `bwopt mark` rewrites the DSCP field of IPv4
     packets in a pcap file according to their class and recomputes the IPv4 header checksum,
     so DSCP values and the checksum/ECN handling can be verified offline without a live
     interface
6. **QoS policy engine (HTB)**: generates the tc script for the configured interface:
   - an HTB root qdisc with `default` set to the default class
   - a parent class at `total_bandwidth`
   - one child class per traffic class (`rate` = share × total, `ceil` = total, `burst`, and
     `prio` taken from the class's order in the file)
   - `bw_qos_change_line()` for auto-tuning emits the full parameter set
     (`tc class change dev IF parent 1:1 classid 1:N htb rate Rbit ceil Cbit burst B prio P`),
     because `tc class change` with only rate/ceil resets `prio` to 0 and `burst` to the
     default
   - an SFQ leaf qdisc for each class
   - u32 filters that match the DSCP (`ip dsfield`) to send marked traffic to its class
7. **Apply / clear**: `bwopt apply` first runs the clear script in ignore-errors mode (on a
   fresh interface `tc qdisc del … root` and `iptables -F/-X BWOPT` fail because nothing exists
   yet), then runs the tc script and the DSCP rules in strict mode, stopping at the first
   failure. `bwopt clear` runs the clear script in strict mode and reports errors. With
   `--dry-run`, both commands print the shell commands without running them.
8. **Monitoring module**: per-class packet and byte counters fed by libpcap (live interface or
   pcap file). Every `update_interval` seconds it computes bits per second and writes one row per
   class to SQLite. It stops cleanly on SIGINT/SIGTERM, and writes log lines to `log_file`
   (overridable with `--log`).
9. **Reporting**: `bwopt report --db metrics.db` prints per-class totals and average/peak bps
   over a time window.
10. **Auto-tuning**: a deterministic, stateless re-balancing algorithm over the last `window`
    samples, fully defined in "Auto-tuning algorithm" below. Idle classes lend rate down to a
    floor, saturated classes receive it in proportion to their configured share, classes drift
    back to their configured rate when nobody is saturated, small changes are suppressed by
    hysteresis, and the sum of guaranteed rates never exceeds `total_bandwidth`. The result is
    emitted or applied as full-parameter `tc class change` commands (see feature 6), and each
    change is logged to SQLite. It is available as `bwopt autotune` and as
    `bwopt monitor --autotune`.
11. **Build / install**: `make`, `make install PREFIX=… DESTDIR=…`, `make test`, and
    `make memcheck` (valgrind), all run inside the period Docker image.

## Out of scope

| Original README item | Reason |
|---|---|
| Full deep packet inspection (protocol dissectors, stateful L7 matching as in l7-filter/nDPI) | Too large for a solo core. Replaced by the small signature matcher in feature 3, which only affects userspace classification, and the README will say so. |
| Signature-based marking of live traffic (iptables `-m string`/`-m u32` rules per signature) | Would need a second rule generator and kernel-module-dependent tests. Live marking uses port rules only. |
| Web dashboard (referenced as `web_dashboard.h` in the generated `src/main.c`) | Not part of the original README's feature list. `bwopt report` covers read-out. |
| IPv6 classification and shaping | The policy file and README only describe IPv4-era port rules. IPv6 frames are counted as `unclassified`. |
| Ingress shaping (IFB device / policing) | HTB only shapes egress. Ingress would need IFB setup, which is not in the README concept. |
| Kernel-bypass or "high-performance" packet paths (PF_RING, zero-copy) | Not measurable or testable in a container. Plain libpcap is used. |
| Business-impact metrics claimed in the original README | Not measured by anything in this project; dropped. |
| `scripts/` deployment scripts for real routers | There is no real router target. `scripts/demo.sh` only drives the Docker demo. |
| Daemonising (fork/setsid, pid files, init scripts) | `bwopt monitor` runs in the foreground, which is enough for Docker and tests. |

## Architecture

```
                 config/policies.conf
                         |
                   +-----v------+
                   |  config.c  |  parse + validate -> struct bw_config
                   +-----+------+
          +--------------+-----------------+---------------------+
          |              |                 |                     |
   +------v-----+  +-----v------+   +------v------+       +------v------+
   |  qos.c     |  |  dscp.c    |   | classifier.c|<------| signatures.c|
   | tc script  |  | iptables   |   | port rules  |       | payload DPI |
   +------+-----+  | + pcap mark|   +------^------+       +-------------+
          |        +-----+------+          |
          |              |          +------+------+
          +------+-------+          |  packet.c   |  Ethernet/VLAN/SLL/IPv4/L4 decode
                 |                  +------^------+
          +------v------+                  |
          |  exec.c     |          +-------+-------+
          | run/dry-run |          |  capture.c    |  libpcap live (-i) / offline (-r)
          +------+------+          +-------+-------+
                 |                         |
        tc / iptables (kernel)     +-------v-------+     +-----------+
                 ^                 |  monitor.c    |---->|  store.c  | SQLite metrics.db
                 |                 | counters, bps |     +-----+-----+
                 |                 +-------+-------+           |
                 |                         |                   |
                 |                 +-------v-------+           |
                 +-----------------|  autotune.c   |<----------+
                   tc class change | re-balance    |  last N samples
                                   +---------------+
```

Data flow for `bwopt monitor --autotune -i eth0`:

1. The config is loaded and validated.
2. The capture opens `eth0` (snaplen 256, promisc off, timeout 100 ms).
3. For each packet, the decoder produces `struct bw_packet`, the classifier returns a class
   index, and the monitor adds to the counters.
4. Every `update_interval` seconds, the monitor turns the counters into a `struct bw_sample[]`,
   which the store writes to SQLite.
5. If `--autotune` is set, the autotuner reads the last N samples and produces new rates, and
   the exec layer runs `tc class change`. The change is written to the `tuning` table.

`src/` is built into `libbwopt.a`, and the `bwopt` binary and the Check test runner both link
against it.

## Data model & interfaces

### Config format (`config/policies.conf`, existing file kept as-is)

```
[global]
interface=<ifname>                 # default egress interface
total_bandwidth=<bits/s>           # integer, e.g. 100000000
default_class=<class name>

[classes]                          # order of first appearance = HTB prio (0 = highest)
<class>.bandwidth=<N>%             # guaranteed share of total_bandwidth
<class>.dscp=<0..63>
<class>.burst=<N>[k|m]             # passed to tc as-is after validation

[applications]
<app>.port=<1..65535>
<app>.port_range=<lo>-<hi>
<app>.class=<class name>
<app>.signature=http|sip|tls       # optional; enables payload match for this app

[monitoring]
update_interval=<seconds>
log_file=<path>
database=<path>

[autotune]                         # optional; defaults shown
enabled=0
window=10                          # samples per class considered
low_watermark=50                   # % utilisation below which a class may lend
high_watermark=90                  # % utilisation above which a class may borrow
min_share=50                       # floor, % of configured rate a class keeps
hysteresis=5                       # % change below which no tc change is issued
```

Limits: 8 classes, 64 applications, names up to 31 chars. Unknown keys are an error that
includes the line number.

### Core C types (`src/*.h`)

```c
struct bw_class   { char name[32]; unsigned pct; unsigned dscp; char burst[16];
                    uint64_t rate_bps; unsigned classid_minor; unsigned prio; };
struct bw_app     { char name[32]; uint16_t port_lo, port_hi; int class_idx;
                    enum bw_sig sig; };
struct bw_config  { char iface[16]; uint64_t total_bps; int default_class;
                    struct bw_class classes[8]; int nclasses;
                    struct bw_app apps[64]; int napps;
                    unsigned update_interval; char log_file[256]; char database[256];
                    struct bw_autotune_cfg tune; };
struct bw_packet  { uint16_t ethertype; uint8_t ip_proto; uint32_t src, dst;
                    uint16_t sport, dport; uint8_t dscp; const u_char *payload;
                    size_t payload_len; size_t ip_off; size_t wire_len; };
struct bw_sample  { time_t ts; int class_idx; uint64_t packets, bytes, bps; };

int  bw_config_load(const char *path, struct bw_config *out, char *err, size_t errlen);
int  bw_packet_decode(int dlt, const u_char *buf, size_t caplen, size_t wirelen,
                      struct bw_packet *out);
int  bw_classify(const struct bw_config *, const struct bw_packet *);   /* class idx, -1 = non-IPv4 */
enum bw_sig bw_signature_match(const u_char *payload, size_t len);
int  bw_qos_script(const struct bw_config *, const char *iface, FILE *out);
int  bw_qos_clear_script(const char *iface, FILE *out);
int  bw_qos_change_line(const struct bw_config *, const char *iface, int class_idx,
                        uint64_t rate_bps, FILE *out);   /* rate, ceil, burst, prio */
int  bw_exec_run(const char *script, int flags, FILE *dry_out);  /* BW_EXEC_DRY_RUN,
                                                     BW_EXEC_IGNORE_ERRORS */
int  bw_dscp_script(const struct bw_config *, const char *iface, FILE *out);
int  bw_dscp_clear_script(const struct bw_config *, const char *iface, FILE *out);
int  bw_dscp_rewrite(u_char *ip_hdr, size_t len, uint8_t dscp);  /* fixes checksum */
void bw_monitor_add(struct bw_monitor *, int class_idx, size_t bytes);
int  bw_monitor_flush(struct bw_monitor *, time_t now, struct bw_sample *out);
int  bw_store_open(const char *path, sqlite3 **db);
int  bw_store_put(sqlite3 *, const char *iface, const struct bw_config *,
                  const struct bw_sample *, int n);
int  bw_autotune(const struct bw_config *, const uint64_t *avg_bps,
                 const uint64_t *cur_rate, uint64_t *new_rate);  /* returns #changed */
```

### tc layout generated for the shipped config (`eth0`, 100 Mbit)

```
tc qdisc add dev eth0 root handle 1: htb default 40
tc class add dev eth0 parent 1: classid 1:1 htb rate 100000000bit
tc class add dev eth0 parent 1:1 classid 1:10 htb rate 30000000bit ceil 100000000bit burst 32k prio 0
tc class add dev eth0 parent 1:1 classid 1:20 htb rate 40000000bit ceil 100000000bit burst 64k prio 1
tc class add dev eth0 parent 1:1 classid 1:30 htb rate 20000000bit ceil 100000000bit burst 128k prio 2
tc class add dev eth0 parent 1:1 classid 1:40 htb rate 10000000bit ceil 100000000bit burst 256k prio 3
tc qdisc add dev eth0 parent 1:10 handle 10: sfq perturb 10          (… one per class)
tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip dsfield 0xb8 0xfc flowid 1:10
                                                                      (tos = dscp<<2, mask 0xfc)
```

Class minor IDs are `10 × (index+1)`. The default class has no filter, because HTB `default`
already catches unmatched traffic (including non-IPv4 frames).

Auto-tuning change line (class 1:40 lowered to 5 Mbit):

```
tc class change dev eth0 parent 1:1 classid 1:40 htb rate 5000000bit ceil 100000000bit burst 256k prio 3
```

### iptables rules generated

```
iptables -t mangle -N BWOPT
iptables -t mangle -A POSTROUTING -o eth0 -j BWOPT
iptables -t mangle -A BWOPT -p udp --dport 5060 -j DSCP --set-dscp 46   (tcp and udp, dport and sport)
iptables -t mangle -A BWOPT -p udp --dport 10000:20000 -j DSCP --set-dscp 46
```

Every rule goes into a dedicated `BWOPT` chain, so `clear` can flush and delete it without
touching other rules.

### Auto-tuning algorithm (`bw_autotune`)

Inputs per class *i*: configured rate `C_i` (share × total), current rate `R_i` (latest `tuning`
row for that class and interface, else `C_i`), and `A_i`, the mean `bps` of the class's last
`window` samples. Derived: floor `F_i = min_share% × C_i`, utilisation `U_i = 100 × A_i / C_i`
(always measured against the **configured** rate, so the result does not depend on earlier
tuning). All rates are rounded down to a multiple of 1000 bit/s. Steps, in order:

1. **Classify**: donor if `U_i < low_watermark`, receiver if `U_i >= high_watermark`,
   otherwise neutral. `unclassified` is never tuned.
2. **Targets**:
   - If there is at least one donor **and** at least one receiver (re-balance):
     - donor target `T_i = min(C_i, max(F_i, 1.2 × A_i))`
     - pool `P = Σ_donors (C_i − T_i)`
     - receiver target `T_j = C_j + P × pct_j / Σ_receivers pct` (split by configured share)
     - neutral target `T_k = C_k`
   - Otherwise (drift back): every class moves half-way from its current rate to its
     configured rate, `T_i = R_i + (C_i − R_i) / 2`. If the remaining gap `|C_i − T_i|` is at
     most `hysteresis% × C_i`, then `T_i = C_i` (snap), so rates reach their configured values
     in a bounded number of runs.
3. **Hysteresis**: if `|T_i − R_i| < hysteresis% × C_i`, then `T_i = R_i` (no change).
4. **Invariant**: if `Σ T_i > total`, the excess is taken from the classes whose `T_i > R_i`, in
   proportion to their increase. Since `Σ R_i ≤ total`, this always succeeds. No `T_i` is ever
   below `F_i`.
5. **Output**: every class with `T_i ≠ R_i` gets one `bw_qos_change_line()` and one `tuning`
   row. The return value is the number of changed classes.

Because targets in a re-balance are computed from configured rates, running the algorithm
again on the same samples gives the same targets, and so no change. Worked example for the
shipped config: high_priority at 100% of 30 Mbit (receiver), medium/low at 60% (neutral),
best_effort at 0% (donor). best_effort goes to `max(5 Mbit, 0) = 5 Mbit`, the pool is 5 Mbit,
and high_priority goes to 35 Mbit. That makes 2 changes, and a second run makes 0.

### SQLite schema (`PRAGMA user_version = 1`)

```sql
CREATE TABLE IF NOT EXISTS samples (
  ts      INTEGER NOT NULL,      -- unix seconds, end of interval
  iface   TEXT    NOT NULL,
  class   TEXT    NOT NULL,      -- class name or 'unclassified'
  packets INTEGER NOT NULL,
  bytes   INTEGER NOT NULL,
  bps     INTEGER NOT NULL,
  PRIMARY KEY (ts, iface, class)
);
CREATE TABLE IF NOT EXISTS tuning (
  ts INTEGER NOT NULL, iface TEXT NOT NULL, class TEXT NOT NULL,
  old_rate INTEGER NOT NULL, new_rate INTEGER NOT NULL
);
```

### CLI

```
bwopt --version | --help
bwopt check-config  [-c FILE]
bwopt classify      [-c FILE] -r IN.pcap [--summary]
bwopt mark          [-c FILE] -r IN.pcap -w OUT.pcap          (testing aid)
bwopt tc-script     [-c FILE] [-i IFACE]
bwopt dscp-script   [-c FILE] [-i IFACE]
bwopt apply         [-c FILE] [-i IFACE] [--dry-run]
bwopt clear         [-c FILE] [-i IFACE] [--dry-run]
bwopt monitor       [-c FILE] (-i IFACE | -r IN.pcap) [--db PATH] [--log PATH]
                    [--interval S] [--duration S] [--autotune] [--dry-run]
bwopt report        --db PATH [--since UNIX_TS] [--iface IFACE]
bwopt autotune      [-c FILE] --db PATH [-i IFACE] [--apply]
```

`-c`/`--config` and `-i`/`--interface` are equivalent long and short forms (the long forms
come from the existing `src/main.c`). `-c` defaults to `config/policies.conf`. `--db` and
`--log` override `database` and `log_file` from `[monitoring]`. Exit codes: 0 means OK, 1 is a
runtime error, and 2 is a usage or config error.

The shipped config's `/var/log/bandwidth_optimizer.log` and
`/var/lib/bandwidth_optimizer/metrics.db` are kept as-is. `bwopt` does not create missing
directories: if a path cannot be opened, `monitor` exits 1 with the error. Tests and the demo
always pass `--db` and `--log` under `/tmp`.

`classify` per-packet output (one line per packet, 1-based index):

```
<n> <proto> <src>:<sport> -> <dst>:<dport> len=<wire_len> dscp=<dscp> class=<name>
<n> ethertype=0x<hhhh> len=<wire_len> class=unclassified          (non-IPv4)
```

`<proto>` is `tcp`, `udp` or `ip/<num>`. Ports are omitted (`<src> -> <dst>`) for non-first
fragments and other protocols. `classify --summary` prints `class packets bytes` rows in config
order, followed by an `unclassified` row.

## Stack & pinned versions

C projects in 2013 did not use a language package registry. Dependencies come from the
distribution, so they are pinned as exact Debian 7 (wheezy) package versions in the Dockerfile
(`apt-get install pkg=version`). `check_period.py` has no C/apt ecosystem. It was run against a
temp directory holding the apt pin list and exited 0, but that run checked nothing. The upstream
release dates below were checked by hand against the projects' release archives.

Upstream versions are all released on or before 2013-09-30. The Debian revisions are not all
period-accurate: the only pullable wheezy image and the only live wheezy archive are the 7.11
point release (2016–2017), so a few revisions are later security rebuilds of the same upstream
version. The "Debian revision" column says which. The true 2013-09-30 state, for reference, is
`snapshot.debian.org/archive/debian/20130930T000000Z` (libc6 `2.13-38`, sqlite3
`3.7.13-1+deb7u1`, git `1:1.7.10.4-1+wheezy1`); it is not used because a 7.0-era userland
cannot be installed over the 7.11 base image's newer libc6.

| Component | Upstream version | Debian package pin | Debian revision period-accurate? | Upstream release | Why it was the popular choice then |
|---|---|---|---|---|---|
| Debian GNU/Linux 7 "wheezy" | 7 | image `debian:wheezy` | No: the image is 7.11 | 2013-05-04 (7.0) | Current Debian stable in mid-2013, and a common base for Linux routers and servers |
| GNU C library | 2.13 | `libc6-dev=2.13-38+deb7u12`, `libc-dev-bin=2.13-38+deb7u12`, `libc6-dbg=2.13-38+deb7u12` | No: LTS security rebuild, forced to match the image's `libc6 2.13-38+deb7u12` (2013 state: `2.13-38`) | 2011-02-01 | wheezy's system libc |
| GCC | 4.7.2 | `gcc-4.7=4.7.2-5`, `build-essential=11.5` | Yes | 2012-09-20 | wheezy's system compiler. GCC 4.8.1 existed, but distros shipped 4.7. |
| C standard | C99 | `-std=c99 -D_BSD_SOURCE` | n/a | 1999 | The existing Makefile already uses it, and it was the portable choice before C11 support was widespread |
| GNU Make | 3.81 | `make=3.81-8.2` | Yes | 2006-04-01 | Default make on wheezy |
| libpcap | 1.3.0 | `libpcap0.8-dev=1.3.0-1` | Yes | 2012-06 | The standard capture library (tcpdump/Wireshark), shipped by wheezy |
| SQLite | 3.7.13 | `libsqlite3-0=3.7.13-1+deb7u2`, `libsqlite3-dev=3.7.13-1+deb7u2`, `sqlite3=3.7.13-1+deb7u2` | No: post-2013 security revision from 7.11 main (2013 state: `deb7u1`). Pinned below the security archive's `deb7u4` so the three packages stay consistent. | 2012-06-11 | Named in the original README. Embedded, no server needed. |
| iproute2 (`tc`) | 3.4.0 snapshot | `iproute=20120521-3+b3` | Yes | 2012-05-21 | Provides `tc`, the Linux traffic control front-end used for HTB |
| iptables | 1.4.14 | `iptables=1.4.14-3.1` | Yes | 2012-05-26 | The standard firewall/mangle tool (nftables came later) |
| Check (unit tests) | 0.9.8 | `check=0.9.8-2` | Yes | 2009-09-23 | The most widely packaged C unit-test framework of the time |
| pkg-config | 0.26 | `pkg-config=0.26-1` | Yes | 2011-05-15 | Finds the Check/libpcap flags |
| Valgrind | 3.7.0 | `valgrind=1:3.7.0-6` | Yes | 2011-11-05 | Standard leak checker used in `make memcheck` |
| git | 1.7.10.4 | `git=1:1.7.10.4-1+wheezy3`, `git-man=1:1.7.10.4-1+wheezy3` | No: later wheezy revision (2013 state: `wheezy1`) | 2012-06-03 | Needed in the image only for the README layout check (`git ls-files`) |
| bash | 4.2 | from the base image (`4.2+dfsg-0.1+deb7u3`) | No: base-image revision | 2011-02-13 | Runs the integration scripts (`/dev/udp` senders) |
| Linux HTB / SFQ / u32 / xt_DSCP | in-kernel | Docker host kernel | n/a | HTB since 2.4.20 (2002) | This is what "Linux Traffic Control" in the README refers to |

Apt sources in the Dockerfile:

```
deb http://archive.debian.org/debian wheezy main
deb http://archive.debian.org/debian-security wheezy/updates main
```

The security repository is required: the base image already carries `libc6 2.13-38+deb7u12`
from it, and `libc6-dev` in wheezy main (`deb7u10`) requires an exact `libc6` match, so without
the security repo `build-essential`, `libpcap0.8-dev`, `libsqlite3-dev` and `valgrind` (via
`libc6-dbg`) cannot be installed. Every package above is pinned explicitly, so adding the
security repo does not silently pull other newer versions of the pinned packages. tcpdump is not
installed; `bwopt classify` covers what the tests need.

## Docker images

| Image | Tag check (`hub.docker.com/v2/.../tags/<tag>`) | Pullable here | Decision |
|---|---|---|---|
| `gcc:4.8` (candidate) | 200 | **No**: "unsupported manifest media type … manifest.v1+prettyjws" (schema-1 manifest; current Docker refuses it) | Rejected |
| `gcc:4.8.5` | 200 | Yes (wheezy-based) | Rejected: GCC 4.8.5 was released 2015-06-23, after the period |
| `debian:wheezy` | 200 | Yes | **Chosen** as the base of the single `bwopt` dev/runtime image |
| `debian:7` | 200 | Yes | Same image as `debian:wheezy`. Kept as a fallback. |

The Dockerfile replaces the apt sources with the two `archive.debian.org` lines above and sets
`Acquire::Check-Valid-Until=false`. The wheezy archive keys have expired, so it also needs
`--force-yes`/`AllowUnauthenticated`. In `docker-compose.yml`, the `bwopt` service builds this
image, mounts the repo at `/src`, and adds `cap_add: [NET_ADMIN]` so the integration tests can
create a `dummy` interface and install tc and iptables rules. The `demo` service uses the same
image and also has `cap_add: [NET_ADMIN]`. `NET_RAW` is already in Docker's default
capabilities, which covers libpcap.

Verified in `debian:wheezy` with NET_ADMIN on this Docker host: dummy interface creation,
HTB/SFQ, u32 `ip dsfield` filters, and `tc class change` behaviour (it resets `prio`/`burst`
unless they are passed). Not yet re-verified, because the pinned packages could not be installed
during review and the Docker disk later filled up: the exact apt pin line, `-j DSCP
--set-dscp` via `xt_DSCP`, and valgrind 3.7.0 on the host CPU. T1 therefore adds a `docker build`
of the exact pin line and a `tests/integration/test_env.sh` smoke test that runs
`valgrind --error-exitcode=1 /bin/true` and creates a mangle chain with a DSCP rule, so any
incompatibility shows up in the first commit.

## Simulated/mocked integrations

This project has no proprietary integrations. Two things stand in for real equipment:

- **Egress link**: a Linux `dummy` interface (`bw0`, 10.99.0.1/24) inside the container
  simulates the WAN uplink. It accepts and discards packets, so HTB and iptables counters work,
  but no real link is saturated.
- **Traffic**: synthetic traffic comes from `tests/gen_pcap` (deterministic pcap fixtures written
  with `pcap_open_dead` + `pcap_dump`) and from bash `/dev/udp` senders in the integration
  scripts (run with `bash -e`). No real user traffic is captured.

The kernel doing the shaping belongs to the Docker host and is not a 2013 kernel. The README
must state all of this.

## Existing code inventory

| File | Decision | Reason |
|---|---|---|
| `Makefile` | refactor | Keep CC/CFLAGS/`install` structure. Add `_BSD_SOURCE`, the library build, test/integration/memcheck targets, and `PREFIX`/`DESTDIR`. |
| `README.md` | refactor | Regenerated in the last task from `tools/readme_template.md` with an honest Status and a Layout tree from `git ls-files` |
| `config/policies.conf` | keep | Already a sensible period-style policy file. The parser is written to accept it unchanged, including the inline `# 100 Mbps` comment. |
| `src/main.c` | refactor | Keep the signal handler, the `--interface`/`--config` handling (kept as long aliases of `-i`/`-c`), and the main-loop shape. Remove the includes of four headers that don't exist (`traffic_classifier.h`, `qos_engine.h`, `monitoring.h`, `web_dashboard.h`) and the web dashboard calls, and switch to subcommand dispatch. |

## Test strategy

- **Framework**: Check 0.9.8. There is one suite per module in `tests/test_<module>.c`, and all
  of them are linked into `tests/run_tests` against `libbwopt.a`. `make unit` runs it.
  `CK_FORK=yes` (the default) isolates crashes. Only the Check 0.9.8 API is used (`ck_assert`,
  `ck_assert_msg`, `ck_assert_int_*`, `ck_assert_str_*`). 0.9.8 has no unsigned or 64-bit
  asserts and formats `ck_assert_int_*` with `%d`, so `uint64_t` values are compared with an
  `ASSERT_U64_EQ` macro in `tests/test_util.h` built on `ck_assert_msg` and `PRIu64`.
- **Unit tests (pure logic, no privileges)**:
  - config: valid shipped file, each validation error (including duplicate DSCP and DSCP 0 on
    a non-default class), comments, suffixes
  - packet decoder: hand-built byte arrays for Ethernet, VLAN, SLL, IPv4 options, fragments,
    truncated frames, and non-IP frames
  - classifier: port, range, and reverse-direction matches, signature precedence, default,
    non-IPv4 returns -1
  - signatures: positive and negative payloads
  - qos: generated script compared byte-for-byte with `tests/golden/policies.tc`; the change
    line includes `burst` and `prio`
  - dscp: golden iptables script, checksum after rewrite verified against RFC 1071
  - monitor: counter and bps maths over intervals
  - store: SQLite schema, insert, query (temp file)
  - autotune: donor/receiver cases, floor, hysteresis, the sum ≤ total invariant, drift back to
    configured rates, idempotence of a second run on the same samples
  - exec: dry-run output, strict mode stops at the first failure, ignore-errors mode continues
- **Fixture generator**: `tests/gen_pcap.c` writes deterministic pcaps (`mixed.pcap` with
  SIP/RTP/SSH/HTTPS/HTTP/FTP/unknown flows, `vlan.pcap`, `nonip.pcap`) into `tests/fixtures/out/`
  at test time, so no binary fixtures are committed.
- **Integration tests** (`tests/integration/*.sh`, bash scripts run with `bash -e` because
  wheezy's `/bin/sh` is dash, which has no `/dev/udp`; `make integration`; need NET_ADMIN from
  compose):
  - `test_env.sh`: valgrind runs, and iptables accepts a `-j DSCP --set-dscp 46` rule
  - `test_cli.sh`: exit codes and `check-config` output
  - `test_classify.sh`: `classify --summary` on `mixed.pcap` against an expected table
  - `test_mark.sh` (testing aid): `mark`, then `classify` shows the DSCP rewritten
  - `test_apply.sh`: the first `apply` on a fresh dummy `bw0` succeeds, then
    `tc class show`/`iptables -t mangle -S BWOPT` match the expected output. UDP sent to ports
    5060, 443, and 80 raises the counters of 1:10/1:20/1:30 by exactly 5; UDP to 9999 raises
    1:40 by at least 5 (the default class can also pick up stray IPv6 ND/MLD frames). `clear`
    removes everything.
  - `test_monitor.sh`: offline `monitor -r mixed.pcap` gives the expected rows in SQLite, and
    `report` output is checked. A live `monitor -i bw0 --duration 3` while sending traffic gives
    rows with non-zero bytes for the right classes.
  - `test_autotune.sh`: seed the db with a saturated high_priority and an idle best_effort, run
    `autotune --apply`, and check that `tc class show` shows the changed rates with `prio` and
    `burst` unchanged, that the `tuning` table has rows, and that a second run changes nothing.
  - `test_install.sh`: staged `make install` layout.
- **Memory**: `make memcheck` runs `run_tests` (CK_FORK=no) and `bwopt classify` under
  valgrind with `--error-exitcode=1 --leak-check=full`. It is added right after the pcap
  classify task, and from then on every task's acceptance runs it.
- **Entry point**: `make test` = `unit` + `integration`. The canonical command is
  `docker compose run --rm bwopt make test`.

## Known limitations that will remain

- Only IPv4 and TCP/UDP port rules. No IPv6, and no ICMP/GRE-specific handling.
- The "DPI" is three payload signatures, not a protocol-aware inspection engine.
  Encrypted/obfuscated traffic on non-standard ports falls through to the default class.
  Signatures only affect offline classification, monitoring and pcap marking. Live iptables
  marking and tc filters use port rules only.
- Only egress shaping. Downloads are not shaped unless the tool runs on the LAN-side interface
  of a router.
- Auto-tuning is a heuristic over average bps per window. It does not measure latency or queue
  delay, so it cannot claim any efficiency gain.
- Integration tests shape a dummy interface in a container, using the Docker host's kernel.
  They have not been validated against a real 2013 kernel or a real saturated WAN link.
- The period image needs expired-key apt settings to build from `archive.debian.org`, and the
  build may break if the archive moves.
- Upstream versions are all from on or before 2013-09-30, but some Debian revisions are later
  rebuilds (libc6 `2.13-38+deb7u12`, sqlite3 `3.7.13-1+deb7u2`, git `1:1.7.10.4-1+wheezy3`),
  because the only pullable wheezy image and archive are the 7.11 point release. The true
  period state is snapshot `20130930T000000Z`. The final README must say this.
- Shaping and marking need `sch_htb`, `sch_sfq`, `cls_u32`, `xt_DSCP` and the `dummy` driver
  in the Docker host kernel. Without them, the NET_ADMIN integration tests fail (or skip, for
  the dummy interface).
- `docker-compose.yml` is a modern convenience for running the period image. Compose (then
  "fig") did not exist before December 2013.
