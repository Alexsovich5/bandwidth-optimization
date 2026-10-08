/*
 * Bandwidth Optimization Engine
 *
 * Real-time traffic classification and QoS management system
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>

#include "capture.h"
#include "classifier.h"
#include "config.h"
#include "dscp.h"
#include "exec.h"
#include "monitor.h"
#include "packet.h"
#include "qos.h"
#include "report.h"
#include "store.h"
#include "version.h"

#define EXIT_RUNTIME 1
#define EXIT_USAGE   2

#define PROTO_TCP      6
#define PROTO_UDP      17

#define LIVE_SNAPLEN    256
#define LIVE_TIMEOUT_MS 100

static volatile sig_atomic_t running = 1;

/* The live capture to interrupt on SIGINT/SIGTERM, if any. */
static struct bw_capture *volatile active_capture;

static void signal_handler(int signum)
{
    (void)signum;
    running = 0;
    if (active_capture != NULL)
        bw_capture_break(active_capture);
}

static void usage(FILE *out)
{
    fprintf(out,
            "Usage: bwopt [--version | --help]\n"
            "       bwopt <command> [-c FILE] [-i IFACE] [options]\n"
            "\n"
            "Commands:\n"
            "  check-config           validate the policy file and print its classes\n"
            "  classify -r FILE       classify every frame of a pcap file\n"
            "  mark -r IN -w OUT      testing aid: rewrite the DSCP of IPv4 packets in a\n"
            "                         pcap file according to their class\n"
            "  dscp-script            print the iptables DSCP marking rules\n"
            "  tc-script              print the tc commands for the HTB shaping tree\n"
            "  apply                  install the HTB tree and DSCP rules on the interface,\n"
            "                         replacing any previous policy\n"
            "  clear                  remove the HTB tree and DSCP rules from the interface\n"
            "  monitor -r FILE        replay a pcap file, counting traffic per class and\n"
            "                         storing bits per second for every interval in SQLite\n"
            "  monitor -i IFACE       the same on live traffic, until SIGINT/SIGTERM or\n"
            "                         --duration, logging each interval\n"
            "  report --db PATH       print per-class totals and average/peak bit/s\n"
            "\n"
            "Options:\n"
            "  -c, --config FILE      policy file (default config/policies.conf)\n"
            "  -i, --interface IFACE  network interface (default: interface= in the policy)\n"
            "  -r, --read FILE        pcap file to read\n"
            "  -w, --write FILE       pcap file to write\n"
            "  --summary              print packets and bytes per class instead\n"
            "  --dry-run              print the commands apply/clear would run\n"
            "  --db PATH              SQLite database (default: database= in the policy)\n"
            "  --interval S           seconds per sample (default: update_interval=)\n"
            "  --duration S           live monitor: stop after S seconds\n"
            "  --log PATH             live monitor log, appended to (default: log_file=)\n"
            "  --since UNIX_TS        report: only samples with ts >= UNIX_TS\n"
            "  --iface IFACE          report: only samples of this interface\n"
            "  --version              print the version and exit\n"
            "  --help                 print this help and exit\n");
}

static int load_config(const char *path, struct bw_config *cfg)
{
    char err[512];

    if (bw_config_load(path, cfg, err, sizeof err) != 0) {
        fprintf(stderr, "bwopt: %s\n", err);
        return -1;
    }
    return 0;
}

static void print_port(const struct bw_app *a, char *buf, size_t len)
{
    if (a->port_lo == 0)
        snprintf(buf, len, "-");
    else if (a->port_lo == a->port_hi)
        snprintf(buf, len, "%u", (unsigned)a->port_lo);
    else
        snprintf(buf, len, "%u-%u", (unsigned)a->port_lo, (unsigned)a->port_hi);
}

static int cmd_check_config(const char *config_file)
{
    struct bw_config cfg;
    const struct bw_autotune_cfg *t = &cfg.tune;
    int i;

    if (load_config(config_file, &cfg) != 0)
        return EXIT_USAGE;

    printf("config %s: ok\n", config_file);
    printf("interface %s, total %" PRIu64 " bit/s, default class %s\n\n",
           cfg.iface, cfg.total_bps, cfg.classes[cfg.default_class].name);

    printf("%-16s %5s %4s %12s %6s %7s %4s\n",
           "class", "share", "dscp", "rate(bit/s)", "burst", "classid", "prio");
    for (i = 0; i < cfg.nclasses; i++) {
        const struct bw_class *c = &cfg.classes[i];
        char share[8], classid[16];

        snprintf(share, sizeof share, "%u%%", c->pct);
        snprintf(classid, sizeof classid, "1:%u", c->classid_minor);
        printf("%-16s %5s %4u %12" PRIu64 " %6s %7s %4u\n",
               c->name, share, c->dscp, c->rate_bps, c->burst, classid, c->prio);
    }

    printf("\n%-16s %-11s %-9s %s\n", "application", "port", "signature", "class");
    for (i = 0; i < cfg.napps; i++) {
        const struct bw_app *a = &cfg.apps[i];
        char port[16];

        print_port(a, port, sizeof port);
        printf("%-16s %-11s %-9s %s\n", a->name, port, bw_sig_name(a->sig),
               cfg.classes[a->class_idx].name);
    }

    printf("\nautotune %s: window=%u low_watermark=%u high_watermark=%u "
           "min_share=%u hysteresis=%u\n",
           t->enabled ? "enabled" : "disabled", t->window, t->low_watermark,
           t->high_watermark, t->min_share, t->hysteresis);
    return 0;
}

struct classify_state {
    const struct bw_config *cfg;
    int summary;
    unsigned long index;
    uint64_t packets[BW_MAX_CLASSES + 1];  /* last slot: unclassified */
    uint64_t bytes[BW_MAX_CLASSES + 1];
};

static void format_addr(uint32_t a, char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u", (unsigned)(a >> 24) & 0xff,
             (unsigned)(a >> 16) & 0xff, (unsigned)(a >> 8) & 0xff, (unsigned)a & 0xff);
}

/* True for a TCP/UDP packet whose ports were decoded (first fragment). */
static int has_ports(const u_char *frame, const struct bw_packet *pkt)
{
    const u_char *ip = frame + pkt->ip_off;

    if (pkt->ip_proto != PROTO_TCP && pkt->ip_proto != PROTO_UDP)
        return 0;
    return (((ip[6] << 8) | ip[7]) & 0x1fff) == 0;
}

/*
 * Prints one classify line. Frames that were not classified (non-IPv4, or
 * too short or malformed to decode) are shown by ethertype only.
 */
static void print_packet(unsigned long n, const u_char *frame, const struct bw_packet *pkt,
                         const char *class_name, int classified)
{
    char src[16], dst[16], proto[16];

    if (!classified) {
        printf("%lu ethertype=0x%04x len=%lu class=%s\n", n, (unsigned)pkt->ethertype,
               (unsigned long)pkt->wire_len, class_name);
        return;
    }
    format_addr(pkt->src, src, sizeof src);
    format_addr(pkt->dst, dst, sizeof dst);
    if (pkt->ip_proto == PROTO_TCP)
        snprintf(proto, sizeof proto, "tcp");
    else if (pkt->ip_proto == PROTO_UDP)
        snprintf(proto, sizeof proto, "udp");
    else
        snprintf(proto, sizeof proto, "ip/%u", (unsigned)pkt->ip_proto);

    if (has_ports(frame, pkt))
        printf("%lu %s %s:%u -> %s:%u len=%lu dscp=%u class=%s\n", n, proto,
               src, (unsigned)pkt->sport, dst, (unsigned)pkt->dport,
               (unsigned long)pkt->wire_len, (unsigned)pkt->dscp, class_name);
    else
        printf("%lu %s %s -> %s len=%lu dscp=%u class=%s\n", n, proto, src, dst,
               (unsigned long)pkt->wire_len, (unsigned)pkt->dscp, class_name);
}

static void classify_frame(u_char *user, int dlt, const struct pcap_pkthdr *hdr,
                           const u_char *bytes)
{
    struct classify_state *st = (struct classify_state *)user;
    struct bw_packet pkt;
    int idx = -1, slot;

    st->index++;
    /* A frame that fails to decode is counted as unclassified. */
    if (bw_packet_decode(dlt, bytes, hdr->caplen, hdr->len, &pkt) == 0)
        idx = bw_classify(st->cfg, &pkt);

    slot = idx >= 0 ? idx : BW_MAX_CLASSES;
    st->packets[slot]++;
    st->bytes[slot] += hdr->len;

    if (!st->summary)
        print_packet(st->index, bytes, &pkt,
                     idx >= 0 ? st->cfg->classes[idx].name : "unclassified", idx >= 0);
}

static int cmd_classify(const char *config_file, const char *pcap_file, int summary)
{
    struct bw_config cfg;
    struct bw_capture cap;
    struct classify_state st;
    char err[PCAP_ERRBUF_SIZE + 64];
    int i;

    if (pcap_file == NULL) {
        fprintf(stderr, "bwopt: classify needs -r FILE\n");
        usage(stderr);
        return EXIT_USAGE;
    }
    if (load_config(config_file, &cfg) != 0)
        return EXIT_USAGE;
    if (bw_capture_open_offline(&cap, pcap_file, err, sizeof err) != 0) {
        fprintf(stderr, "bwopt: %s\n", err);
        return EXIT_RUNTIME;
    }

    memset(&st, 0, sizeof st);
    st.cfg = &cfg;
    st.summary = summary;
    if (bw_capture_loop(&cap, -1, classify_frame, (u_char *)&st) < 0) {
        fprintf(stderr, "bwopt: %s: %s\n", pcap_file, bw_capture_error(&cap));
        bw_capture_close(&cap);
        return EXIT_RUNTIME;
    }
    bw_capture_close(&cap);

    if (summary) {
        printf("%-16s %8s %10s\n", "class", "packets", "bytes");
        for (i = 0; i < cfg.nclasses; i++)
            printf("%-16s %8" PRIu64 " %10" PRIu64 "\n", cfg.classes[i].name,
                   st.packets[i], st.bytes[i]);
        printf("%-16s %8" PRIu64 " %10" PRIu64 "\n", "unclassified",
               st.packets[BW_MAX_CLASSES], st.bytes[BW_MAX_CLASSES]);
    }
    return 0;
}

struct mark_state {
    const struct bw_config *cfg;
    pcap_dumper_t *dumper;
    u_char *buf;
    size_t buflen;
    unsigned long packets, marked;
    int nomem;
};

static void mark_frame(u_char *user, int dlt, const struct pcap_pkthdr *hdr,
                       const u_char *bytes)
{
    struct mark_state *st = (struct mark_state *)user;
    struct bw_packet pkt;
    int idx;

    st->packets++;
    if (bw_packet_decode(dlt, bytes, hdr->caplen, hdr->len, &pkt) != 0
        || (idx = bw_classify(st->cfg, &pkt)) < 0) {
        pcap_dump((u_char *)st->dumper, hdr, bytes);
        return;
    }

    if (hdr->caplen > st->buflen) {
        u_char *nb = realloc(st->buf, hdr->caplen);

        if (nb == NULL) {
            st->nomem = 1;
            pcap_dump((u_char *)st->dumper, hdr, bytes);
            return;
        }
        st->buf = nb;
        st->buflen = hdr->caplen;
    }
    memcpy(st->buf, bytes, hdr->caplen);
    if (bw_dscp_rewrite(st->buf + pkt.ip_off, hdr->caplen - pkt.ip_off,
                        (uint8_t)st->cfg->classes[idx].dscp) == 0)
        st->marked++;
    pcap_dump((u_char *)st->dumper, hdr, st->buf);
}

static int cmd_mark(const char *config_file, const char *in_file, const char *out_file)
{
    struct bw_config cfg;
    struct bw_capture cap;
    struct mark_state st;
    char err[PCAP_ERRBUF_SIZE + 64];
    int rc = 0;

    if (in_file == NULL || out_file == NULL) {
        fprintf(stderr, "bwopt: mark needs -r IN.pcap and -w OUT.pcap\n");
        usage(stderr);
        return EXIT_USAGE;
    }
    if (load_config(config_file, &cfg) != 0)
        return EXIT_USAGE;
    if (bw_capture_open_offline(&cap, in_file, err, sizeof err) != 0) {
        fprintf(stderr, "bwopt: %s\n", err);
        return EXIT_RUNTIME;
    }

    memset(&st, 0, sizeof st);
    st.cfg = &cfg;
    st.dumper = pcap_dump_open(cap.pcap, out_file);
    if (st.dumper == NULL) {
        fprintf(stderr, "bwopt: %s\n", pcap_geterr(cap.pcap));
        bw_capture_close(&cap);
        return EXIT_RUNTIME;
    }

    if (bw_capture_loop(&cap, -1, mark_frame, (u_char *)&st) < 0) {
        fprintf(stderr, "bwopt: %s: %s\n", in_file, bw_capture_error(&cap));
        rc = EXIT_RUNTIME;
    } else if (st.nomem) {
        fprintf(stderr, "bwopt: out of memory\n");
        rc = EXIT_RUNTIME;
    }
    if (pcap_dump_flush(st.dumper) != 0) {
        fprintf(stderr, "bwopt: %s: write error\n", out_file);
        rc = EXIT_RUNTIME;
    }
    pcap_dump_close(st.dumper);
    bw_capture_close(&cap);
    free(st.buf);

    if (rc == 0)
        printf("marked %lu of %lu packets, wrote %s\n", st.marked, st.packets, out_file);
    return rc;
}

static int cmd_dscp_script(const char *config_file, const char *iface)
{
    struct bw_config cfg;

    if (load_config(config_file, &cfg) != 0)
        return EXIT_USAGE;
    if (bw_dscp_script(&cfg, iface, stdout) != 0 || fflush(stdout) != 0) {
        fprintf(stderr, "bwopt: write error\n");
        return EXIT_RUNTIME;
    }
    return 0;
}

static int cmd_tc_script(const char *config_file, const char *iface)
{
    struct bw_config cfg;

    if (load_config(config_file, &cfg) != 0)
        return EXIT_USAGE;
    if (bw_qos_script(&cfg, iface, stdout) != 0 || fflush(stdout) != 0) {
        fprintf(stderr, "bwopt: write error\n");
        return EXIT_RUNTIME;
    }
    return 0;
}

enum { SCRIPT_CLEAR, SCRIPT_APPLY };

/*
 * Builds the clear script (tc, then iptables) or the apply script (tc tree,
 * then DSCP rules) in a malloc'd string. Returns NULL on failure.
 */
static char *build_script(const struct bw_config *cfg, const char *iface, int which)
{
    FILE *f = tmpfile();
    char *buf = NULL;
    long len;
    int rc;

    if (f == NULL)
        return NULL;
    if (which == SCRIPT_CLEAR)
        rc = bw_qos_clear_script(iface, f) | bw_dscp_clear_script(cfg, iface, f);
    else
        rc = bw_qos_script(cfg, iface, f) | bw_dscp_script(cfg, iface, f);
    if (rc == 0 && fflush(f) == 0 && (len = ftell(f)) >= 0
        && (buf = malloc((size_t)len + 1)) != NULL) {
        rewind(f);
        if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
            free(buf);
            buf = NULL;
        } else {
            buf[len] = '\0';
        }
    }
    fclose(f);
    return buf;
}

/*
 * apply: removes any previous policy ignoring errors (on a fresh interface
 * there is nothing to remove), then installs the new one, stopping at the
 * first failing command. clear: removes the policy, reporting failures.
 */
static int cmd_apply_clear(const char *config_file, const char *iface, int apply,
                           int dry_run)
{
    struct bw_config cfg;
    char *clear_script, *apply_script = NULL;
    int dry = dry_run ? BW_EXEC_DRY_RUN : 0;
    int rc = 0;

    if (load_config(config_file, &cfg) != 0)
        return EXIT_USAGE;
    if (iface == NULL)
        iface = cfg.iface;

    clear_script = build_script(&cfg, iface, SCRIPT_CLEAR);
    if (apply)
        apply_script = build_script(&cfg, iface, SCRIPT_APPLY);
    if (clear_script == NULL || (apply && apply_script == NULL)) {
        fprintf(stderr, "bwopt: cannot build the command script\n");
        rc = EXIT_RUNTIME;
    } else if (apply) {
        bw_exec_run(clear_script, dry | BW_EXEC_IGNORE_ERRORS, stdout);
        if (bw_exec_run(apply_script, dry, stdout) != 0)
            rc = EXIT_RUNTIME;
        else if (!dry_run)
            printf("applied policy %s to %s\n", config_file, iface);
    } else {
        if (bw_exec_run(clear_script, dry, stdout) != 0)
            rc = EXIT_RUNTIME;
        else if (!dry_run)
            printf("cleared policy from %s\n", iface);
    }
    free(clear_script);
    free(apply_script);
    if (dry_run && fflush(stdout) != 0) {
        fprintf(stderr, "bwopt: write error\n");
        rc = EXIT_RUNTIME;
    }
    return rc;
}

struct monitor_state {
    const struct bw_config *cfg;
    struct bw_capture *cap;
    sqlite3 *db;
    const char *db_path;
    const char *iface;
    unsigned interval;
    struct bw_monitor mon;
    int started;
    time_t next;               /* end of the current interval */
    struct timeval last_ts;    /* timestamp of the latest packet */
    unsigned long packets, flushes;
    FILE *log;                 /* live runs only */
    int failed;
};

/* Appends one timestamped line to the monitor log and flushes it. */
static void log_line(FILE *log, const char *fmt, ...)
{
    char stamp[32];
    time_t now = time(NULL);
    struct tm tm;
    va_list ap;

    if (log == NULL)
        return;
    if (localtime_r(&now, &tm) == NULL || strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", &tm) == 0)
        snprintf(stamp, sizeof stamp, "%ld", (long)now);
    fprintf(log, "%s bwopt[%ld]: ", stamp, (long)getpid());
    va_start(ap, fmt);
    vfprintf(log, fmt, ap);
    va_end(ap);
    fputc('\n', log);
    fflush(log);
}

/* Writes the counters as samples ending at now; stops the loop on error. */
static void monitor_flush(struct monitor_state *st, time_t now)
{
    struct bw_sample samples[BW_MONITOR_MAX_SAMPLES];
    int n = bw_monitor_flush(&st->mon, now, samples);
    uint64_t packets = 0, bytes = 0;
    int i;

    if (bw_store_put(st->db, st->iface, st->cfg, samples, n) != SQLITE_OK) {
        fprintf(stderr, "bwopt: %s: %s\n", st->db_path, sqlite3_errmsg(st->db));
        log_line(st->log, "error: %s: %s", st->db_path, sqlite3_errmsg(st->db));
        st->failed = 1;
        bw_capture_break(st->cap);
        return;
    }
    st->flushes++;
    for (i = 0; i < n; i++) {
        packets += samples[i].packets;
        bytes += samples[i].bytes;
    }
    log_line(st->log, "flush ts=%ld packets=%" PRIu64 " bytes=%" PRIu64,
             (long)now, packets, bytes);
}

/* Classifies one frame and adds it to the current interval's counters. */
static void monitor_count(struct monitor_state *st, int dlt, const struct pcap_pkthdr *hdr,
                          const u_char *bytes)
{
    struct bw_packet pkt;
    int idx = -1;

    if (bw_packet_decode(dlt, bytes, hdr->caplen, hdr->len, &pkt) == 0)
        idx = bw_classify(st->cfg, &pkt);
    bw_monitor_add(&st->mon, idx, hdr->len);
    st->packets++;
}

/*
 * Intervals follow packet timestamps: the first packet starts the first
 * interval, and every interval boundary that a packet passes is flushed
 * before the packet is counted (idle intervals give rows of zeros).
 */
static void monitor_frame(u_char *user, int dlt, const struct pcap_pkthdr *hdr,
                          const u_char *bytes)
{
    struct monitor_state *st = (struct monitor_state *)user;
    time_t ts = hdr->ts.tv_sec;

    if (st->failed)
        return;
    if (!st->started) {
        bw_monitor_init(&st->mon, st->cfg->nclasses, ts);
        st->next = ts + (time_t)st->interval;
        st->started = 1;
    }
    while (ts >= st->next) {
        monitor_flush(st, st->next);
        if (st->failed)
            return;
        st->next += (time_t)st->interval;
    }
    monitor_count(st, dlt, hdr, bytes);
    st->last_ts = hdr->ts;
}

/* Live frames are counted only; intervals follow the wall clock. */
static void monitor_live_frame(u_char *user, int dlt, const struct pcap_pkthdr *hdr,
                               const u_char *bytes)
{
    struct monitor_state *st = (struct monitor_state *)user;

    if (!st->failed)
        monitor_count(st, dlt, hdr, bytes);
}

/*
 * The final, partial interval ends at the latest packet's timestamp
 * rounded up to a whole second, and at least one second after it began.
 */
static void monitor_final_flush(struct monitor_state *st)
{
    time_t end = st->last_ts.tv_sec + (st->last_ts.tv_usec > 0 ? 1 : 0);

    if (end <= st->mon.last)
        end = st->mon.last + 1;
    monitor_flush(st, end);
}

static int parse_seconds(const char *s, unsigned long max, unsigned long *out)
{
    char *end;
    unsigned long v;

    if (*s < '0' || *s > '9')
        return -1;
    v = strtoul(s, &end, 10);
    if (*end != '\0' || v > max)
        return -1;
    *out = v;
    return 0;
}

/*
 * Captures until a signal, the end of --duration (0: none) or an error,
 * flushing every interval by the wall clock, then writes a final flush
 * of the partial interval. Returns 0 or EXIT_RUNTIME.
 */
static int monitor_live(struct monitor_state *st, unsigned long duration)
{
    struct timeval now, deadline;
    const char *reason = "signal";
    int n, rc = 0;

    gettimeofday(&now, NULL);
    bw_monitor_init(&st->mon, st->cfg->nclasses, now.tv_sec);
    st->started = 1;
    st->next = now.tv_sec + (time_t)st->interval;
    deadline = now;
    deadline.tv_sec += (time_t)duration;

    while (running && !st->failed) {
        n = bw_capture_dispatch(st->cap, monitor_live_frame, (u_char *)st);
        if (n == -1) {
            fprintf(stderr, "bwopt: %s: %s\n", st->iface, bw_capture_error(st->cap));
            log_line(st->log, "error: %s: %s", st->iface, bw_capture_error(st->cap));
            reason = "capture error";
            rc = EXIT_RUNTIME;
            break;
        }
        gettimeofday(&now, NULL);
        while (!st->failed && now.tv_sec >= st->next) {
            monitor_flush(st, st->next);
            st->next += (time_t)st->interval;
        }
        if (duration > 0 && !timercmp(&now, &deadline, <)) {
            reason = "duration";
            break;
        }
    }

    /*
     * The final interval ends now, or one second after it began when that
     * is still the current second (sample times are whole seconds and
     * unique per interface and class).
     */
    if (!st->failed)
        monitor_flush(st, now.tv_sec > st->mon.last ? now.tv_sec : st->mon.last + 1);
    if (st->failed) {
        reason = "database error";
        rc = EXIT_RUNTIME;
    }
    log_line(st->log, "monitor stopped on %s (%s): %lu packets, %lu intervals",
             st->iface, reason, st->packets, st->flushes);
    return rc;
}

static int cmd_monitor(const char *config_file, const char *pcap_file, const char *live_iface,
                       const char *db_path, const char *log_path, unsigned interval,
                       unsigned long duration)
{
    struct bw_config cfg;
    struct bw_capture cap;
    struct monitor_state st;
    char err[PCAP_ERRBUF_SIZE + 64];
    int rc = 0;

    if ((pcap_file == NULL) == (live_iface == NULL)) {
        fprintf(stderr, "bwopt: monitor needs either -r FILE or -i IFACE\n");
        usage(stderr);
        return EXIT_USAGE;
    }
    if (pcap_file != NULL && duration > 0) {
        fprintf(stderr, "bwopt: --duration applies to -i IFACE only\n");
        return EXIT_USAGE;
    }
    if (load_config(config_file, &cfg) != 0)
        return EXIT_USAGE;
    if (db_path == NULL)
        db_path = cfg.database;
    if (log_path == NULL)
        log_path = cfg.log_file;
    if (interval == 0)
        interval = cfg.update_interval;

    memset(&st, 0, sizeof st);
    if (pcap_file != NULL && bw_capture_open_offline(&cap, pcap_file, err, sizeof err) != 0) {
        fprintf(stderr, "bwopt: %s\n", err);
        return EXIT_RUNTIME;
    }
    if (bw_store_open(db_path, &st.db) != SQLITE_OK) {
        fprintf(stderr, "bwopt: %s: %s\n", db_path,
                st.db ? sqlite3_errmsg(st.db) : "out of memory");
        bw_store_close(st.db);
        if (pcap_file != NULL)
            bw_capture_close(&cap);
        return EXIT_RUNTIME;
    }
    if (live_iface != NULL) {
        st.log = fopen(log_path, "a");
        if (st.log == NULL) {
            fprintf(stderr, "bwopt: %s: %s\n", log_path, strerror(errno));
            bw_store_close(st.db);
            return EXIT_RUNTIME;
        }
        if (bw_capture_open_live(&cap, live_iface, LIVE_SNAPLEN, 0, LIVE_TIMEOUT_MS,
                                 err, sizeof err) != 0) {
            fprintf(stderr, "bwopt: %s\n", err);
            log_line(st.log, "error: %s", err);
            fclose(st.log);
            bw_store_close(st.db);
            return EXIT_RUNTIME;
        }
    }
    st.cfg = &cfg;
    st.cap = &cap;
    st.db_path = db_path;
    st.iface = live_iface != NULL ? live_iface : cfg.iface;
    st.interval = interval;

    if (live_iface != NULL) {
        log_line(st.log, "monitor started on %s (interval %us, database %s)",
                 live_iface, interval, db_path);
        active_capture = &cap;
        rc = monitor_live(&st, duration);
        active_capture = NULL;
    } else if (bw_capture_loop(&cap, -1, monitor_frame, (u_char *)&st) < 0) {
        fprintf(stderr, "bwopt: %s: %s\n", pcap_file, bw_capture_error(&cap));
        rc = EXIT_RUNTIME;
    } else if (!st.failed && st.started) {
        monitor_final_flush(&st);
    }
    if (st.failed)
        rc = EXIT_RUNTIME;
    if (st.log != NULL && fclose(st.log) != 0 && rc == 0) {
        fprintf(stderr, "bwopt: %s: write error\n", log_path);
        rc = EXIT_RUNTIME;
    }
    bw_store_close(st.db);
    bw_capture_close(&cap);

    if (rc == 0)
        printf("monitor: %lu packets from %s, %lu intervals of %us written to %s\n",
               st.packets, pcap_file != NULL ? pcap_file : live_iface, st.flushes,
               interval, db_path);
    return rc;
}

static int cmd_report(const char *db_path, const char *iface, time_t since)
{
    sqlite3 *db = NULL;
    struct bw_store_stat *rows = NULL;
    int n, rc = 0;

    if (db_path == NULL) {
        fprintf(stderr, "bwopt: report needs --db PATH\n");
        usage(stderr);
        return EXIT_USAGE;
    }
    /* read-only: a mistyped path is an error, not a new empty database */
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "bwopt: %s: %s\n", db_path, db ? sqlite3_errmsg(db) : "out of memory");
        sqlite3_close(db);
        return EXIT_RUNTIME;
    }
    n = bw_store_query(db, iface, since, 0, NULL, 0);
    if (n > 0 && (rows = calloc((size_t)n, sizeof *rows)) == NULL) {
        fprintf(stderr, "bwopt: out of memory\n");
        sqlite3_close(db);
        return EXIT_RUNTIME;
    }
    if (n > 0)
        n = bw_store_query(db, iface, since, 0, rows, n);
    if (n < 0) {
        fprintf(stderr, "bwopt: %s: %s\n", db_path, sqlite3_errmsg(db));
        rc = EXIT_RUNTIME;
    } else if (bw_report_print(rows, n, stdout) != 0 || fflush(stdout) != 0) {
        fprintf(stderr, "bwopt: write error\n");
        rc = EXIT_RUNTIME;
    }
    free(rows);
    sqlite3_close(db);
    return rc;
}

int main(int argc, char *argv[])
{
    const char *interface = NULL;   /* NULL: interface= from the policy */
    const char *config_file = "config/policies.conf";
    const char *command = NULL;
    const char *read_file = NULL;
    const char *write_file = NULL;
    const char *db_path = NULL;     /* NULL: database= from the policy */
    unsigned long interval = 0;     /* 0: update_interval= from the policy */
    const char *log_path = NULL;    /* NULL: log_file= from the policy */
    unsigned long duration = 0;     /* 0: until SIGINT/SIGTERM */
    unsigned long since = 0;
    int summary = 0;
    int dry_run = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("bwopt %s\n", BWOPT_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(stdout);
            return 0;
        } else if ((strcmp(argv[i], "--interface") == 0 || strcmp(argv[i], "-i") == 0)
                   && i + 1 < argc) {
            interface = argv[++i];
        } else if ((strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-c") == 0)
                   && i + 1 < argc) {
            config_file = argv[++i];
        } else if ((strcmp(argv[i], "--read") == 0 || strcmp(argv[i], "-r") == 0)
                   && i + 1 < argc) {
            read_file = argv[++i];
        } else if ((strcmp(argv[i], "--write") == 0 || strcmp(argv[i], "-w") == 0)
                   && i + 1 < argc) {
            write_file = argv[++i];
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            if (parse_seconds(argv[++i], 86400, &interval) != 0 || interval == 0) {
                fprintf(stderr, "bwopt: --interval '%s' must be 1-86400 seconds\n", argv[i]);
                return EXIT_USAGE;
            }
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            if (parse_seconds(argv[++i], 0x7fffffffUL, &duration) != 0 || duration == 0) {
                fprintf(stderr, "bwopt: --duration '%s' must be a positive number of seconds\n",
                        argv[i]);
                return EXIT_USAGE;
            }
        } else if (strcmp(argv[i], "--since") == 0 && i + 1 < argc) {
            if (parse_seconds(argv[++i], 0x7fffffffUL, &since) != 0) {
                fprintf(stderr, "bwopt: --since '%s' must be a unix timestamp\n", argv[i]);
                return EXIT_USAGE;
            }
        } else if (strcmp(argv[i], "--summary") == 0) {
            summary = 1;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = 1;
        } else if (argv[i][0] != '-' && command == NULL) {
            command = argv[i];
        } else {
            fprintf(stderr, "bwopt: unknown option '%s'\n", argv[i]);
            usage(stderr);
            return EXIT_USAGE;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (command == NULL) {
        usage(stderr);
        return EXIT_USAGE;
    }

    if (strcmp(command, "check-config") == 0)
        return cmd_check_config(config_file);
    if (strcmp(command, "classify") == 0)
        return cmd_classify(config_file, read_file, summary);
    if (strcmp(command, "mark") == 0)
        return cmd_mark(config_file, read_file, write_file);
    if (strcmp(command, "dscp-script") == 0)
        return cmd_dscp_script(config_file, interface);
    if (strcmp(command, "tc-script") == 0)
        return cmd_tc_script(config_file, interface);
    if (strcmp(command, "apply") == 0)
        return cmd_apply_clear(config_file, interface, 1, dry_run);
    if (strcmp(command, "clear") == 0)
        return cmd_apply_clear(config_file, interface, 0, dry_run);
    if (strcmp(command, "monitor") == 0)
        return cmd_monitor(config_file, read_file, interface, db_path, log_path,
                           (unsigned)interval, duration);
    if (strcmp(command, "report") == 0)
        return cmd_report(db_path, interface, (time_t)since);

    fprintf(stderr, "bwopt: unknown command '%s'\n", command);
    usage(stderr);
    return EXIT_USAGE;
}
