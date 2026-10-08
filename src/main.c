/*
 * Bandwidth Optimization Engine
 *
 * Real-time traffic classification and QoS management system
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "capture.h"
#include "classifier.h"
#include "config.h"
#include "dscp.h"
#include "packet.h"
#include "version.h"

#define EXIT_RUNTIME 1
#define EXIT_USAGE   2

#define PROTO_TCP      6
#define PROTO_UDP      17

static volatile sig_atomic_t running = 1;

static void signal_handler(int signum)
{
    (void)signum;
    running = 0;
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
            "\n"
            "Options:\n"
            "  -c, --config FILE      policy file (default config/policies.conf)\n"
            "  -i, --interface IFACE  network interface (default: interface= in the policy)\n"
            "  -r, --read FILE        pcap file to read\n"
            "  -w, --write FILE       pcap file to write\n"
            "  --summary              print packets and bytes per class instead\n"
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

int main(int argc, char *argv[])
{
    const char *interface = NULL;   /* NULL: interface= from the policy */
    const char *config_file = "config/policies.conf";
    const char *command = NULL;
    const char *read_file = NULL;
    const char *write_file = NULL;
    int summary = 0;
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
        } else if (strcmp(argv[i], "--summary") == 0) {
            summary = 1;
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

    fprintf(stderr, "bwopt: unknown command '%s'\n", command);
    usage(stderr);
    return EXIT_USAGE;
}
