/*
 * Writes the deterministic pcap fixtures used by the integration tests:
 *
 *   mixed.pcap  SIP, RTP, SSH, HTTPS, HTTP, FTP and unknown flows, an HTTP
 *               request on a non-standard port, ICMP, a non-first UDP
 *               fragment, ARP and IPv6 (Ethernet II)
 *   vlan.pcap   the same frames behind an 802.1Q tag (VLAN 100)
 *   nonip.pcap  ARP, IPv6 and LLDP frames only
 *
 * usage: gen_pcap OUTDIR
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

#define MAX_FRAME 512
#define BASE_SEC  1000000000L
#define STEP_USEC 100000L          /* 100 ms between frames */

#define PROTO_ICMP 1
#define PROTO_TCP  6
#define PROTO_UDP  17

#define HOST_A "192.168.1.10"
#define HOST_B "10.0.0.20"

struct frame {
    unsigned char buf[MAX_FRAME];
    size_t len;
};

/* One IPv4 packet of mixed.pcap. */
struct ip_spec {
    int proto;
    const char *src;
    unsigned sport;
    const char *dst;
    unsigned dport;
    unsigned tos;
    const char *text;          /* payload text, or NULL */
    const unsigned char *head; /* when text is NULL: leading payload bytes, or NULL */
    size_t head_len;
    size_t size;               /* when text is NULL: payload length, zero-filled after head */
    unsigned frag_off;         /* fragment offset in 8-byte units */
};

static const unsigned char tls_client_hello[] = {
    0x16, 0x03, 0x01, 0x00, 0x3b, 0x01, 0x00, 0x00, 0x37, 0x03, 0x01
};
static const unsigned char tls_server_hello[] = {
    0x16, 0x03, 0x01, 0x00, 0x3b, 0x02, 0x00, 0x00, 0x37, 0x03, 0x01
};
static const unsigned char rtp_header[] = {
    0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x12, 0x34, 0x56, 0x78
};

#define TEXT(t)          t, NULL, 0, 0
#define BYTES(head, n)   NULL, head, sizeof head, n
#define ZEROS(n)         NULL, NULL, 0, n

static const struct ip_spec mixed[] = {
    { PROTO_UDP, HOST_A, 40000, HOST_B, 5060, 0xb8,
      TEXT("INVITE sip:bob@10.0.0.20 SIP/2.0\r\n"), 0 },
    { PROTO_UDP, HOST_B, 5060, HOST_A, 40000, 0xb8,
      TEXT("SIP/2.0 200 OK\r\n"), 0 },
    { PROTO_UDP, HOST_A, 16000, HOST_B, 16002, 0xb8, BYTES(rtp_header, 172), 0 },
    { PROTO_UDP, HOST_A, 16000, HOST_B, 16002, 0xb8, BYTES(rtp_header, 172), 0 },
    { PROTO_UDP, HOST_A, 16000, HOST_B, 16002, 0xb8, BYTES(rtp_header, 172), 0 },
    { PROTO_TCP, HOST_A, 51000, HOST_B, 22, 0, TEXT("SSH-2.0-OpenSSH_6.0\r\n"), 0 },
    { PROTO_TCP, HOST_B, 22, HOST_A, 51000, 0, TEXT("SSH-2.0-OpenSSH_6.0\r\n"), 0 },
    { PROTO_TCP, HOST_A, 51001, HOST_B, 443, 0, BYTES(tls_client_hello, 64), 0 },
    { PROTO_TCP, HOST_B, 443, HOST_A, 51001, 0, BYTES(tls_server_hello, 64), 0 },
    { PROTO_TCP, HOST_A, 51002, HOST_B, 80, 0,
      TEXT("GET / HTTP/1.0\r\nHost: 10.0.0.20\r\n\r\n"), 0 },
    { PROTO_TCP, HOST_B, 80, HOST_A, 51002, 0, TEXT("HTTP/1.0 200 OK\r\n\r\n"), 0 },
    { PROTO_TCP, HOST_A, 51003, HOST_B, 21, 0, TEXT("USER anonymous\r\n"), 0 },
    { PROTO_UDP, HOST_A, 40001, HOST_B, 9999, 0, ZEROS(100), 0 },
    { PROTO_UDP, HOST_A, 40001, HOST_B, 9999, 0, ZEROS(100), 0 },
    { PROTO_TCP, HOST_A, 51004, HOST_B, 8080, 0,
      TEXT("GET /index.html HTTP/1.0\r\n\r\n"), 0 },
    /* ICMP echo request: 8-byte header + 32 bytes of data */
    { PROTO_ICMP, HOST_A, 0, HOST_B, 0, 0, ZEROS(40), 0 },
    /* tail of a fragmented UDP datagram: offset 1480, 64 data bytes */
    { PROTO_UDP, HOST_A, 0, HOST_B, 0, 0, ZEROS(64), 185 },
};

#define NMIXED (sizeof mixed / sizeof mixed[0])

static void put16(unsigned char *p, unsigned v)
{
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

static void put_addr(unsigned char *p, const char *dotted)
{
    unsigned a, b, c, d;

    if (sscanf(dotted, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        fprintf(stderr, "gen_pcap: bad address %s\n", dotted);
        exit(1);
    }
    p[0] = (unsigned char)a;
    p[1] = (unsigned char)b;
    p[2] = (unsigned char)c;
    p[3] = (unsigned char)d;
}

/* RFC 1071 checksum over an IPv4 header. */
static unsigned ip_checksum(const unsigned char *hdr, size_t len)
{
    unsigned long sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += (unsigned long)((hdr[i] << 8) | hdr[i + 1]);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned)(~sum & 0xffff);
}

static void eth_header(struct frame *f, unsigned ethertype, int vlan)
{
    static const unsigned char macs[12] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb
    };

    memcpy(f->buf, macs, sizeof macs);
    f->len = 12;
    if (vlan) {
        put16(f->buf + f->len, 0x8100);
        put16(f->buf + f->len + 2, 100);
        f->len += 4;
    }
    put16(f->buf + f->len, ethertype);
    f->len += 2;
}

static void append(struct frame *f, const void *data, size_t len)
{
    if (f->len + len > MAX_FRAME) {
        fprintf(stderr, "gen_pcap: frame too large\n");
        exit(1);
    }
    memcpy(f->buf + f->len, data, len);
    f->len += len;
}

static void build_ip(struct frame *f, const struct ip_spec *s, int vlan, unsigned id)
{
    unsigned char ip[20], l4[20], payload[MAX_FRAME];
    size_t l4len = 0, plen;

    memset(payload, 0, sizeof payload);
    if (s->text != NULL) {
        plen = strlen(s->text);
        memcpy(payload, s->text, plen);
    } else {
        plen = s->size;
        if (s->head != NULL)
            memcpy(payload, s->head, s->head_len);
    }
    if (s->proto == PROTO_ICMP) {
        payload[0] = 8;            /* echo request */
        payload[5] = 1;            /* identifier 1 */
        payload[7] = 1;            /* sequence 1 */
    }

    if (s->frag_off == 0 && s->proto == PROTO_UDP) {
        l4len = 8;
        memset(l4, 0, l4len);
        put16(l4, s->sport);
        put16(l4 + 2, s->dport);
        put16(l4 + 4, (unsigned)(l4len + plen));
    } else if (s->frag_off == 0 && s->proto == PROTO_TCP) {
        l4len = 20;
        memset(l4, 0, l4len);
        put16(l4, s->sport);
        put16(l4 + 2, s->dport);
        l4[7] = 1;                 /* seq 1 */
        l4[12] = 0x50;             /* data offset 5 */
        l4[13] = 0x18;             /* PSH|ACK */
        put16(l4 + 14, 0x1000);    /* window */
    }

    eth_header(f, 0x0800, vlan);

    memset(ip, 0, sizeof ip);
    ip[0] = 0x45;
    ip[1] = (unsigned char)s->tos;
    put16(ip + 2, (unsigned)(sizeof ip + l4len + plen));
    put16(ip + 4, id);
    put16(ip + 6, s->frag_off & 0x1fff);
    ip[8] = 64;
    ip[9] = (unsigned char)s->proto;
    put_addr(ip + 12, s->src);
    put_addr(ip + 16, s->dst);
    put16(ip + 10, ip_checksum(ip, sizeof ip));
    append(f, ip, sizeof ip);

    append(f, l4, l4len);
    append(f, payload, plen);
}

static void build_arp(struct frame *f, int vlan)
{
    static const unsigned char arp[28] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xc0, 0xa8, 0x01, 0x0a,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x14
    };

    eth_header(f, 0x0806, vlan);
    memset(f->buf, 0xff, 6);       /* broadcast */
    append(f, arp, sizeof arp);
}

static void build_ipv6(struct frame *f, int vlan)
{
    static const unsigned char ip6[48] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        0x13, 0xc4, 0x13, 0xc4, 0x00, 0x08, 0x00, 0x00
    };

    eth_header(f, 0x86dd, vlan);
    append(f, ip6, sizeof ip6);
}

static void build_lldp(struct frame *f)
{
    static const unsigned char lldp[] = {
        0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,   /* chassis id */
        0x04, 0x05, 0x05, 'e', 't', 'h', '0',                 /* port id */
        0x06, 0x02, 0x00, 0x78,                               /* TTL 120 */
        0x00, 0x00                                            /* end */
    };

    eth_header(f, 0x88cc, 0);
    f->buf[0] = 0x01; f->buf[1] = 0x80; f->buf[2] = 0xc2;
    f->buf[3] = 0x00; f->buf[4] = 0x00; f->buf[5] = 0x0e;
    append(f, lldp, sizeof lldp);
}

struct writer {
    pcap_t *dead;
    pcap_dumper_t *dumper;
    long n;
};

static void writer_open(struct writer *w, const char *dir, const char *name)
{
    char path[1024];

    snprintf(path, sizeof path, "%s/%s", dir, name);
    w->dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (w->dead == NULL) {
        fprintf(stderr, "gen_pcap: pcap_open_dead failed\n");
        exit(1);
    }
    w->dumper = pcap_dump_open(w->dead, path);
    if (w->dumper == NULL) {
        fprintf(stderr, "gen_pcap: %s\n", pcap_geterr(w->dead));
        exit(1);
    }
    w->n = 0;
}

static void writer_put(struct writer *w, const struct frame *f)
{
    struct pcap_pkthdr h;
    long usec = w->n * STEP_USEC;

    memset(&h, 0, sizeof h);
    h.ts.tv_sec = BASE_SEC + usec / 1000000L;
    h.ts.tv_usec = usec % 1000000L;
    h.caplen = (bpf_u_int32)f->len;
    h.len = (bpf_u_int32)f->len;
    pcap_dump((u_char *)w->dumper, &h, f->buf);
    w->n++;
}

static void writer_close(struct writer *w)
{
    pcap_dump_close(w->dumper);
    pcap_close(w->dead);
}

/* mixed.pcap (vlan = 0) or vlan.pcap (vlan = 1). */
static void write_mixed(const char *dir, const char *name, int vlan)
{
    struct writer w;
    struct frame f;
    size_t i;

    writer_open(&w, dir, name);
    for (i = 0; i < NMIXED; i++) {
        build_ip(&f, &mixed[i], vlan, (unsigned)(0x1000 + i));
        writer_put(&w, &f);
    }
    build_arp(&f, vlan);
    writer_put(&w, &f);
    build_ipv6(&f, vlan);
    writer_put(&w, &f);
    writer_close(&w);
}

static void write_nonip(const char *dir)
{
    struct writer w;
    struct frame f;

    writer_open(&w, dir, "nonip.pcap");
    build_arp(&f, 0);
    writer_put(&w, &f);
    build_ipv6(&f, 0);
    writer_put(&w, &f);
    build_lldp(&f);
    writer_put(&w, &f);
    writer_close(&w);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: gen_pcap OUTDIR\n");
        return 2;
    }
    write_mixed(argv[1], "mixed.pcap", 0);
    write_mixed(argv[1], "vlan.pcap", 1);
    write_nonip(argv[1]);
    return 0;
}
