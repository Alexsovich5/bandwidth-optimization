/*
 * The per-frame path of classify, mark and monitor (decode, classify,
 * print, DSCP rewrite) fed with untrusted input: every truncation of the
 * fixture frames and a few thousand pseudo-random frames. Each frame is
 * copied into a heap buffer of exactly its captured length, so valgrind
 * (make memcheck) and AddressSanitizer (make asan) report any read or
 * write past the end.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "../src/classifier.h"
#include "../src/config.h"
#include "../src/dscp.h"
#include "../src/packet.h"
#include "frames.h"
#include "test_util.h"

#define RANDOM_FRAMES 4000
#define RANDOM_MAXLEN 160

struct sample_frame {
    const char *name;
    int dlt;
    const unsigned char *bytes;
    size_t len;
};

#define FRAME(dlt, f) { #f, dlt, f, sizeof f }

static const struct sample_frame frames[] = {
    FRAME(DLT_EN10MB, frame_eth_udp_sip),
    FRAME(DLT_EN10MB, frame_vlan_udp_sip),
    FRAME(DLT_LINUX_SLL, frame_sll_udp_rtp),
    FRAME(DLT_EN10MB, frame_eth_ipopt_tcp),
    FRAME(DLT_EN10MB, frame_eth_frag_tail),
    FRAME(DLT_EN10MB, frame_eth_frag_head),
    FRAME(DLT_EN10MB, frame_eth_trunc_ip),
    FRAME(DLT_EN10MB, frame_eth_trunc_ipopt),
    FRAME(DLT_EN10MB, frame_eth_trunc_tcp),
    FRAME(DLT_EN10MB, frame_eth_trunc_udp),
    FRAME(DLT_EN10MB, frame_eth_tcp_doff8),
    FRAME(DLT_EN10MB, frame_eth_tcp_doff_trunc),
    FRAME(DLT_EN10MB, frame_eth_arp),
    FRAME(DLT_EN10MB, frame_eth_ipv6),
    FRAME(DLT_EN10MB, frame_eth_icmp),
};

#define NFRAMES (sizeof frames / sizeof frames[0])

static struct bw_config cfg;
static FILE *sink;

static void setup(void)
{
    char err[256];

    ck_assert_msg(bw_config_load("tests/fixtures/conf/signatures.conf", &cfg, err, sizeof err)
                  == 0, "%s", err);
    sink = fopen("/dev/null", "w");
    ck_assert(sink != NULL);
}

static void teardown(void)
{
    fclose(sink);
}

/*
 * Runs one frame through the same steps as bwopt classify and bwopt mark,
 * checking that everything the decoder reports lies inside the capture.
 * Returns the decode result.
 */
static int run_frame(int dlt, const unsigned char *src, size_t caplen, size_t wirelen)
{
    unsigned char *buf = malloc(caplen);
    struct bw_packet pkt;
    int rc, prc, idx = -1;

    ck_assert(buf != NULL || caplen == 0);
    if (caplen > 0)
        memcpy(buf, src, caplen);
    memset(&pkt, 0xa5, sizeof pkt);     /* the decoder must not leave any of this */

    rc = bw_packet_decode(dlt, buf, caplen, wirelen, &pkt);
    ck_assert_msg(pkt.wire_len == wirelen, "wire_len not set");
    if (rc == 0) {
        if (pkt.ethertype == 0x0800) {
            ck_assert_msg(pkt.ip_off <= caplen && caplen - pkt.ip_off >= 20,
                          "IPv4 header outside the capture");
            ck_assert_msg(pkt.payload >= buf + pkt.ip_off + 20
                          && pkt.payload <= buf + caplen
                          && pkt.payload_len <= (size_t)(buf + caplen - pkt.payload),
                          "payload outside the capture");
        } else {
            ck_assert_msg(pkt.payload == NULL && pkt.payload_len == 0, "non-IPv4 payload");
        }
        idx = bw_classify(&cfg, &pkt);
        ck_assert(idx >= -1 && idx < cfg.nclasses);
        ck_assert_msg((idx == -1) == (pkt.ethertype != 0x0800), "class %d for 0x%04x",
                      idx, (unsigned)pkt.ethertype);
        bw_packet_has_ports(buf, caplen, &pkt);
    } else {
        ck_assert_int_eq(rc, -1);
        ck_assert_msg(pkt.payload == NULL && pkt.payload_len == 0 && pkt.ip_off == 0,
                      "failed decode left stale fields");
    }

    prc = bw_packet_print(sink, 1, buf, caplen, wirelen, rc == 0 ? &pkt : NULL,
                          idx >= 0 ? cfg.classes[idx].name : "unclassified");
    ck_assert_int_eq(prc, 0);
    if (idx >= 0)
        bw_dscp_mark_frame(buf, caplen, &pkt, (uint8_t)cfg.classes[idx].dscp);
    free(buf);
    return rc;
}

START_TEST(test_every_truncation_of_every_fixture)
{
    size_t i, len;

    for (i = 0; i < NFRAMES; i++) {
        const struct sample_frame *f = &frames[i];

        for (len = 0; len <= f->len; len++) {
            run_frame(f->dlt, f->bytes, len, f->len);
            run_frame(f->dlt, f->bytes, len, len);
        }
    }
}
END_TEST

/* Fixed-seed linear congruential generator, so every run sees the same frames. */
static unsigned long rng_state = 0x2545f491UL;

static unsigned rnd(unsigned n)
{
    rng_state = rng_state * 1103515245UL + 12345UL;
    return (unsigned)((rng_state >> 16) & 0x7fff) % n;
}

/*
 * Random bytes, biased towards headers the decoder accepts (IPv4 ethertype,
 * version 4, TCP or UDP, small fragment offsets) so most frames get past
 * the first checks and reach the transport and payload code.
 */
static size_t random_frame(unsigned char *b, int *dlt)
{
    size_t len = rnd(RANDOM_MAXLEN + 1), i, ip;

    for (i = 0; i < len; i++)
        b[i] = (unsigned char)rnd(256);
    *dlt = rnd(4) == 0 ? DLT_LINUX_SLL : DLT_EN10MB;
    ip = *dlt == DLT_LINUX_SLL ? 16 : 14;
    if (*dlt == DLT_EN10MB && rnd(4) == 0) {
        if (len >= 14) { b[12] = 0x81; b[13] = 0x00; }
        ip += 4;
    }
    if (rnd(8) != 0 && len >= ip) {
        b[ip - 2] = 0x08;
        b[ip - 1] = 0x00;
    }
    if (rnd(8) != 0 && len > ip) {
        b[ip] = (unsigned char)(0x40 | (rnd(4) == 0 ? rnd(16) : 5 + rnd(3)));
        if (len > ip + 9)
            b[ip + 9] = rnd(3) == 0 ? (unsigned char)rnd(256) : (rnd(2) ? 6 : 17);
        if (len > ip + 7 && rnd(2)) {
            b[ip + 6] &= 0xe0;
            b[ip + 7] = 0;
        }
    }
    return len;
}

START_TEST(test_random_frames)
{
    unsigned char b[RANDOM_MAXLEN];
    unsigned decoded = 0;
    int i, dlt;

    for (i = 0; i < RANDOM_FRAMES; i++) {
        size_t len = random_frame(b, &dlt);

        if (run_frame(dlt, b, len, len + rnd(64)) == 0)
            decoded++;
    }
    /* the generator must actually reach the deeper code, not just fail early */
    ck_assert_msg(decoded > RANDOM_FRAMES / 4, "only %u frames decoded", decoded);
}
END_TEST

/* Output of bw_packet_print for one frame. */
static void print_to(char *out, size_t outlen, const unsigned char *frame, size_t caplen,
                     size_t wirelen, const struct bw_packet *pkt, const char *cls)
{
    FILE *f = tmpfile();
    size_t n;
    int rc;

    ck_assert(f != NULL);
    rc = bw_packet_print(f, 7, frame, caplen, wirelen, pkt, cls);  /* evaluated once */
    ck_assert_int_eq(rc, 0);
    rewind(f);
    n = fread(out, 1, outlen - 1, f);
    out[n] = '\0';
    fclose(f);
}

START_TEST(test_print_undecoded_uses_capture_lengths_only)
{
    char out[256];
    struct bw_packet pkt;

    /* a 20-byte capture of a 60-byte frame: Ethernet plus 6 bytes of IPv4 */
    ck_assert_int_eq(bw_packet_decode(DLT_EN10MB, frame_eth_udp_sip, 20, 60, &pkt), -1);
    print_to(out, sizeof out, frame_eth_udp_sip, 20, 60, NULL, "unclassified");
    ck_assert_str_eq(out, "7 undecoded caplen=20 len=60 class=unclassified\n");
}
END_TEST

START_TEST(test_print_formats)
{
    char out[256];
    struct bw_packet pkt;

    ck_assert_int_eq(bw_packet_decode(DLT_EN10MB, frame_eth_udp_sip, sizeof frame_eth_udp_sip,
                                      sizeof frame_eth_udp_sip, &pkt), 0);
    print_to(out, sizeof out, frame_eth_udp_sip, sizeof frame_eth_udp_sip,
             sizeof frame_eth_udp_sip, &pkt, "high_priority");
    ck_assert_str_eq(out, "7 udp 192.168.1.10:40000 -> 10.0.0.20:5060 len=46 dscp=0 "
                     "class=high_priority\n");

    ck_assert_int_eq(bw_packet_decode(DLT_EN10MB, frame_eth_arp, sizeof frame_eth_arp,
                                      sizeof frame_eth_arp, &pkt), 0);
    print_to(out, sizeof out, frame_eth_arp, sizeof frame_eth_arp, sizeof frame_eth_arp,
             &pkt, "unclassified");
    ck_assert_str_eq(out, "7 ethertype=0x0806 len=42 class=unclassified\n");
}
END_TEST

START_TEST(test_has_ports_checks_caplen)
{
    struct bw_packet pkt;

    ck_assert_int_eq(bw_packet_decode(DLT_EN10MB, frame_eth_udp_sip, sizeof frame_eth_udp_sip,
                                      sizeof frame_eth_udp_sip, &pkt), 0);
    ck_assert_int_eq(bw_packet_has_ports(frame_eth_udp_sip, sizeof frame_eth_udp_sip, &pkt), 1);
    /* the fragment field (IPv4 bytes 6-7) is not inside these captures */
    ck_assert_int_eq(bw_packet_has_ports(frame_eth_udp_sip, 21, &pkt), 0);
    ck_assert_int_eq(bw_packet_has_ports(frame_eth_udp_sip, 10, &pkt), 0);
    pkt.ip_off = 1000;
    ck_assert_int_eq(bw_packet_has_ports(frame_eth_udp_sip, sizeof frame_eth_udp_sip, &pkt), 0);

    ck_assert_int_eq(bw_packet_decode(DLT_EN10MB, frame_eth_frag_tail,
                                      sizeof frame_eth_frag_tail, sizeof frame_eth_frag_tail,
                                      &pkt), 0);
    ck_assert_int_eq(bw_packet_has_ports(frame_eth_frag_tail, sizeof frame_eth_frag_tail,
                                         &pkt), 0);
}
END_TEST

START_TEST(test_mark_frame_checks_offsets)
{
    unsigned char buf[sizeof frame_eth_udp_sip];
    struct bw_packet pkt;

    memcpy(buf, frame_eth_udp_sip, sizeof buf);
    ck_assert_int_eq(bw_packet_decode(DLT_EN10MB, buf, sizeof buf, sizeof buf, &pkt), 0);
    ck_assert_int_eq(bw_dscp_mark_frame(buf, sizeof buf, &pkt, 46), 0);
    ck_assert_int_eq(buf[15], 0xb8);

    memcpy(buf, frame_eth_udp_sip, sizeof buf);
    pkt.ip_off = sizeof buf + 4;        /* past the end: nothing may be touched */
    ck_assert_int_eq(bw_dscp_mark_frame(buf, sizeof buf, &pkt, 46), -1);
    pkt.ip_off = 14;
    ck_assert_int_eq(bw_dscp_mark_frame(buf, 30, &pkt, 46), -1);
    ck_assert_msg(memcmp(buf, frame_eth_udp_sip, sizeof buf) == 0, "frame modified");

    pkt.ethertype = 0x0806;
    ck_assert_int_eq(bw_dscp_mark_frame(buf, sizeof buf, &pkt, 46), -1);
}
END_TEST

Suite *packet_path_suite(void)
{
    Suite *s = suite_create("packet_path");
    TCase *tc = tcase_create("core");

    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_set_timeout(tc, 120);
    tcase_add_test(tc, test_every_truncation_of_every_fixture);
    tcase_add_test(tc, test_random_frames);
    tcase_add_test(tc, test_print_undecoded_uses_capture_lengths_only);
    tcase_add_test(tc, test_print_formats);
    tcase_add_test(tc, test_has_ports_checks_caplen);
    tcase_add_test(tc, test_mark_frame_checks_offsets);
    suite_add_tcase(s, tc);
    return s;
}
