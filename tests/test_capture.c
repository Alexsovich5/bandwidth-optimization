#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <check.h>
#include <pcap/pcap.h>

#include "../src/capture.h"
#include "frames.h"

struct seen {
    int count;
    int dlt;
    size_t caplen[4];
    size_t wirelen[4];
    unsigned char first_byte[4];
};

static void record(u_char *user, int dlt, const struct pcap_pkthdr *h,
                   const u_char *bytes)
{
    struct seen *s = (struct seen *)user;

    if (s->count < 4) {
        s->caplen[s->count] = h->caplen;
        s->wirelen[s->count] = h->len;
        s->first_byte[s->count] = bytes[0];
    }
    s->dlt = dlt;
    s->count++;
}

/* Writes the given frames into a temporary pcap file with link type dlt. */
static void write_pcap(const char *path, int dlt, const unsigned char **frames,
                       const size_t *lens, int n)
{
    pcap_t *dead = pcap_open_dead(dlt, 65535);
    pcap_dumper_t *d;
    int i;

    ck_assert(dead != NULL);
    d = pcap_dump_open(dead, path);
    ck_assert_msg(d != NULL, "pcap_dump_open: %s", pcap_geterr(dead));
    for (i = 0; i < n; i++) {
        struct pcap_pkthdr h;

        memset(&h, 0, sizeof h);
        h.ts.tv_sec = 1000 + i;
        h.caplen = (bpf_u_int32)lens[i];
        h.len = (bpf_u_int32)lens[i] + (i == 1 ? 100 : 0);
        pcap_dump((u_char *)d, &h, frames[i]);
    }
    pcap_dump_close(d);
    pcap_close(dead);
}

static void temp_path(char *buf, size_t len, const char *tag)
{
    snprintf(buf, len, "/tmp/bwopt_test_capture_%s_%ld.pcap", tag, (long)getpid());
}

START_TEST(test_offline_reads_every_frame)
{
    const unsigned char *frames[3] = { frame_eth_udp_sip, frame_eth_arp, frame_vlan_udp_sip };
    size_t lens[3] = { sizeof frame_eth_udp_sip, sizeof frame_eth_arp,
                       sizeof frame_vlan_udp_sip };
    char path[128], err[PCAP_ERRBUF_SIZE + 64];
    struct bw_capture cap;
    int rc;
    struct seen s;
    int n;

    temp_path(path, sizeof path, "eth");
    write_pcap(path, DLT_EN10MB, frames, lens, 3);

    rc = bw_capture_open_offline(&cap, path, err, sizeof err);
    ck_assert_int_eq(rc, 0);
    ck_assert_int_eq(bw_capture_datalink(&cap), DLT_EN10MB);

    memset(&s, 0, sizeof s);
    n = bw_capture_loop(&cap, -1, record, (u_char *)&s);
    bw_capture_close(&cap);
    unlink(path);

    ck_assert_int_eq(n, 3);
    ck_assert_int_eq(s.count, 3);
    ck_assert_int_eq(s.dlt, DLT_EN10MB);
    ck_assert_int_eq((int)s.caplen[0], (int)sizeof frame_eth_udp_sip);
    ck_assert_int_eq((int)s.caplen[1], (int)sizeof frame_eth_arp);
    ck_assert_int_eq((int)s.wirelen[1], (int)sizeof frame_eth_arp + 100);
    ck_assert_int_eq(s.first_byte[1], 0xff);
}
END_TEST

START_TEST(test_offline_count_limits_frames)
{
    const unsigned char *frames[3] = { frame_eth_udp_sip, frame_eth_arp, frame_eth_icmp };
    size_t lens[3] = { sizeof frame_eth_udp_sip, sizeof frame_eth_arp,
                       sizeof frame_eth_icmp };
    char path[128], err[PCAP_ERRBUF_SIZE + 64];
    struct bw_capture cap;
    int rc;
    struct seen s;
    int n;

    temp_path(path, sizeof path, "count");
    write_pcap(path, DLT_EN10MB, frames, lens, 3);

    rc = bw_capture_open_offline(&cap, path, err, sizeof err);
    ck_assert_int_eq(rc, 0);
    memset(&s, 0, sizeof s);
    n = bw_capture_loop(&cap, 2, record, (u_char *)&s);
    ck_assert_int_eq(n, 2);
    ck_assert_int_eq(s.count, 2);
    /* The rest of the file is still available to a second loop. */
    n = bw_capture_loop(&cap, -1, record, (u_char *)&s);
    ck_assert_int_eq(n, 1);
    ck_assert_int_eq(s.count, 3);
    bw_capture_close(&cap);
    unlink(path);
}
END_TEST

START_TEST(test_offline_sll_is_accepted)
{
    const unsigned char *frames[1] = { frame_sll_udp_rtp };
    size_t lens[1] = { sizeof frame_sll_udp_rtp };
    char path[128], err[PCAP_ERRBUF_SIZE + 64];
    struct bw_capture cap;
    int rc;
    struct seen s;
    int n;

    temp_path(path, sizeof path, "sll");
    write_pcap(path, DLT_LINUX_SLL, frames, lens, 1);

    rc = bw_capture_open_offline(&cap, path, err, sizeof err);
    ck_assert_int_eq(rc, 0);
    ck_assert_int_eq(bw_capture_datalink(&cap), DLT_LINUX_SLL);
    memset(&s, 0, sizeof s);
    n = bw_capture_loop(&cap, -1, record, (u_char *)&s);
    ck_assert_int_eq(n, 1);
    ck_assert_int_eq(s.dlt, DLT_LINUX_SLL);
    bw_capture_close(&cap);
    unlink(path);
}
END_TEST

START_TEST(test_offline_unsupported_link_type)
{
    const unsigned char *frames[1] = { frame_eth_udp_sip + 14 };
    size_t lens[1] = { sizeof frame_eth_udp_sip - 14 };
    char path[128], err[PCAP_ERRBUF_SIZE + 64];
    struct bw_capture cap;
    int rc;

    temp_path(path, sizeof path, "raw");
    write_pcap(path, DLT_RAW, frames, lens, 1);

    err[0] = '\0';
    rc = bw_capture_open_offline(&cap, path, err, sizeof err);
    ck_assert_int_eq(rc, -1);
    unlink(path);
    ck_assert_msg(strstr(err, "unsupported link type") != NULL, "err = '%s'", err);
}
END_TEST

START_TEST(test_offline_missing_file)
{
    char err[PCAP_ERRBUF_SIZE + 64];
    struct bw_capture cap;
    int rc;

    err[0] = '\0';
    rc = bw_capture_open_offline(&cap, "/nonexistent/x.pcap", err, sizeof err);
    ck_assert_int_eq(rc, -1);
    ck_assert_msg(strstr(err, "No such file or directory") != NULL, "err = '%s'", err);
}
END_TEST

START_TEST(test_offline_not_a_pcap)
{
    char path[128], err[PCAP_ERRBUF_SIZE + 64];
    struct bw_capture cap;
    int rc;
    FILE *f;

    temp_path(path, sizeof path, "junk");
    f = fopen(path, "w");
    ck_assert(f != NULL);
    fputs("this is not a capture file, just some text\n", f);
    fclose(f);

    err[0] = '\0';
    rc = bw_capture_open_offline(&cap, path, err, sizeof err);
    ck_assert_int_eq(rc, -1);
    unlink(path);
    ck_assert_msg(err[0] != '\0', "no error message");
}
END_TEST

START_TEST(test_dispatch_reads_until_end_of_file)
{
    const unsigned char *frames[3] = { frame_eth_udp_sip, frame_eth_arp, frame_eth_icmp };
    size_t lens[3] = { sizeof frame_eth_udp_sip, sizeof frame_eth_arp,
                       sizeof frame_eth_icmp };
    char path[128], err[PCAP_ERRBUF_SIZE + 64];
    struct bw_capture cap;
    struct seen s;
    int rc, n, total = 0, calls = 0;

    temp_path(path, sizeof path, "dispatch");
    write_pcap(path, DLT_EN10MB, frames, lens, 3);

    /* ck_assert_int_eq evaluates its arguments twice */
    rc = bw_capture_open_offline(&cap, path, err, sizeof err);
    ck_assert_int_eq(rc, 0);
    memset(&s, 0, sizeof s);
    while ((n = bw_capture_dispatch(&cap, record, (u_char *)&s)) > 0 && calls < 10) {
        total += n;
        calls++;
    }
    bw_capture_close(&cap);
    unlink(path);

    ck_assert_int_eq(n, 0);
    ck_assert_int_eq(total, 3);
    ck_assert_int_eq(s.count, 3);
    ck_assert_int_eq(s.dlt, DLT_EN10MB);
}
END_TEST

START_TEST(test_dispatch_after_break)
{
    const unsigned char *frames[2] = { frame_eth_udp_sip, frame_eth_arp };
    size_t lens[2] = { sizeof frame_eth_udp_sip, sizeof frame_eth_arp };
    char path[128], err[PCAP_ERRBUF_SIZE + 64];
    struct bw_capture cap;
    struct seen s;
    int rc, n;

    temp_path(path, sizeof path, "break");
    write_pcap(path, DLT_EN10MB, frames, lens, 2);

    /* ck_assert_int_eq evaluates its arguments twice */
    rc = bw_capture_open_offline(&cap, path, err, sizeof err);
    ck_assert_int_eq(rc, 0);
    memset(&s, 0, sizeof s);
    bw_capture_break(&cap);
    n = bw_capture_dispatch(&cap, record, (u_char *)&s);
    ck_assert_int_eq(n, BW_CAPTURE_BROKEN);
    ck_assert_int_eq(s.count, 0);
    /* The request is consumed: the next call reads the frames. */
    n = bw_capture_dispatch(&cap, record, (u_char *)&s);
    bw_capture_close(&cap);
    unlink(path);
    ck_assert_int_eq(n, 2);
    ck_assert_int_eq(s.count, 2);
}
END_TEST

START_TEST(test_live_unknown_interface)
{
    char err[PCAP_ERRBUF_SIZE + 64];
    struct bw_capture cap;
    int rc;

    err[0] = '\0';
    rc = bw_capture_open_live(&cap, "nosuchif0", 256, 0, 100,
                                          err, sizeof err);
    ck_assert_int_eq(rc, -1);
    ck_assert_msg(strstr(err, "nosuchif0") != NULL, "err = '%s'", err);
}
END_TEST

Suite *capture_suite(void)
{
    Suite *s = suite_create("capture");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_offline_reads_every_frame);
    tcase_add_test(tc, test_offline_count_limits_frames);
    tcase_add_test(tc, test_offline_sll_is_accepted);
    tcase_add_test(tc, test_offline_unsupported_link_type);
    tcase_add_test(tc, test_offline_missing_file);
    tcase_add_test(tc, test_offline_not_a_pcap);
    tcase_add_test(tc, test_dispatch_reads_until_end_of_file);
    tcase_add_test(tc, test_dispatch_after_break);
    tcase_add_test(tc, test_live_unknown_interface);
    suite_add_tcase(s, tc);
    return s;
}
