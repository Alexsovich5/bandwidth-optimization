#include <string.h>
#include <check.h>

#include "../src/classifier.h"
#include "../src/config.h"
#include "../src/packet.h"

#define SHIPPED "config/policies.conf"
#define SIGNATURES "tests/fixtures/conf/signatures.conf"

static void load(const char *path, struct bw_config *cfg)
{
    char err[256] = "";

    ck_assert_msg(bw_config_load(path, cfg, err, sizeof err) == 0, "%s: %s", path, err);
}

/* An IPv4 TCP or UDP packet as bw_packet_decode() would produce it. */
static struct bw_packet ip_pkt(uint8_t proto, uint16_t sport, uint16_t dport,
                               const char *payload)
{
    struct bw_packet p;

    memset(&p, 0, sizeof p);
    p.ethertype = 0x0800;
    p.ip_proto = proto;
    p.src = 0xc0a8010aU;
    p.dst = 0x0a000014U;
    p.sport = sport;
    p.dport = dport;
    p.payload = (const u_char *)payload;
    p.payload_len = payload ? strlen(payload) : 0;
    p.ip_off = 14;
    p.wire_len = 64;
    return p;
}

static void assert_class(const struct bw_config *cfg, const struct bw_packet *p,
                         const char *want)
{
    int got = bw_classify(cfg, p);
    int idx = bw_config_find_class(cfg, want);

    ck_assert_msg(idx >= 0, "no class %s", want);
    ck_assert_msg(got == idx, "expected %s (%d), got %d (%s)", want, idx, got,
                  got >= 0 && got < cfg->nclasses ? cfg->classes[got].name : "-");
}

START_TEST(test_sip_dport_and_reply)
{
    struct bw_config cfg;
    struct bw_packet req, reply;

    load(SHIPPED, &cfg);
    req = ip_pkt(17, 40000, 5060, NULL);
    reply = ip_pkt(17, 5060, 40000, NULL);
    assert_class(&cfg, &req, "high_priority");
    assert_class(&cfg, &reply, "high_priority");
}
END_TEST

START_TEST(test_rtp_range)
{
    struct bw_config cfg;
    struct bw_packet p;

    load(SHIPPED, &cfg);
    p = ip_pkt(17, 40002, 15000, NULL);
    assert_class(&cfg, &p, "high_priority");
    p = ip_pkt(17, 10000, 40002, NULL);   /* range is inclusive, reply direction */
    assert_class(&cfg, &p, "high_priority");
    p = ip_pkt(17, 40002, 20000, NULL);
    assert_class(&cfg, &p, "high_priority");
    p = ip_pkt(17, 40002, 20001, NULL);
    assert_class(&cfg, &p, "best_effort");
}
END_TEST

START_TEST(test_ssh_tcp)
{
    struct bw_config cfg;
    struct bw_packet p;

    load(SHIPPED, &cfg);
    p = ip_pkt(6, 51000, 22, NULL);
    assert_class(&cfg, &p, "medium_priority");
}
END_TEST

START_TEST(test_dport_rule_wins_over_sport_rule)
{
    struct bw_config cfg;
    struct bw_packet p;

    load(SHIPPED, &cfg);
    /* An ephemeral source port inside the RTP range must not hide ssh. */
    p = ip_pkt(6, 15000, 22, NULL);
    assert_class(&cfg, &p, "medium_priority");
}
END_TEST

START_TEST(test_signature_overrides_port)
{
    struct bw_config cfg;
    struct bw_packet p;

    load(SIGNATURES, &cfg);
    p = ip_pkt(6, 51000, 8080, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_class(&cfg, &p, "low_priority");
    /* Port 22 says medium, but the payload is HTTP. */
    p = ip_pkt(6, 51000, 22, "GET /");
    assert_class(&cfg, &p, "low_priority");
    /* A TLS ClientHello on an unlisted port goes where https goes. */
    p = ip_pkt(6, 51000, 8443, "\x16\x03\x01\x00\xc4");
    p.payload_len = 5;      /* the record length contains a NUL byte */
    assert_class(&cfg, &p, "medium_priority");
    /* A SIP request on an odd port goes where sip goes. */
    p = ip_pkt(17, 40000, 5080, "INVITE sip:bob@10.0.0.20 SIP/2.0\r\n");
    assert_class(&cfg, &p, "high_priority");
}
END_TEST

START_TEST(test_signature_ignored_without_config)
{
    struct bw_config cfg;
    struct bw_packet p;

    load(SHIPPED, &cfg);
    p = ip_pkt(6, 51000, 8080, "GET / HTTP/1.1\r\n");
    assert_class(&cfg, &p, "best_effort");
}
END_TEST

START_TEST(test_no_match_is_default)
{
    struct bw_config cfg;
    struct bw_packet p;

    load(SHIPPED, &cfg);
    p = ip_pkt(6, 51000, 9999, NULL);
    assert_class(&cfg, &p, "best_effort");
    load(SIGNATURES, &cfg);
    p = ip_pkt(6, 51000, 9999, "\x01\x02\x03\x04\x05\x06");
    assert_class(&cfg, &p, "best_effort");
    /* ICMP and non-first fragments carry no ports. */
    p = ip_pkt(1, 0, 0, NULL);
    assert_class(&cfg, &p, "best_effort");
    p = ip_pkt(17, 0, 0, "\x9e\x21\xf0\x07");
    assert_class(&cfg, &p, "best_effort");
}
END_TEST

START_TEST(test_non_ipv4_unclassified)
{
    struct bw_config cfg;
    struct bw_packet p;

    load(SIGNATURES, &cfg);
    memset(&p, 0, sizeof p);
    p.ethertype = 0x0806;   /* ARP */
    p.wire_len = 42;
    ck_assert_int_eq(bw_classify(&cfg, &p), -1);
    p.ethertype = 0x86dd;   /* IPv6 */
    p.wire_len = 62;
    ck_assert_int_eq(bw_classify(&cfg, &p), -1);
}
END_TEST

Suite *classifier_suite(void)
{
    Suite *s = suite_create("classifier");
    TCase *tc = tcase_create("classify");

    tcase_add_test(tc, test_sip_dport_and_reply);
    tcase_add_test(tc, test_rtp_range);
    tcase_add_test(tc, test_ssh_tcp);
    tcase_add_test(tc, test_dport_rule_wins_over_sport_rule);
    tcase_add_test(tc, test_signature_overrides_port);
    tcase_add_test(tc, test_signature_ignored_without_config);
    tcase_add_test(tc, test_no_match_is_default);
    tcase_add_test(tc, test_non_ipv4_unclassified);
    suite_add_tcase(s, tc);
    return s;
}
