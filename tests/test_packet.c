#include <string.h>
#include <check.h>

#include "../src/packet.h"
#include "frames.h"
#include "test_util.h"

#define IP_192_168_1_10 0xc0a8010aU
#define IP_10_0_0_20    0x0a000014U

/* Decodes a whole static frame (caplen == wirelen). */
#define DECODE(dlt, frame, pkt) \
    bw_packet_decode((dlt), (frame), sizeof(frame), sizeof(frame), (pkt))

static void assert_sip_udp(const struct bw_packet *p, size_t ip_off)
{
    ck_assert_int_eq(p->ethertype, 0x0800);
    ck_assert_int_eq(p->ip_proto, 17);
    ck_assert_msg(p->src == IP_192_168_1_10, "src %08x", (unsigned)p->src);
    ck_assert_msg(p->dst == IP_10_0_0_20, "dst %08x", (unsigned)p->dst);
    ck_assert_int_eq(p->sport, 40000);
    ck_assert_int_eq(p->dport, 5060);
    ck_assert_int_eq(p->dscp, 0);
    ck_assert_int_eq((int)p->ip_off, (int)ip_off);
    ck_assert_int_eq((int)p->payload_len, 4);
    ck_assert_msg(p->payload != NULL && memcmp(p->payload, "SIP!", 4) == 0,
                  "payload does not point at the UDP data");
}

START_TEST(test_eth_udp)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_udp_sip, &p), 0);
    assert_sip_udp(&p, 14);
    ck_assert_int_eq((int)p.wire_len, (int)sizeof(frame_eth_udp_sip));
    ck_assert_msg(p.payload == frame_eth_udp_sip + 42, "payload offset");
}
END_TEST

START_TEST(test_vlan_udp)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_vlan_udp_sip, &p), 0);
    assert_sip_udp(&p, 18);
    ck_assert_msg(p.payload == frame_vlan_udp_sip + 46, "payload offset");
}
END_TEST

START_TEST(test_sll_udp)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_LINUX_SLL, frame_sll_udp_rtp, &p), 0);
    ck_assert_int_eq(p.ethertype, 0x0800);
    ck_assert_int_eq(p.ip_proto, 17);
    ck_assert_int_eq((int)p.ip_off, 16);
    ck_assert_int_eq(p.sport, 16000);
    ck_assert_int_eq(p.dport, 16002);
    ck_assert_int_eq(p.dscp, 46);
    ck_assert_int_eq((int)p.payload_len, 2);
    ck_assert_msg(p.payload == frame_sll_udp_rtp + 44, "payload offset");
}
END_TEST

START_TEST(test_ip_options)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_ipopt_tcp, &p), 0);
    ck_assert_int_eq(p.ip_proto, 6);
    ck_assert_int_eq(p.dscp, 10);
    ck_assert_int_eq(p.sport, 51000);
    ck_assert_int_eq(p.dport, 22);
    /* 14 Ethernet + 24 IPv4 (with option) + 20 TCP */
    ck_assert_msg(p.payload == frame_eth_ipopt_tcp + 58, "payload offset %d",
                  (int)(p.payload - frame_eth_ipopt_tcp));
    ck_assert_int_eq((int)p.payload_len, 6);
    ck_assert_msg(memcmp(p.payload, "SSH-2.", 6) == 0, "payload bytes");
}
END_TEST

START_TEST(test_fragment_tail_has_no_ports)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_frag_tail, &p), 0);
    ck_assert_int_eq(p.ip_proto, 17);
    ck_assert_int_eq(p.sport, 0);
    ck_assert_int_eq(p.dport, 0);
    /* The fragment data starts right after the IPv4 header. */
    ck_assert_msg(p.payload == frame_eth_frag_tail + 34, "payload offset");
    ck_assert_int_eq((int)p.payload_len, 8);
}
END_TEST

START_TEST(test_fragment_head_has_ports)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_frag_head, &p), 0);
    ck_assert_int_eq(p.sport, 40000);
    ck_assert_int_eq(p.dport, 5060);
    ck_assert_int_eq((int)p.payload_len, 4);
}
END_TEST

START_TEST(test_truncated_ip)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_trunc_ip, &p), -1);
    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_trunc_ipopt, &p), -1);
}
END_TEST

START_TEST(test_truncated_l4)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_trunc_tcp, &p), -1);
    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_trunc_udp, &p), -1);
    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_tcp_doff_trunc, &p), -1);
}
END_TEST

START_TEST(test_truncated_link)
{
    struct bw_packet p;

    /* 13 bytes: one short of an Ethernet header. */
    ck_assert_int_eq(bw_packet_decode(DLT_EN10MB, frame_eth_udp_sip, 13, 13, &p), -1);
    /* VLAN tag cut off after the TPID. */
    ck_assert_int_eq(bw_packet_decode(DLT_EN10MB, frame_vlan_udp_sip, 16, 16, &p), -1);
    /* 15 bytes: one short of an SLL header. */
    ck_assert_int_eq(bw_packet_decode(DLT_LINUX_SLL, frame_sll_udp_rtp, 15, 15, &p), -1);
}
END_TEST

START_TEST(test_snaplen_cut_payload)
{
    struct bw_packet p;

    /* Captured up to the end of the UDP header only; the wire had 4 more bytes. */
    ck_assert_int_eq(bw_packet_decode(DLT_EN10MB, frame_eth_udp_sip, 42,
                                      sizeof(frame_eth_udp_sip), &p), 0);
    ck_assert_int_eq(p.dport, 5060);
    ck_assert_int_eq((int)p.payload_len, 0);
    ck_assert_int_eq((int)p.wire_len, (int)sizeof(frame_eth_udp_sip));
}
END_TEST

START_TEST(test_ethernet_padding_ignored)
{
    unsigned char padded[60];
    struct bw_packet p;

    memset(padded, 0, sizeof(padded));
    memcpy(padded, frame_eth_udp_sip, sizeof(frame_eth_udp_sip));
    ck_assert_int_eq(DECODE(DLT_EN10MB, padded, &p), 0);
    /* The IPv4 total length bounds the payload, not the padded frame. */
    ck_assert_int_eq((int)p.payload_len, 4);
}
END_TEST

START_TEST(test_arp_not_ip)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_arp, &p), 0);
    ck_assert_int_eq(p.ethertype, 0x0806);
    ck_assert_int_eq(p.ip_proto, 0);
    ck_assert_int_eq(p.sport, 0);
    ck_assert_int_eq(p.dport, 0);
    ck_assert_int_eq((int)p.wire_len, (int)sizeof(frame_eth_arp));
}
END_TEST

START_TEST(test_ipv6_not_ip)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_ipv6, &p), 0);
    ck_assert_int_eq(p.ethertype, 0x86dd);
    ck_assert_int_eq(p.ip_proto, 0);
    ck_assert_int_eq(p.dport, 0);
}
END_TEST

START_TEST(test_tcp_data_offset_8)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_tcp_doff8, &p), 0);
    ck_assert_int_eq(p.ip_proto, 6);
    ck_assert_int_eq(p.dport, 8080);
    /* 14 + 20 + 32 */
    ck_assert_msg(p.payload == frame_eth_tcp_doff8 + 66, "payload offset %d",
                  (int)(p.payload - frame_eth_tcp_doff8));
    ck_assert_int_eq((int)p.payload_len, 5);
    ck_assert_msg(memcmp(p.payload, "GET /", 5) == 0, "payload bytes");
}
END_TEST

START_TEST(test_icmp_no_ports)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_EN10MB, frame_eth_icmp, &p), 0);
    ck_assert_int_eq(p.ip_proto, 1);
    ck_assert_int_eq(p.sport, 0);
    ck_assert_int_eq(p.dport, 0);
    ck_assert_int_eq((int)p.payload_len, 8);
}
END_TEST

START_TEST(test_unknown_dlt)
{
    struct bw_packet p;

    ck_assert_int_eq(DECODE(DLT_NULL, frame_eth_udp_sip, &p), -1);
}
END_TEST

START_TEST(test_not_ipv4_version)
{
    unsigned char frame[sizeof(frame_eth_udp_sip)];
    struct bw_packet p;

    memcpy(frame, frame_eth_udp_sip, sizeof(frame));
    frame[14] = 0x65; /* version 6 under an IPv4 ethertype */
    ck_assert_int_eq(DECODE(DLT_EN10MB, frame, &p), -1);
    frame[14] = 0x44; /* IHL 4 is below the minimum */
    ck_assert_int_eq(DECODE(DLT_EN10MB, frame, &p), -1);
}
END_TEST

Suite *packet_suite(void)
{
    Suite *s = suite_create("packet");
    TCase *tc = tcase_create("decode");

    tcase_add_test(tc, test_eth_udp);
    tcase_add_test(tc, test_vlan_udp);
    tcase_add_test(tc, test_sll_udp);
    tcase_add_test(tc, test_ip_options);
    tcase_add_test(tc, test_fragment_tail_has_no_ports);
    tcase_add_test(tc, test_fragment_head_has_ports);
    tcase_add_test(tc, test_truncated_ip);
    tcase_add_test(tc, test_truncated_l4);
    tcase_add_test(tc, test_truncated_link);
    tcase_add_test(tc, test_snaplen_cut_payload);
    tcase_add_test(tc, test_ethernet_padding_ignored);
    tcase_add_test(tc, test_arp_not_ip);
    tcase_add_test(tc, test_ipv6_not_ip);
    tcase_add_test(tc, test_tcp_data_offset_8);
    tcase_add_test(tc, test_icmp_no_ports);
    tcase_add_test(tc, test_unknown_dlt);
    tcase_add_test(tc, test_not_ipv4_version);
    suite_add_tcase(s, tc);
    return s;
}
