#ifndef BWOPT_PACKET_H
#define BWOPT_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <pcap/pcap.h>

/*
 * Decoded view of one captured frame. Pointers refer into the caller's
 * buffer. Addresses are in host byte order. For non-IPv4 frames only
 * ethertype and wire_len are meaningful and ip_proto is 0.
 */
struct bw_packet {
    uint16_t ethertype;
    uint8_t ip_proto;
    uint32_t src, dst;
    uint16_t sport, dport;     /* 0 unless TCP/UDP on the first fragment */
    uint8_t dscp;              /* upper six bits of the IPv4 TOS byte */
    const u_char *payload;     /* first byte after the L4 (or IPv4) header */
    size_t payload_len;        /* captured payload bytes within the IPv4 length */
    size_t ip_off;             /* offset of the IPv4 header in the frame */
    size_t wire_len;
};

/*
 * Decodes a DLT_EN10MB (optionally 802.1Q tagged) or DLT_LINUX_SLL frame.
 * Returns 0 on success, -1 for an unsupported link type or a frame whose
 * link, IPv4 or TCP/UDP header is truncated or malformed.
 */
int bw_packet_decode(int dlt, const u_char *buf, size_t caplen, size_t wirelen,
                     struct bw_packet *out);

#endif
