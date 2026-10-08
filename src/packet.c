#include <string.h>

#include "packet.h"

#define ETH_HLEN        14
#define VLAN_HLEN       4
#define SLL_HLEN        16
#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_VLAN  0x8100
#define IPV4_MIN_HLEN   20
#define TCP_MIN_HLEN    20
#define UDP_HLEN        8
#define IPPROTO_TCP_NUM 6
#define IPPROTO_UDP_NUM 17

static uint16_t get16(const u_char *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get32(const u_char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/*
 * Finds the network-layer ethertype and its offset. Returns -1 if the link
 * header is truncated or the link type is not supported.
 */
static int decode_link(int dlt, const u_char *buf, size_t caplen,
                       uint16_t *ethertype, size_t *off)
{
    switch (dlt) {
    case DLT_EN10MB:
        if (caplen < ETH_HLEN)
            return -1;
        *ethertype = get16(buf + 12);
        *off = ETH_HLEN;
        if (*ethertype == ETHERTYPE_VLAN) {
            if (caplen < ETH_HLEN + VLAN_HLEN)
                return -1;
            *ethertype = get16(buf + ETH_HLEN + 2);
            *off += VLAN_HLEN;
        }
        return 0;
    case DLT_LINUX_SLL:
        if (caplen < SLL_HLEN)
            return -1;
        *ethertype = get16(buf + 14);
        *off = SLL_HLEN;
        return 0;
    default:
        return -1;
    }
}

int bw_packet_decode(int dlt, const u_char *buf, size_t caplen, size_t wirelen,
                     struct bw_packet *out)
{
    const u_char *ip;
    size_t off, ihl, total, end, l4;
    unsigned frag_off;
    uint16_t ethertype;

    memset(out, 0, sizeof(*out));
    out->wire_len = wirelen;

    if (decode_link(dlt, buf, caplen, &ethertype, &off) != 0)
        return -1;
    out->ethertype = ethertype;
    if (ethertype != ETHERTYPE_IPV4)
        return 0;

    if (caplen - off < IPV4_MIN_HLEN)
        return -1;
    ip = buf + off;
    if ((ip[0] >> 4) != 4)
        return -1;
    ihl = (size_t)(ip[0] & 0x0f) * 4;
    if (ihl < IPV4_MIN_HLEN || caplen - off < ihl)
        return -1;
    total = get16(ip + 2);
    if (total != 0 && total < ihl)
        return -1;

    /* The IPv4 length bounds the datagram (and drops Ethernet padding);
     * a zero length, as seen with segmentation offload, falls back to the
     * captured bytes. */
    end = caplen;
    if (total != 0 && off + total < caplen)
        end = off + total;

    out->ip_off = off;
    out->dscp = ip[1] >> 2;
    out->ip_proto = ip[9];
    out->src = get32(ip + 12);
    out->dst = get32(ip + 16);
    frag_off = get16(ip + 6) & 0x1fff;

    l4 = off + ihl;
    if (frag_off == 0) {
        if (out->ip_proto == IPPROTO_TCP_NUM) {
            size_t doff;

            if (end - l4 < TCP_MIN_HLEN)
                return -1;
            doff = (size_t)(buf[l4 + 12] >> 4) * 4;
            if (doff < TCP_MIN_HLEN || end - l4 < doff)
                return -1;
            out->sport = get16(buf + l4);
            out->dport = get16(buf + l4 + 2);
            l4 += doff;
        } else if (out->ip_proto == IPPROTO_UDP_NUM) {
            if (end - l4 < UDP_HLEN)
                return -1;
            out->sport = get16(buf + l4);
            out->dport = get16(buf + l4 + 2);
            l4 += UDP_HLEN;
        }
    }

    out->payload = buf + l4;
    out->payload_len = end - l4;
    return 0;
}
