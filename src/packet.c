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

/* Clears a partly decoded result so no field describes a frame that failed. */
static int fail(struct bw_packet *out)
{
    size_t wire_len = out->wire_len;

    memset(out, 0, sizeof(*out));
    out->wire_len = wire_len;
    return -1;
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

    if (buf == NULL && caplen > 0)
        return fail(out);
    if (decode_link(dlt, buf, caplen, &ethertype, &off) != 0)
        return fail(out);
    out->ethertype = ethertype;
    if (ethertype != ETHERTYPE_IPV4)
        return 0;

    if (off > caplen || caplen - off < IPV4_MIN_HLEN)
        return fail(out);
    ip = buf + off;
    if ((ip[0] >> 4) != 4)
        return fail(out);
    ihl = (size_t)(ip[0] & 0x0f) * 4;
    if (ihl < IPV4_MIN_HLEN || caplen - off < ihl)
        return fail(out);
    total = get16(ip + 2);
    if (total != 0 && total < ihl)
        return fail(out);

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
    if (l4 > end)
        return fail(out);
    if (frag_off == 0) {
        if (out->ip_proto == IPPROTO_TCP_NUM) {
            size_t doff;

            if (end - l4 < TCP_MIN_HLEN)
                return fail(out);
            doff = (size_t)(buf[l4 + 12] >> 4) * 4;
            if (doff < TCP_MIN_HLEN || end - l4 < doff)
                return fail(out);
            out->sport = get16(buf + l4);
            out->dport = get16(buf + l4 + 2);
            l4 += doff;
        } else if (out->ip_proto == IPPROTO_UDP_NUM) {
            if (end - l4 < UDP_HLEN)
                return fail(out);
            out->sport = get16(buf + l4);
            out->dport = get16(buf + l4 + 2);
            l4 += UDP_HLEN;
        }
    }

    out->payload = buf + l4;
    out->payload_len = end - l4;
    return 0;
}

int bw_packet_has_ports(const u_char *frame, size_t caplen, const struct bw_packet *pkt)
{
    const u_char *ip;

    if (pkt->ethertype != ETHERTYPE_IPV4
        || (pkt->ip_proto != IPPROTO_TCP_NUM && pkt->ip_proto != IPPROTO_UDP_NUM))
        return 0;
    if (frame == NULL || pkt->ip_off > caplen || caplen - pkt->ip_off < 8)
        return 0;
    ip = frame + pkt->ip_off;
    return (get16(ip + 6) & 0x1fff) == 0;
}

static void format_addr(uint32_t a, char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u", (unsigned)(a >> 24) & 0xff,
             (unsigned)(a >> 16) & 0xff, (unsigned)(a >> 8) & 0xff, (unsigned)a & 0xff);
}

int bw_packet_print(FILE *out, unsigned long n, const u_char *frame, size_t caplen,
                    size_t wirelen, const struct bw_packet *pkt, const char *class_name)
{
    char src[16], dst[16], proto[16];

    if (pkt == NULL) {
        fprintf(out, "%lu undecoded caplen=%lu len=%lu class=%s\n", n,
                (unsigned long)caplen, (unsigned long)wirelen, class_name);
    } else if (pkt->ethertype != ETHERTYPE_IPV4) {
        fprintf(out, "%lu ethertype=0x%04x len=%lu class=%s\n", n, (unsigned)pkt->ethertype,
                (unsigned long)pkt->wire_len, class_name);
    } else {
        format_addr(pkt->src, src, sizeof src);
        format_addr(pkt->dst, dst, sizeof dst);
        if (pkt->ip_proto == IPPROTO_TCP_NUM)
            snprintf(proto, sizeof proto, "tcp");
        else if (pkt->ip_proto == IPPROTO_UDP_NUM)
            snprintf(proto, sizeof proto, "udp");
        else
            snprintf(proto, sizeof proto, "ip/%u", (unsigned)pkt->ip_proto);

        if (bw_packet_has_ports(frame, caplen, pkt))
            fprintf(out, "%lu %s %s:%u -> %s:%u len=%lu dscp=%u class=%s\n", n, proto,
                    src, (unsigned)pkt->sport, dst, (unsigned)pkt->dport,
                    (unsigned long)pkt->wire_len, (unsigned)pkt->dscp, class_name);
        else
            fprintf(out, "%lu %s %s -> %s len=%lu dscp=%u class=%s\n", n, proto, src, dst,
                    (unsigned long)pkt->wire_len, (unsigned)pkt->dscp, class_name);
    }
    return ferror(out) ? -1 : 0;
}
