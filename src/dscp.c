#include "dscp.h"

static const char *egress(const struct bw_config *cfg, const char *iface)
{
    return iface != NULL ? iface : cfg->iface;
}

static void format_ports(const struct bw_app *a, char *buf, size_t len)
{
    if (a->port_lo == a->port_hi)
        snprintf(buf, len, "%u", (unsigned)a->port_lo);
    else
        snprintf(buf, len, "%u:%u", (unsigned)a->port_lo, (unsigned)a->port_hi);
}

int bw_dscp_script(const struct bw_config *cfg, const char *iface, FILE *out)
{
    static const char *const protos[] = { "tcp", "udp" };
    static const char *const dirs[] = { "dport", "sport" };
    int i, p, d;

    if (!bw_iface_valid(egress(cfg, iface)))
        return -1;

    fprintf(out, "iptables -t mangle -N " BW_DSCP_CHAIN "\n");
    fprintf(out, "iptables -t mangle -A POSTROUTING -o %s -j " BW_DSCP_CHAIN "\n",
            egress(cfg, iface));

    for (i = 0; i < cfg->napps; i++) {
        const struct bw_app *a = &cfg->apps[i];
        char ports[16];

        if (a->port_lo == 0)       /* signature-only application */
            continue;
        format_ports(a, ports, sizeof ports);
        for (p = 0; p < 2; p++)
            for (d = 0; d < 2; d++)
                fprintf(out, "iptables -t mangle -A " BW_DSCP_CHAIN
                        " -p %s --%s %s -j DSCP --set-dscp %u\n",
                        protos[p], dirs[d], ports, cfg->classes[a->class_idx].dscp);
    }
    return ferror(out) ? -1 : 0;
}

int bw_dscp_clear_script(const struct bw_config *cfg, const char *iface, FILE *out)
{
    if (!bw_iface_valid(egress(cfg, iface)))
        return -1;
    fprintf(out, "iptables -t mangle -F " BW_DSCP_CHAIN "\n");
    fprintf(out, "iptables -t mangle -D POSTROUTING -o %s -j " BW_DSCP_CHAIN "\n",
            egress(cfg, iface));
    fprintf(out, "iptables -t mangle -X " BW_DSCP_CHAIN "\n");
    return ferror(out) ? -1 : 0;
}

/* RFC 1071 Internet checksum over len bytes (len is even for IPv4 headers). */
static uint16_t ip_checksum(const u_char *p, size_t len)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

int bw_dscp_rewrite(u_char *ip_hdr, size_t len, uint8_t dscp)
{
    size_t hlen;
    uint16_t sum;

    if (len < 20 || dscp > 63 || (ip_hdr[0] >> 4) != 4)
        return -1;
    hlen = (size_t)(ip_hdr[0] & 0x0f) * 4;
    if (hlen < 20 || hlen > len)
        return -1;

    ip_hdr[1] = (u_char)((dscp << 2) | (ip_hdr[1] & 0x03));
    ip_hdr[10] = 0;
    ip_hdr[11] = 0;
    sum = ip_checksum(ip_hdr, hlen);
    ip_hdr[10] = (u_char)(sum >> 8);
    ip_hdr[11] = (u_char)(sum & 0xff);
    return 0;
}

int bw_dscp_mark_frame(u_char *frame, size_t caplen, const struct bw_packet *pkt, uint8_t dscp)
{
    if (frame == NULL || pkt->ethertype != 0x0800 || pkt->ip_off > caplen)
        return -1;
    return bw_dscp_rewrite(frame + pkt->ip_off, caplen - pkt->ip_off, dscp);
}
