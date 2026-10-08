#include "classifier.h"
#include "signatures.h"

#define ETHERTYPE_IPV4 0x0800
#define PROTO_TCP 6
#define PROTO_UDP 17

static int has_ports(const struct bw_packet *pkt)
{
    return pkt->ip_proto == PROTO_TCP || pkt->ip_proto == PROTO_UDP;
}

static int by_signature(const struct bw_config *cfg, const struct bw_packet *pkt)
{
    enum bw_sig sig;
    int i;

    if (!has_ports(pkt) || pkt->payload_len == 0)
        return -1;
    sig = bw_signature_match(pkt->payload, pkt->payload_len);
    if (sig == BW_SIG_NONE)
        return -1;
    for (i = 0; i < cfg->napps; i++)
        if (cfg->apps[i].sig == sig)
            return cfg->apps[i].class_idx;
    return -1;
}

/* Port 0 never matches: signature-only apps have 0/0, portless packets 0. */
static int by_port(const struct bw_config *cfg, uint16_t port)
{
    int i;

    if (port == 0)
        return -1;
    for (i = 0; i < cfg->napps; i++) {
        const struct bw_app *a = &cfg->apps[i];

        if (a->port_lo != 0 && port >= a->port_lo && port <= a->port_hi)
            return a->class_idx;
    }
    return -1;
}

int bw_classify(const struct bw_config *cfg, const struct bw_packet *pkt)
{
    int idx;

    if (pkt->ethertype != ETHERTYPE_IPV4)
        return -1;
    if ((idx = by_signature(cfg, pkt)) >= 0)
        return idx;
    if (has_ports(pkt)) {
        if ((idx = by_port(cfg, pkt->dport)) >= 0)
            return idx;
        if ((idx = by_port(cfg, pkt->sport)) >= 0)
            return idx;
    }
    return cfg->default_class;
}
