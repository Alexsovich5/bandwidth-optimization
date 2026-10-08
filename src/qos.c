#include <inttypes.h>

#include "qos.h"

/* Every class sits under one parent class at the full link rate. */
#define BW_QOS_PARENT "1:1"

int bw_qos_script(const struct bw_config *cfg, const char *iface, FILE *out)
{
    const char *dev = iface != NULL ? iface : cfg->iface;
    int i;

    fprintf(out, "tc qdisc add dev %s root handle 1: htb default %u\n",
            dev, cfg->classes[cfg->default_class].classid_minor);
    fprintf(out, "tc class add dev %s parent 1: classid " BW_QOS_PARENT
            " htb rate %" PRIu64 "bit\n", dev, cfg->total_bps);

    for (i = 0; i < cfg->nclasses; i++) {
        const struct bw_class *c = &cfg->classes[i];

        fprintf(out, "tc class add dev %s parent " BW_QOS_PARENT " classid 1:%u htb rate %"
                PRIu64 "bit ceil %" PRIu64 "bit burst %s prio %u\n",
                dev, c->classid_minor, c->rate_bps, cfg->total_bps, c->burst, c->prio);
    }

    for (i = 0; i < cfg->nclasses; i++)
        fprintf(out, "tc qdisc add dev %s parent 1:%u handle %u: sfq perturb 10\n",
                dev, cfg->classes[i].classid_minor, cfg->classes[i].classid_minor);

    /* The default class needs no filter: HTB "default" catches the rest. */
    for (i = 0; i < cfg->nclasses; i++) {
        const struct bw_class *c = &cfg->classes[i];

        if (i == cfg->default_class)
            continue;
        fprintf(out, "tc filter add dev %s parent 1: protocol ip prio 1 u32"
                " match ip dsfield 0x%02x 0xfc flowid 1:%u\n",
                dev, (c->dscp << 2) & 0xfc, c->classid_minor);
    }
    return ferror(out) ? -1 : 0;
}

int bw_qos_clear_script(const char *iface, FILE *out)
{
    fprintf(out, "tc qdisc del dev %s root\n", iface);
    return ferror(out) ? -1 : 0;
}

int bw_qos_change_line(const struct bw_config *cfg, const char *iface, int class_idx,
                       uint64_t rate_bps, FILE *out)
{
    const char *dev = iface != NULL ? iface : cfg->iface;
    const struct bw_class *c;

    if (class_idx < 0 || class_idx >= cfg->nclasses)
        return -1;
    c = &cfg->classes[class_idx];
    fprintf(out, "tc class change dev %s parent " BW_QOS_PARENT " classid 1:%u htb rate %"
            PRIu64 "bit ceil %" PRIu64 "bit burst %s prio %u\n",
            dev, c->classid_minor, rate_bps, cfg->total_bps, c->burst, c->prio);
    return ferror(out) ? -1 : 0;
}
