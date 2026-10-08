#include <string.h>

#include "monitor.h"

void bw_monitor_init(struct bw_monitor *m, int nclasses, time_t start)
{
    memset(m, 0, sizeof *m);
    if (nclasses < 0)
        nclasses = 0;
    if (nclasses > BW_MAX_CLASSES)
        nclasses = BW_MAX_CLASSES;
    m->nclasses = nclasses;
    m->last = start;
}

void bw_monitor_add(struct bw_monitor *m, int class_idx, size_t bytes)
{
    struct bw_counter *c;

    if (class_idx >= 0 && class_idx < m->nclasses)
        c = &m->cls[class_idx];
    else
        c = &m->unclassified;
    c->packets++;
    c->bytes += (uint64_t)bytes;
}

static void fill(struct bw_sample *s, time_t now, int class_idx,
                 const struct bw_counter *c, uint64_t elapsed)
{
    s->ts = now;
    s->class_idx = class_idx;
    s->packets = c->packets;
    s->bytes = c->bytes;
    s->bps = elapsed ? c->bytes * 8 / elapsed : 0;
}

int bw_monitor_flush(struct bw_monitor *m, time_t now, struct bw_sample *out)
{
    uint64_t elapsed = now > m->last ? (uint64_t)(now - m->last) : 0;
    int i;

    for (i = 0; i < m->nclasses; i++)
        fill(&out[i], now, i, &m->cls[i], elapsed);
    fill(&out[i], now, BW_UNCLASSIFIED, &m->unclassified, elapsed);

    memset(m->cls, 0, sizeof m->cls);
    memset(&m->unclassified, 0, sizeof m->unclassified);
    m->last = now;
    return m->nclasses + 1;
}
