#ifndef BWOPT_MONITOR_H
#define BWOPT_MONITOR_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "config.h"

/* class_idx of the sample that collects non-IPv4 and out-of-range packets */
#define BW_UNCLASSIFIED -1

/* one row per configured class plus the unclassified row */
#define BW_MONITOR_MAX_SAMPLES (BW_MAX_CLASSES + 1)

struct bw_sample {
    time_t ts;                 /* end of the interval */
    int class_idx;             /* 0..nclasses-1 or BW_UNCLASSIFIED */
    uint64_t packets, bytes, bps;
};

struct bw_counter {
    uint64_t packets, bytes;
};

struct bw_monitor {
    int nclasses;
    time_t last;               /* start of the current interval */
    struct bw_counter cls[BW_MAX_CLASSES];
    struct bw_counter unclassified;
};

/* Clears every counter; the first interval starts at start. */
void bw_monitor_init(struct bw_monitor *m, int nclasses, time_t start);

/* Counts one packet of bytes for class_idx; -1 or an unknown index goes to unclassified. */
void bw_monitor_add(struct bw_monitor *m, int class_idx, size_t bytes);

/*
 * Writes nclasses + 1 samples to out (classes in config order, then
 * unclassified), each with bps = bytes * 8 / (now - interval start), or 0
 * when no time has passed. Resets the counters, starts the next interval at
 * now and returns the number of samples written.
 */
int bw_monitor_flush(struct bw_monitor *m, time_t now, struct bw_sample *out);

#endif
