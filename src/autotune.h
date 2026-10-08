#ifndef BWOPT_AUTOTUNE_H
#define BWOPT_AUTOTUNE_H

#include <stdint.h>

#include "config.h"

/*
 * Computes new HTB guaranteed rates for every configured class.
 *
 * avg_bps[i] is the mean bps of class i over the last window samples,
 * cur_rate[i] its current tc rate. new_rate[i] receives the target rate,
 * equal to cur_rate[i] for classes that do not change. All arrays hold
 * cfg->nclasses entries. Returns the number of classes whose rate changed.
 */
int bw_autotune(const struct bw_config *cfg, const uint64_t *avg_bps,
                const uint64_t *cur_rate, uint64_t *new_rate);

#endif
