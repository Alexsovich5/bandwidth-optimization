#ifndef BWOPT_QOS_H
#define BWOPT_QOS_H

#include <stdint.h>
#include <stdio.h>

#include "config.h"

/*
 * Writes the tc commands that build the HTB tree on iface (cfg->iface when
 * NULL): a root qdisc whose default is the default class, parent class 1:1
 * at total_bandwidth, one child class 1:N per traffic class (rate = share of
 * the total, ceil = total, the configured burst, prio = file order), an SFQ
 * leaf under every child, and one u32 dsfield filter per non-default class.
 * Returns 0, or -1 on a write error.
 */
int bw_qos_script(const struct bw_config *cfg, const char *iface, FILE *out);

/* Writes the command that removes the root qdisc (and the whole tree). */
int bw_qos_clear_script(const char *iface, FILE *out);

/*
 * Writes the "tc class change" command that sets the guaranteed rate of
 * class class_idx on iface (cfg->iface when NULL) to rate_bps. The command
 * repeats ceil, burst and prio from the config, because tc class change
 * resets any HTB parameter it is not given. Returns 0, or -1 for an index
 * outside the config or a write error.
 */
int bw_qos_change_line(const struct bw_config *cfg, const char *iface, int class_idx,
                       uint64_t rate_bps, FILE *out);

#endif
