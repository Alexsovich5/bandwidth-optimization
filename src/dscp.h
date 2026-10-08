#ifndef BWOPT_DSCP_H
#define BWOPT_DSCP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "config.h"

/* Name of the dedicated mangle chain that holds every marking rule. */
#define BW_DSCP_CHAIN "BWOPT"

/*
 * Writes the iptables commands that create the BWOPT mangle chain, hook it
 * into POSTROUTING for egress on iface (cfg->iface when NULL), and add one
 * DSCP rule per application port rule: tcp and udp, --dport and --sport,
 * with ranges written as lo:hi. Signature-only applications get no rule.
 * Returns 0, or -1 on a write error.
 */
int bw_dscp_script(const struct bw_config *cfg, const char *iface, FILE *out);

/* Writes the commands that flush, unhook and delete the BWOPT chain. */
int bw_dscp_clear_script(const struct bw_config *cfg, const char *iface, FILE *out);

/*
 * Sets the DSCP of the IPv4 header at ip_hdr (len bytes available) while
 * keeping the two ECN bits, then recomputes the header checksum.
 * Returns 0, or -1 (header untouched) when len is shorter than the header,
 * the version is not 4, the IHL is invalid or dscp is above 63.
 */
int bw_dscp_rewrite(u_char *ip_hdr, size_t len, uint8_t dscp);

#endif
