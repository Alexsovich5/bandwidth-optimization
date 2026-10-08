#ifndef BWOPT_CLASSIFIER_H
#define BWOPT_CLASSIFIER_H

#include "config.h"
#include "packet.h"

/*
 * Returns the index of the class a decoded packet belongs to, or -1 for a
 * non-IPv4 frame (reported as "unclassified").
 *
 * Order for IPv4 packets:
 *   1. payload signature: the first application (config order) whose
 *      <app>.signature equals bw_signature_match() of a TCP/UDP payload
 *   2. port rules: the first application whose port or port range contains
 *      the destination port, then the first one containing the source port
 *   3. default_class
 */
int bw_classify(const struct bw_config *cfg, const struct bw_packet *pkt);

#endif
