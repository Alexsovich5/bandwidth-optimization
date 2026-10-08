#ifndef BWOPT_REPORT_H
#define BWOPT_REPORT_H

#include <stdio.h>

#include "store.h"

/*
 * Prints a header and one line per aggregated (iface, class) row, or
 * "(no samples)" when n is 0. Returns 0, or -1 on a write error.
 */
int bw_report_print(const struct bw_store_stat *rows, int n, FILE *out);

#endif
