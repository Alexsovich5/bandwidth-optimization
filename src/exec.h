#ifndef BWOPT_EXEC_H
#define BWOPT_EXEC_H

#include <stdio.h>

#define BW_EXEC_DRY_RUN       0x01  /* print the lines to dry_out, run nothing */
#define BW_EXEC_IGNORE_ERRORS 0x02  /* run every line, discard stderr, return 0 */

/*
 * Runs each non-empty line of script through /bin/sh -c, in order.
 * Strict mode (no flags): stops at the first command that fails, prints the
 * failing command to stderr and returns its exit status (or -1 when it could
 * not be run or was killed by a signal). Returns 0 when every line succeeds.
 */
int bw_exec_run(const char *script, int flags, FILE *dry_out);

#endif
