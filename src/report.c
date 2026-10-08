#include <inttypes.h>

#include "report.h"

int bw_report_print(const struct bw_store_stat *rows, int n, FILE *out)
{
    int i;

    fprintf(out, "%-10s %-16s %7s %8s %10s %12s %12s\n", "iface", "class", "samples",
            "packets", "bytes", "avg(bit/s)", "peak(bit/s)");
    if (n == 0)
        fprintf(out, "(no samples)\n");
    for (i = 0; i < n; i++) {
        const struct bw_store_stat *r = &rows[i];

        fprintf(out, "%-10s %-16s %7" PRIu64 " %8" PRIu64 " %10" PRIu64 " %12" PRIu64
                " %12" PRIu64 "\n", r->iface, r->cls, r->samples, r->packets, r->bytes,
                r->avg_bps, r->peak_bps);
    }
    return ferror(out) ? -1 : 0;
}
