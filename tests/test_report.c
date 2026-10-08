#include <stdio.h>
#include <string.h>
#include <check.h>

#include "test_util.h"
#include "../src/report.h"

/* Renders rows through a temporary file and returns the text. */
static const char *render(const struct bw_store_stat *rows, int n)
{
    static char buf[4096];
    FILE *f = tmpfile();
    size_t len;
    int rc;

    ck_assert_msg(f != NULL, "tmpfile failed");
    rc = bw_report_print(rows, n, f);
    ck_assert_int_eq(rc, 0);
    rewind(f);
    len = fread(buf, 1, sizeof buf - 1, f);
    buf[len] = '\0';
    fclose(f);
    return buf;
}

static void set(struct bw_store_stat *s, const char *iface, const char *cls,
                uint64_t samples, uint64_t packets, uint64_t bytes,
                uint64_t avg, uint64_t peak)
{
    memset(s, 0, sizeof *s);
    strcpy(s->iface, iface);
    strcpy(s->cls, cls);
    s->samples = samples;
    s->packets = packets;
    s->bytes = bytes;
    s->avg_bps = avg;
    s->peak_bps = peak;
}

START_TEST(test_known_rows_give_exact_table)
{
    struct bw_store_stat rows[3];

    set(&rows[0], "eth0", "best_effort", 2, 5, 538, 2152, 3008);
    set(&rows[1], "eth0", "high_priority", 2, 5, 776, 3104, 5408);
    set(&rows[2], "eth1", "unclassified", 1, 2, 104, 832, 832);

    ck_assert_str_eq(render(rows, 3),
        "iface      class            samples  packets      bytes   avg(bit/s)  peak(bit/s)\n"
        "eth0       best_effort            2        5        538         2152         3008\n"
        "eth0       high_priority          2        5        776         3104         5408\n"
        "eth1       unclassified           1        2        104          832          832\n");
}
END_TEST

START_TEST(test_large_counters_are_printed_in_full)
{
    struct bw_store_stat row;

    /* 10 GB and 10 Gbit/s do not fit in 32 bits */
    set(&row, "eth0", "best_effort", 1, 7000000, 10000000000ULL,
        10000000000ULL, 10000000000ULL);
    ck_assert_str_eq(render(&row, 1),
        "iface      class            samples  packets      bytes   avg(bit/s)  peak(bit/s)\n"
        "eth0       best_effort            1  7000000 10000000000  10000000000  10000000000\n");
}
END_TEST

START_TEST(test_no_rows_prints_header_and_note)
{
    ck_assert_str_eq(render(NULL, 0),
        "iface      class            samples  packets      bytes   avg(bit/s)  peak(bit/s)\n"
        "(no samples)\n");
}
END_TEST

Suite *report_suite(void)
{
    Suite *s = suite_create("report");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_known_rows_give_exact_table);
    tcase_add_test(tc, test_large_counters_are_printed_in_full);
    tcase_add_test(tc, test_no_rows_prints_header_and_note);
    suite_add_tcase(s, tc);
    return s;
}
