#include <stdint.h>
#include <check.h>

#include "test_util.h"
#include "../src/monitor.h"

/* flush must not appear inside ck_assert_int_eq: Check 0.9.8 evaluates
 * the arguments twice, once more for the failure message */
#define GB 1000000000ULL

static struct bw_monitor mon;
static struct bw_sample out[BW_MONITOR_MAX_SAMPLES];

START_TEST(test_known_bytes_give_exact_bps)
{
    int n;

    bw_monitor_init(&mon, 3, 1000);
    bw_monitor_add(&mon, 0, 1250000);   /* 10 Mbit over 10 s = 1 Mbit/s */
    bw_monitor_add(&mon, 1, 500);
    bw_monitor_add(&mon, 1, 750);       /* 10000 bit over 10 s = 1000 bit/s */
    bw_monitor_add(&mon, 2, 3);         /* 24 bit over 10 s = 2 bit/s (floor) */
    n = bw_monitor_flush(&mon, 1010, out);

    ck_assert_int_eq(n, 4);
    ck_assert_int_eq(out[0].class_idx, 0);
    ck_assert_int_eq(out[1].class_idx, 1);
    ck_assert_int_eq(out[2].class_idx, 2);
    ck_assert_int_eq((int)out[0].ts, 1010);
    ASSERT_U64_EQ(out[0].packets, 1);
    ASSERT_U64_EQ(out[0].bytes, 1250000);
    ASSERT_U64_EQ(out[0].bps, 1000000);
    ASSERT_U64_EQ(out[1].packets, 2);
    ASSERT_U64_EQ(out[1].bytes, 1250);
    ASSERT_U64_EQ(out[1].bps, 1000);
    ASSERT_U64_EQ(out[2].packets, 1);
    ASSERT_U64_EQ(out[2].bytes, 3);
    ASSERT_U64_EQ(out[2].bps, 2);
}
END_TEST

START_TEST(test_minus_one_is_unclassified)
{
    int n;

    bw_monitor_init(&mon, 2, 0);
    bw_monitor_add(&mon, -1, 100);
    bw_monitor_add(&mon, -1, 60);
    n = bw_monitor_flush(&mon, 4, out);

    ck_assert_int_eq(n, 3);
    ck_assert_int_eq(out[2].class_idx, BW_UNCLASSIFIED);
    ck_assert_int_eq(out[2].class_idx, -1);
    ASSERT_U64_EQ(out[2].packets, 2);
    ASSERT_U64_EQ(out[2].bytes, 160);
    ASSERT_U64_EQ(out[2].bps, 320);
    ASSERT_U64_EQ(out[0].packets, 0);
    ASSERT_U64_EQ(out[1].packets, 0);
}
END_TEST

START_TEST(test_out_of_range_index_is_unclassified)
{
    int n;

    bw_monitor_init(&mon, 2, 0);
    bw_monitor_add(&mon, 2, 10);
    bw_monitor_add(&mon, 99, 10);
    n = bw_monitor_flush(&mon, 1, out);
    ck_assert_int_eq(n, 3);
    ASSERT_U64_EQ(out[2].packets, 2);
    ASSERT_U64_EQ(out[0].packets, 0);
    ASSERT_U64_EQ(out[1].packets, 0);
}
END_TEST

START_TEST(test_zero_traffic_rows)
{
    int n, i;

    bw_monitor_init(&mon, 5, 100);
    n = bw_monitor_flush(&mon, 110, out);

    ck_assert_int_eq(n, 6);
    for (i = 0; i < n; i++) {
        ck_assert_int_eq(out[i].class_idx, i < 5 ? i : -1);
        ck_assert_int_eq((int)out[i].ts, 110);
        ASSERT_U64_EQ(out[i].packets, 0);
        ASSERT_U64_EQ(out[i].bytes, 0);
        ASSERT_U64_EQ(out[i].bps, 0);
    }
}
END_TEST

START_TEST(test_zero_elapsed_guarded)
{
    int n;

    bw_monitor_init(&mon, 1, 500);
    bw_monitor_add(&mon, 0, 1000);
    n = bw_monitor_flush(&mon, 500, out);
    ck_assert_int_eq(n, 2);
    ASSERT_U64_EQ(out[0].bytes, 1000);
    ASSERT_U64_EQ(out[0].bps, 0);

    /* a clock that steps backwards is treated the same way */
    bw_monitor_add(&mon, 0, 1000);
    n = bw_monitor_flush(&mon, 400, out);
    ck_assert_int_eq(n, 2);
    ASSERT_U64_EQ(out[0].bytes, 1000);
    ASSERT_U64_EQ(out[0].bps, 0);
}
END_TEST

START_TEST(test_counters_reset_after_flush)
{
    int n;

    bw_monitor_init(&mon, 2, 0);
    bw_monitor_add(&mon, 0, 400);
    bw_monitor_add(&mon, 1, 800);
    bw_monitor_add(&mon, -1, 80);
    n = bw_monitor_flush(&mon, 2, out);
    ck_assert_int_eq(n, 3);
    ASSERT_U64_EQ(out[0].bps, 1600);

    bw_monitor_add(&mon, 1, 100);
    n = bw_monitor_flush(&mon, 6, out);
    ck_assert_int_eq(n, 3);
    /* second interval runs from the previous flush, 2 -> 6 */
    ASSERT_U64_EQ(out[0].packets, 0);
    ASSERT_U64_EQ(out[0].bytes, 0);
    ASSERT_U64_EQ(out[0].bps, 0);
    ASSERT_U64_EQ(out[1].packets, 1);
    ASSERT_U64_EQ(out[1].bytes, 100);
    ASSERT_U64_EQ(out[1].bps, 200);
    ASSERT_U64_EQ(out[2].packets, 0);
    ASSERT_U64_EQ(out[2].bytes, 0);
}
END_TEST

START_TEST(test_no_overflow_at_10gb)
{
    int i, n;

    bw_monitor_init(&mon, 1, 0);
    /* 10 GB arrives in 1 GB chunks, more than 32 bits can hold */
    for (i = 0; i < 10; i++)
        bw_monitor_add(&mon, 0, (size_t)GB);
    n = bw_monitor_flush(&mon, 10, out);
    ck_assert_int_eq(n, 2);
    ASSERT_U64_EQ(out[0].packets, 10);
    ASSERT_U64_EQ(out[0].bytes, 10 * GB);
    ASSERT_U64_EQ(out[0].bps, 8 * GB);
}
END_TEST

Suite *monitor_suite(void)
{
    Suite *s = suite_create("monitor");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_known_bytes_give_exact_bps);
    tcase_add_test(tc, test_minus_one_is_unclassified);
    tcase_add_test(tc, test_out_of_range_index_is_unclassified);
    tcase_add_test(tc, test_zero_traffic_rows);
    tcase_add_test(tc, test_zero_elapsed_guarded);
    tcase_add_test(tc, test_counters_reset_after_flush);
    tcase_add_test(tc, test_no_overflow_at_10gb);
    suite_add_tcase(s, tc);
    return s;
}
