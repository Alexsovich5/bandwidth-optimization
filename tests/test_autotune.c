#include <stdint.h>
#include <string.h>
#include <check.h>

#include "test_util.h"
#include "../src/config.h"
#include "../src/autotune.h"

#define SHIPPED "config/policies.conf"
#define MBIT 1000000ULL

/* Class indexes in the shipped config. */
enum { HIGH = 0, MEDIUM = 1, LOW = 2, BEST = 3 };

static struct bw_config cfg;

static void load_shipped(void)
{
    char err[256];

    ck_assert_msg(bw_config_load(SHIPPED, &cfg, err, sizeof err) == 0, "%s", err);
    ck_assert_int_eq(cfg.nclasses, 4);
}

/* Average of pct percent of each class's configured rate. */
static void set_util(uint64_t *avg, unsigned h, unsigned m, unsigned l, unsigned b)
{
    avg[HIGH] = cfg.classes[HIGH].rate_bps * h / 100;
    avg[MEDIUM] = cfg.classes[MEDIUM].rate_bps * m / 100;
    avg[LOW] = cfg.classes[LOW].rate_bps * l / 100;
    avg[BEST] = cfg.classes[BEST].rate_bps * b / 100;
}

static void set_rates(uint64_t *r, uint64_t h, uint64_t m, uint64_t l, uint64_t b)
{
    r[HIGH] = h;
    r[MEDIUM] = m;
    r[LOW] = l;
    r[BEST] = b;
}

static void set_configured(uint64_t *r)
{
    int i;

    for (i = 0; i < cfg.nclasses; i++)
        r[i] = cfg.classes[i].rate_bps;
}

START_TEST(test_neutral_load_changes_nothing)
{
    uint64_t avg[BW_MAX_CLASSES], cur[BW_MAX_CLASSES], out[BW_MAX_CLASSES];
    int n;

    load_shipped();
    set_util(avg, 60, 60, 60, 60);
    set_configured(cur);
    n = bw_autotune(&cfg, avg, cur, out);

    ck_assert_int_eq(n, 0);
    ASSERT_U64_EQ(out[HIGH], 30 * MBIT);
    ASSERT_U64_EQ(out[MEDIUM], 40 * MBIT);
    ASSERT_U64_EQ(out[LOW], 20 * MBIT);
    ASSERT_U64_EQ(out[BEST], 10 * MBIT);
}
END_TEST

START_TEST(test_idle_best_effort_lends_to_high_priority)
{
    uint64_t avg[BW_MAX_CLASSES], cur[BW_MAX_CLASSES], out[BW_MAX_CLASSES];
    int n;

    load_shipped();
    set_util(avg, 100, 60, 60, 0);
    set_configured(cur);
    n = bw_autotune(&cfg, avg, cur, out);

    ck_assert_int_eq(n, 2);
    ASSERT_U64_EQ(out[HIGH], 35000000);
    ASSERT_U64_EQ(out[MEDIUM], 40000000);
    ASSERT_U64_EQ(out[LOW], 20000000);
    ASSERT_U64_EQ(out[BEST], 5000000);
}
END_TEST

START_TEST(test_rebalance_is_idempotent)
{
    uint64_t avg[BW_MAX_CLASSES], cur[BW_MAX_CLASSES], out[BW_MAX_CLASSES];
    int n;

    load_shipped();
    set_util(avg, 100, 60, 60, 0);
    set_rates(cur, 35000000, 40000000, 20000000, 5000000);
    n = bw_autotune(&cfg, avg, cur, out);

    ck_assert_int_eq(n, 0);
    ASSERT_U64_EQ(out[HIGH], 35000000);
    ASSERT_U64_EQ(out[BEST], 5000000);
}
END_TEST

START_TEST(test_pool_split_by_configured_share)
{
    uint64_t avg[BW_MAX_CLASSES], cur[BW_MAX_CLASSES], out[BW_MAX_CLASSES];
    int n;

    load_shipped();
    set_util(avg, 100, 95, 60, 0);
    set_configured(cur);
    n = bw_autotune(&cfg, avg, cur, out);

    ck_assert_int_eq(n, 3);
    ASSERT_U64_EQ(out[HIGH], 32142000);
    ASSERT_U64_EQ(out[MEDIUM], 42857000);
    ASSERT_U64_EQ(out[LOW], 20000000);
    ASSERT_U64_EQ(out[BEST], 5000000);
}
END_TEST

START_TEST(test_donor_keeps_floor_and_headroom)
{
    uint64_t avg[BW_MAX_CLASSES], cur[BW_MAX_CLASSES], out[BW_MAX_CLASSES];
    int i, n;

    load_shipped();
    /* best_effort at 40%: 1.2 x 4 Mbit = 4.8 Mbit, the floor of 5 Mbit wins.
     * low_priority at 45%: 1.2 x 9 Mbit = 10.8 Mbit, above its 10 Mbit floor. */
    set_util(avg, 100, 100, 45, 40);
    set_configured(cur);
    n = bw_autotune(&cfg, avg, cur, out);

    ck_assert_int_eq(n, 4);
    ASSERT_U64_EQ(out[BEST], 5000000);
    ASSERT_U64_EQ(out[LOW], 10800000);
    for (i = 0; i < cfg.nclasses; i++)
        ck_assert_msg(out[i] >= cfg.classes[i].rate_bps / 2,
                      "class %d below its floor", i);
}
END_TEST

START_TEST(test_drift_back_to_configured_rates)
{
    static const uint64_t high[] = { 32500000, 30000000, 30000000, 30000000, 30000000 };
    static const uint64_t best[] = { 7500000, 8750000, 9375000, 10000000, 10000000 };
    static const int changed[] = { 2, 2, 1, 1, 0 };
    uint64_t avg[BW_MAX_CLASSES], cur[BW_MAX_CLASSES], out[BW_MAX_CLASSES];
    int step, n;

    load_shipped();
    set_util(avg, 60, 60, 60, 60);
    set_rates(cur, 35000000, 40000000, 20000000, 5000000);
    for (step = 0; step < 5; step++) {
        n = bw_autotune(&cfg, avg, cur, out);
        ck_assert_msg(n == changed[step], "step %d: %d changes, expected %d",
                      step, n, changed[step]);
        ASSERT_U64_EQ(out[HIGH], high[step]);
        ASSERT_U64_EQ(out[BEST], best[step]);
        ASSERT_U64_EQ(out[MEDIUM], 40000000);
        ASSERT_U64_EQ(out[LOW], 20000000);
        memcpy(cur, out, sizeof cur);
    }
}
END_TEST

START_TEST(test_small_change_suppressed_by_hysteresis)
{
    uint64_t avg[BW_MAX_CLASSES], cur[BW_MAX_CLASSES], out[BW_MAX_CLASSES];
    int n;

    load_shipped();
    /* The re-balance target for high_priority is 35 Mbit, 0.9 Mbit (3% of
     * the configured 30 Mbit) above its current rate: below the 5% threshold. */
    set_util(avg, 100, 60, 60, 0);
    set_rates(cur, 34100000, 40000000, 20000000, 5000000);
    n = bw_autotune(&cfg, avg, cur, out);

    ck_assert_int_eq(n, 0);
    ASSERT_U64_EQ(out[HIGH], 34100000);

    /* Drift back: low_priority 0.6 Mbit (3% of 20 Mbit) under its configured rate. */
    set_util(avg, 60, 60, 60, 60);
    set_rates(cur, 30000000, 40000000, 19400000, 10000000);
    n = bw_autotune(&cfg, avg, cur, out);

    ck_assert_int_eq(n, 0);
    ASSERT_U64_EQ(out[LOW], 19400000);
}
END_TEST

static uint32_t lcg_state;

static uint32_t lcg(void)
{
    lcg_state = lcg_state * 1103515245u + 12345u;
    return (lcg_state >> 8) & 0xffffff;
}

static uint64_t rnd(uint64_t n)
{
    uint64_t r = ((uint64_t)lcg() << 24) | lcg();
    return n ? r % n : 0;
}

START_TEST(test_random_inputs_keep_sum_and_floors)
{
    uint64_t avg[BW_MAX_CLASSES], cur[BW_MAX_CLASSES], out[BW_MAX_CLASSES];
    uint64_t floor_bps[BW_MAX_CLASSES];
    int iter, i;

    lcg_state = 0x9e3779b9u;
    for (iter = 0; iter < 1000; iter++) {
        struct bw_config c;
        unsigned left = 100;
        uint64_t sum_floor = 0, slack, sum_out = 0;

        memset(&c, 0, sizeof c);
        c.total_bps = (1 + rnd(10000)) * 100000;
        c.nclasses = 1 + (int)rnd(BW_MAX_CLASSES);
        c.tune.window = 10;
        c.tune.low_watermark = 10 + (unsigned)rnd(50);
        c.tune.high_watermark = c.tune.low_watermark + 1 + (unsigned)rnd(40);
        c.tune.min_share = (unsigned)rnd(101);
        c.tune.hysteresis = (unsigned)rnd(21);
        for (i = 0; i < c.nclasses; i++) {
            unsigned pct = i == c.nclasses - 1 ? left : (unsigned)rnd(left + 1);

            left -= pct;
            c.classes[i].pct = pct;
            c.classes[i].rate_bps = c.total_bps * pct / 100;
            floor_bps[i] = c.classes[i].rate_bps * c.tune.min_share / 100;
            sum_floor += floor_bps[i];
            avg[i] = rnd(c.classes[i].rate_bps * 2 + 1);
        }
        /* current rates: each at or above its floor, sum within total */
        slack = c.total_bps - sum_floor;
        for (i = 0; i < c.nclasses; i++) {
            uint64_t extra = rnd(slack + 1);

            slack -= extra;
            cur[i] = floor_bps[i] + extra;
        }

        bw_autotune(&c, avg, cur, out);

        for (i = 0; i < c.nclasses; i++) {
            sum_out += out[i];
            ck_assert_msg(out[i] >= floor_bps[i],
                          "iter %d class %d: %llu below floor %llu", iter, i,
                          (unsigned long long)out[i], (unsigned long long)floor_bps[i]);
        }
        ck_assert_msg(sum_out <= c.total_bps, "iter %d: sum %llu > total %llu", iter,
                      (unsigned long long)sum_out, (unsigned long long)c.total_bps);
    }
}
END_TEST

Suite *autotune_suite(void)
{
    Suite *s = suite_create("autotune");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_neutral_load_changes_nothing);
    tcase_add_test(tc, test_idle_best_effort_lends_to_high_priority);
    tcase_add_test(tc, test_rebalance_is_idempotent);
    tcase_add_test(tc, test_pool_split_by_configured_share);
    tcase_add_test(tc, test_donor_keeps_floor_and_headroom);
    tcase_add_test(tc, test_drift_back_to_configured_rates);
    tcase_add_test(tc, test_small_change_suppressed_by_hysteresis);
    tcase_add_test(tc, test_random_inputs_keep_sum_and_floors);
    suite_add_tcase(s, tc);
    return s;
}
