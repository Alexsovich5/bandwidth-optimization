#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <check.h>

#include "test_util.h"
#include "../src/store.h"

static char path[64];
static sqlite3 *db;
static struct bw_config cfg;

static const char *names[] = {
    "high_priority", "medium_priority", "low_priority", "best_effort"
};

static void setup(void)
{
    int fd, i;

    strcpy(path, "/tmp/bwopt_store_XXXXXX");
    fd = mkstemp(path);
    ck_assert_msg(fd >= 0, "mkstemp failed");
    close(fd);
    unlink(path);               /* start from a file that does not exist */
    db = NULL;

    memset(&cfg, 0, sizeof cfg);
    cfg.nclasses = 4;
    for (i = 0; i < cfg.nclasses; i++)
        strcpy(cfg.classes[i].name, names[i]);
}

static void teardown(void)
{
    bw_store_close(db);
    db = NULL;
    unlink(path);
}

static int int_query(sqlite3 *h, const char *sql)
{
    sqlite3_stmt *st;
    int v = -1, rc;

    /* not inside ck_assert_int_eq: Check 0.9.8 evaluates its arguments twice */
    rc = sqlite3_prepare_v2(h, sql, -1, &st, NULL);
    ck_assert_int_eq(rc, SQLITE_OK);
    if (sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

static void open_ok(void)
{
    int rc = bw_store_open(path, &db);
    ck_assert_msg(rc == SQLITE_OK, "open: %s", db ? sqlite3_errmsg(db) : "no handle");
}

/* bps of class c (0..3, 4 = unclassified) in interval k */
static const uint64_t bps_tab[5][3] = {
    { 100, 300, 200 },
    { 0, 0, 0 },
    { 10, 20, 40 },
    { 5, 5, 5 },
    { 1000, 0, 7 },
};

static void fill(struct bw_sample *s, int k)
{
    int c;

    for (c = 0; c < 5; c++) {
        s[c].ts = 100 + 10 * k;
        s[c].class_idx = c < 4 ? c : BW_UNCLASSIFIED;
        s[c].packets = (uint64_t)(c + 1) * (k + 1);
        s[c].bytes = bps_tab[c][k] * 10 / 8;
        s[c].bps = bps_tab[c][k];
    }
}

static void put_three_intervals(const char *iface)
{
    struct bw_sample s[5];
    int k, rc;

    for (k = 0; k < 3; k++) {
        fill(s, k);
        rc = bw_store_put(db, iface, &cfg, s, 5);
        ck_assert_msg(rc == SQLITE_OK, "put: %s", sqlite3_errmsg(db));
    }
}

static const struct bw_store_stat *find(const struct bw_store_stat *st, int n,
                                        const char *iface, const char *cls)
{
    int i;

    for (i = 0; i < n; i++)
        if (strcmp(st[i].iface, iface) == 0 && strcmp(st[i].cls, cls) == 0)
            return &st[i];
    ck_assert_msg(0, "no row for %s/%s", iface, cls);
    return NULL;
}

START_TEST(test_open_creates_schema)
{
    open_ok();
    ck_assert_int_eq(access(path, F_OK), 0);
    ck_assert_int_eq(int_query(db, "PRAGMA user_version"), BW_STORE_VERSION);
    ck_assert_int_eq(int_query(db, "PRAGMA user_version"), 1);
    ck_assert_int_eq(int_query(db,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='samples'"), 1);
    ck_assert_int_eq(int_query(db,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='tuning'"), 1);
}
END_TEST

START_TEST(test_reopen_keeps_data)
{
    struct bw_sample s[5];
    int rc;

    open_ok();
    fill(s, 0);
    rc = bw_store_put(db, "eth0", &cfg, s, 5);
    ck_assert_int_eq(rc, SQLITE_OK);
    bw_store_close(db);
    db = NULL;

    open_ok();
    ck_assert_int_eq(int_query(db, "PRAGMA user_version"), 1);
    ck_assert_int_eq(int_query(db, "SELECT COUNT(*) FROM samples"), 5);
}
END_TEST

START_TEST(test_avg_and_peak)
{
    struct bw_store_stat st[16];
    const struct bw_store_stat *r;
    int n;

    open_ok();
    put_three_intervals("eth0");
    ck_assert_int_eq(int_query(db, "SELECT COUNT(*) FROM samples"), 15);

    n = bw_store_query(db, NULL, 0, 0, st, 16);
    ck_assert_int_eq(n, 5);

    /* ordered by class name */
    ck_assert_str_eq(st[0].cls, "best_effort");
    ck_assert_str_eq(st[4].cls, "unclassified");

    r = find(st, n, "eth0", "high_priority");
    ASSERT_U64_EQ(r->samples, 3);
    ASSERT_U64_EQ(r->avg_bps, 200);
    ASSERT_U64_EQ(r->peak_bps, 300);
    ASSERT_U64_EQ(r->packets, 1 + 2 + 3);
    ASSERT_U64_EQ(r->bytes, 125 + 375 + 250);

    r = find(st, n, "eth0", "medium_priority");
    ASSERT_U64_EQ(r->avg_bps, 0);
    ASSERT_U64_EQ(r->peak_bps, 0);

    r = find(st, n, "eth0", "low_priority");
    ASSERT_U64_EQ(r->avg_bps, 23);      /* 70 / 3, rounded down */
    ASSERT_U64_EQ(r->peak_bps, 40);

    r = find(st, n, "eth0", "best_effort");
    ASSERT_U64_EQ(r->avg_bps, 5);
    ASSERT_U64_EQ(r->peak_bps, 5);
    ASSERT_U64_EQ(r->packets, 4 + 8 + 12);

    r = find(st, n, "eth0", "unclassified");
    ASSERT_U64_EQ(r->avg_bps, 335);     /* 1007 / 3 */
    ASSERT_U64_EQ(r->peak_bps, 1000);
}
END_TEST

START_TEST(test_last_n_and_since)
{
    struct bw_store_stat st[16];
    const struct bw_store_stat *r;
    int n;

    open_ok();
    put_three_intervals("eth0");

    /* last 2 samples are ts 110 and 120 */
    n = bw_store_query(db, "eth0", 0, 2, st, 16);
    ck_assert_int_eq(n, 5);
    r = find(st, n, "eth0", "high_priority");
    ASSERT_U64_EQ(r->samples, 2);
    ASSERT_U64_EQ(r->avg_bps, 250);
    ASSERT_U64_EQ(r->peak_bps, 300);
    r = find(st, n, "eth0", "unclassified");
    ASSERT_U64_EQ(r->avg_bps, 3);
    ASSERT_U64_EQ(r->peak_bps, 7);

    /* since 120 keeps only the last interval */
    n = bw_store_query(db, "eth0", 120, 0, st, 16);
    ck_assert_int_eq(n, 5);
    r = find(st, n, "eth0", "low_priority");
    ASSERT_U64_EQ(r->samples, 1);
    ASSERT_U64_EQ(r->avg_bps, 40);

    /* nothing after the last interval */
    n = bw_store_query(db, "eth0", 121, 0, st, 16);
    ck_assert_int_eq(n, 0);
}
END_TEST

START_TEST(test_iface_filter_and_max)
{
    struct bw_store_stat st[16];
    int n;

    open_ok();
    put_three_intervals("eth0");
    put_three_intervals("eth1");

    n = bw_store_query(db, NULL, 0, 0, st, 16);
    ck_assert_int_eq(n, 10);
    ck_assert_str_eq(st[0].iface, "eth0");
    ck_assert_str_eq(st[9].iface, "eth1");

    n = bw_store_query(db, "eth1", 0, 0, st, 16);
    ck_assert_int_eq(n, 5);
    ck_assert_str_eq(st[0].iface, "eth1");
    ck_assert_str_eq(st[4].iface, "eth1");

    /* only 2 slots: the count still reports every pair */
    memset(st, 0, sizeof st);
    n = bw_store_query(db, NULL, 0, 0, st, 2);
    ck_assert_int_eq(n, 10);
    ck_assert_str_eq(st[1].cls, "high_priority");
    ck_assert_str_eq(st[2].cls, "");
}
END_TEST

START_TEST(test_duplicate_rejected)
{
    struct bw_sample s[5];
    int rc;

    open_ok();
    fill(s, 0);
    rc = bw_store_put(db, "eth0", &cfg, s, 5);
    ck_assert_int_eq(rc, SQLITE_OK);

    rc = bw_store_put(db, "eth0", &cfg, s, 5);
    ck_assert_int_eq(rc, SQLITE_CONSTRAINT);
    ck_assert_int_eq(int_query(db, "SELECT COUNT(*) FROM samples"), 5);

    /* a duplicate inside a new batch rolls the whole batch back */
    fill(s, 1);
    s[4] = s[0];
    rc = bw_store_put(db, "eth0", &cfg, s, 5);
    ck_assert_int_eq(rc, SQLITE_CONSTRAINT);
    ck_assert_int_eq(int_query(db, "SELECT COUNT(*) FROM samples"), 5);

    /* the same (ts, class) on another interface is fine */
    fill(s, 0);
    rc = bw_store_put(db, "eth1", &cfg, s, 5);
    ck_assert_int_eq(rc, SQLITE_OK);
    ck_assert_int_eq(int_query(db, "SELECT COUNT(*) FROM samples"), 10);
}
END_TEST

START_TEST(test_out_of_range_index_stored_as_unclassified)
{
    struct bw_sample s[1];
    int rc;

    open_ok();
    memset(s, 0, sizeof s);
    s[0].ts = 5;
    s[0].class_idx = 7;         /* config has 4 classes */
    s[0].bps = 9;
    rc = bw_store_put(db, "eth0", &cfg, s, 1);
    ck_assert_int_eq(rc, SQLITE_OK);
    ck_assert_int_eq(int_query(db,
        "SELECT COUNT(*) FROM samples WHERE class='unclassified' AND bps=9"), 1);
}
END_TEST

START_TEST(test_tuning_round_trip)
{
    uint64_t rate = 0;
    int rc, r;

    open_ok();

    r = bw_store_latest_rate(db, "eth0", "best_effort", &rate);
    ck_assert_int_eq(r, 0);

    rc = bw_store_tuning(db, 100, "eth0", "best_effort", 10000000, 5000000);
    ck_assert_int_eq(rc, SQLITE_OK);
    rc = bw_store_tuning(db, 200, "eth0", "best_effort", 5000000, 7500000);
    ck_assert_int_eq(rc, SQLITE_OK);
    /* larger than 32 bits */
    rc = bw_store_tuning(db, 150, "eth1", "best_effort", 10000000000ULL, 12000000000ULL);
    ck_assert_int_eq(rc, SQLITE_OK);

    r = bw_store_latest_rate(db, "eth0", "best_effort", &rate);
    ck_assert_int_eq(r, 1);
    ASSERT_U64_EQ(rate, 7500000);

    r = bw_store_latest_rate(db, "eth1", "best_effort", &rate);
    ck_assert_int_eq(r, 1);
    ASSERT_U64_EQ(rate, 12000000000ULL);

    r = bw_store_latest_rate(db, "eth0", "high_priority", &rate);
    ck_assert_int_eq(r, 0);
    ck_assert_int_eq(int_query(db,
        "SELECT old_rate FROM tuning WHERE ts=200"), 5000000);

    /* same ts: the later row wins */
    rc = bw_store_tuning(db, 200, "eth0", "best_effort", 7500000, 6000000);
    ck_assert_int_eq(rc, SQLITE_OK);
    r = bw_store_latest_rate(db, "eth0", "best_effort", &rate);
    ck_assert_int_eq(r, 1);
    ASSERT_U64_EQ(rate, 6000000);
}
END_TEST

START_TEST(test_open_missing_dir_fails)
{
    int rc;

    rc = bw_store_open("/nonexistent/dir/m.db", &db);
    ck_assert_int_ne(rc, SQLITE_OK);
    ck_assert_msg(db != NULL, "no handle for the error message");
    ck_assert_str_eq(sqlite3_errmsg(db), "unable to open database file");
}
END_TEST

/*
 * bw_store_query_all sizes its result itself: 5 interfaces x 5 classes is
 * more pairs than its first allocation, and every pair must come back.
 */
START_TEST(test_query_all_allocates_every_row)
{
    static const char *ifaces[] = { "eth0", "eth1", "eth2", "eth3", "eth4" };
    struct bw_store_stat *rows = (struct bw_store_stat *)1;
    int i, n;

    open_ok();
    n = bw_store_query_all(db, NULL, 0, 0, &rows);
    ck_assert_int_eq(n, 0);
    ck_assert_msg(rows == NULL, "no rows must give a NULL array");

    for (i = 0; i < 5; i++)
        put_three_intervals(ifaces[i]);
    n = bw_store_query_all(db, NULL, 0, 0, &rows);
    ck_assert_int_eq(n, 25);
    ck_assert(rows != NULL);
    for (i = 0; i < 5; i++) {
        const struct bw_store_stat *r = find(rows, n, ifaces[i], "high_priority");

        ASSERT_U64_EQ(r->samples, 3);
        ASSERT_U64_EQ(r->avg_bps, 200);
        ASSERT_U64_EQ(r->peak_bps, 300);
        find(rows, n, ifaces[i], "unclassified");
    }
    free(rows);

    n = bw_store_query_all(db, "eth3", 0, 2, &rows);
    ck_assert_int_eq(n, 5);
    ck_assert_str_eq(rows[0].iface, "eth3");
    free(rows);
}
END_TEST

Suite *store_suite(void)
{
    Suite *s = suite_create("store");
    TCase *tc = tcase_create("core");

    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_open_creates_schema);
    tcase_add_test(tc, test_reopen_keeps_data);
    tcase_add_test(tc, test_avg_and_peak);
    tcase_add_test(tc, test_last_n_and_since);
    tcase_add_test(tc, test_iface_filter_and_max);
    tcase_add_test(tc, test_duplicate_rejected);
    tcase_add_test(tc, test_out_of_range_index_stored_as_unclassified);
    tcase_add_test(tc, test_tuning_round_trip);
    tcase_add_test(tc, test_open_missing_dir_fails);
    tcase_add_test(tc, test_query_all_allocates_every_row);
    suite_add_tcase(s, tc);
    return s;
}
