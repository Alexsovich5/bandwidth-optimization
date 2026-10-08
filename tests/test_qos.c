#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "../src/config.h"
#include "../src/qos.h"

#define SHIPPED   "config/policies.conf"
#define ONE_CLASS "tests/fixtures/conf/one_class.conf"
#define UNDER_100 "tests/fixtures/conf/under_100.conf"
#define GOLDEN    "tests/golden/policies.tc"

static void load(const char *path, struct bw_config *cfg)
{
    char err[256] = "";

    ck_assert_msg(bw_config_load(path, cfg, err, sizeof err) == 0, "%s: %s", path, err);
}

/* Reads a whole stream into a malloc'd, NUL-terminated buffer. */
static char *slurp(FILE *f)
{
    size_t cap = 4096, len = 0, n;
    char *buf = malloc(cap);

    ck_assert(buf != NULL);
    rewind(f);
    while ((n = fread(buf + len, 1, cap - len - 1, f)) > 0) {
        len += n;
        if (len + 1 == cap) {
            cap *= 2;
            buf = realloc(buf, cap);
            ck_assert(buf != NULL);
        }
    }
    buf[len] = '\0';
    return buf;
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *s;

    ck_assert_msg(f != NULL, "cannot open %s", path);
    s = slurp(f);
    fclose(f);
    return s;
}

static char *qos_script(const struct bw_config *cfg, const char *iface)
{
    FILE *f = tmpfile();
    char *s;
    int rc;

    ck_assert(f != NULL);
    rc = bw_qos_script(cfg, iface, f);   /* ck_assert_int_eq evaluates twice */
    ck_assert_int_eq(rc, 0);
    s = slurp(f);
    fclose(f);
    return s;
}

static int count_lines(const char *s, const char *needle)
{
    int n = 0;
    const char *p = s;

    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += strlen(needle);
    }
    return n;
}

START_TEST(test_script_matches_golden)
{
    struct bw_config cfg;
    char *got, *want;

    load(SHIPPED, &cfg);
    got = qos_script(&cfg, NULL);
    want = read_file(GOLDEN);
    ck_assert_str_eq(got, want);
    free(got);
    free(want);
}
END_TEST

START_TEST(test_interface_override)
{
    struct bw_config cfg;
    char *got;

    load(SHIPPED, &cfg);
    got = qos_script(&cfg, "bw0");
    ck_assert_msg(strstr(got, "tc qdisc add dev bw0 root handle 1: htb default 40\n") != NULL,
                  "no bw0 root qdisc in:\n%s", got);
    ck_assert_msg(strstr(got, "eth0") == NULL, "eth0 still present:\n%s", got);
    ck_assert_int_eq(count_lines(got, "dev bw0 "), 13);
    free(got);
}
END_TEST

START_TEST(test_under_100_keeps_ceil_at_total)
{
    struct bw_config cfg;
    char *got;

    load(UNDER_100, &cfg);
    got = qos_script(&cfg, NULL);
    ck_assert_str_eq(got,
        "tc qdisc add dev eth1 root handle 1: htb default 20\n"
        "tc class add dev eth1 parent 1: classid 1:1 htb rate 50000000bit\n"
        "tc class add dev eth1 parent 1:1 classid 1:10 htb rate 10000000bit"
        " ceil 50000000bit burst 32k prio 0\n"
        "tc class add dev eth1 parent 1:1 classid 1:20 htb rate 5000000bit"
        " ceil 50000000bit burst 64k prio 1\n"
        "tc qdisc add dev eth1 parent 1:10 handle 10: sfq perturb 10\n"
        "tc qdisc add dev eth1 parent 1:20 handle 20: sfq perturb 10\n"
        "tc filter add dev eth1 parent 1: protocol ip prio 1 u32"
        " match ip dsfield 0xb8 0xfc flowid 1:10\n");
    free(got);
}
END_TEST

START_TEST(test_one_class_has_no_filters)
{
    struct bw_config cfg;
    char *got;

    load(ONE_CLASS, &cfg);
    got = qos_script(&cfg, NULL);
    ck_assert_msg(strstr(got, "tc filter") == NULL, "unexpected filter in:\n%s", got);
    ck_assert_str_eq(got,
        "tc qdisc add dev eth0 root handle 1: htb default 10\n"
        "tc class add dev eth0 parent 1: classid 1:1 htb rate 1000000bit\n"
        "tc class add dev eth0 parent 1:1 classid 1:10 htb rate 1000000bit"
        " ceil 1000000bit burst 16k prio 0\n"
        "tc qdisc add dev eth0 parent 1:10 handle 10: sfq perturb 10\n");
    free(got);
}
END_TEST

START_TEST(test_dscp34_tos_and_mask)
{
    struct bw_config cfg;
    char *got;

    load(SHIPPED, &cfg);
    ck_assert_int_eq(cfg.classes[1].dscp, 34);
    got = qos_script(&cfg, NULL);
    ck_assert_msg(strstr(got, "u32 match ip dsfield 0x88 0xfc flowid 1:20\n") != NULL,
                  "no DSCP 34 filter in:\n%s", got);
    free(got);
}
END_TEST

START_TEST(test_default_class_not_first)
{
    struct bw_config cfg;
    char *got;

    /* The default class gets no filter wherever it sits in the file. */
    load(SHIPPED, &cfg);
    cfg.default_class = 0;
    got = qos_script(&cfg, NULL);
    ck_assert_msg(strstr(got, "htb default 10\n") != NULL, "wrong default in:\n%s", got);
    ck_assert_msg(strstr(got, "flowid 1:10") == NULL, "filter for default class:\n%s", got);
    ck_assert_msg(strstr(got, "dsfield 0x00 0xfc flowid 1:40\n") != NULL,
                  "no filter for best_effort:\n%s", got);
    ck_assert_int_eq(count_lines(got, "tc filter "), 3);
    free(got);
}
END_TEST

START_TEST(test_clear_script)
{
    FILE *f = tmpfile();
    char *got;
    int rc;

    ck_assert(f != NULL);
    rc = bw_qos_clear_script("bw0", f);
    ck_assert_int_eq(rc, 0);
    got = slurp(f);
    fclose(f);
    ck_assert_str_eq(got, "tc qdisc del dev bw0 root\n");
    free(got);
}
END_TEST

START_TEST(test_change_line_keeps_burst_and_prio)
{
    struct bw_config cfg;
    FILE *f = tmpfile();
    char *got;
    int rc;

    ck_assert(f != NULL);
    load(SHIPPED, &cfg);
    rc = bw_qos_change_line(&cfg, NULL, 3, 5000000ULL, f);
    ck_assert_int_eq(rc, 0);
    got = slurp(f);
    fclose(f);
    ck_assert_str_eq(got, "tc class change dev eth0 parent 1:1 classid 1:40 htb rate 5000000bit"
                          " ceil 100000000bit burst 256k prio 3\n");
    free(got);
}
END_TEST

START_TEST(test_change_line_interface_and_range)
{
    struct bw_config cfg;
    FILE *f = tmpfile();
    char *got;
    int rc;

    ck_assert(f != NULL);
    load(SHIPPED, &cfg);
    rc = bw_qos_change_line(&cfg, "bw0", 0, 35000000ULL, f);
    ck_assert_int_eq(rc, 0);
    rc = bw_qos_change_line(&cfg, "bw0", 4, 1000ULL, f);
    ck_assert_int_eq(rc, -1);
    rc = bw_qos_change_line(&cfg, "bw0", -1, 1000ULL, f);
    ck_assert_int_eq(rc, -1);
    got = slurp(f);
    fclose(f);
    ck_assert_str_eq(got, "tc class change dev bw0 parent 1:1 classid 1:10 htb rate 35000000bit"
                          " ceil 100000000bit burst 32k prio 0\n");
    free(got);
}
END_TEST

Suite *qos_suite(void)
{
    Suite *s = suite_create("qos");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_script_matches_golden);
    tcase_add_test(tc, test_interface_override);
    tcase_add_test(tc, test_under_100_keeps_ceil_at_total);
    tcase_add_test(tc, test_one_class_has_no_filters);
    tcase_add_test(tc, test_dscp34_tos_and_mask);
    tcase_add_test(tc, test_default_class_not_first);
    tcase_add_test(tc, test_clear_script);
    tcase_add_test(tc, test_change_line_keeps_burst_and_prio);
    tcase_add_test(tc, test_change_line_interface_and_range);
    suite_add_tcase(s, tc);
    return s;
}
