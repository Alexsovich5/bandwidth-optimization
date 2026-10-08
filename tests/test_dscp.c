#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "../src/config.h"
#include "../src/dscp.h"

#define SHIPPED    "config/policies.conf"
#define SIGNATURES "tests/fixtures/conf/signatures.conf"
#define GOLDEN     "tests/golden/policies.iptables"

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

typedef int (*script_fn)(const struct bw_config *, const char *, FILE *);

static char *run_script(script_fn fn, const struct bw_config *cfg, const char *iface)
{
    FILE *f = tmpfile();
    char *s;
    int rc;

    ck_assert(f != NULL);
    rc = fn(cfg, iface, f);   /* ck_assert_int_eq evaluates its arguments twice */
    ck_assert_int_eq(rc, 0);
    s = slurp(f);
    fclose(f);
    return s;
}

/* Check 0.9.8's ck_assert_int_eq evaluates its arguments twice. */
#define EXPECT_REWRITE(hdr, len, dscp, want) do { \
        int rc_ = bw_dscp_rewrite((hdr), (len), (dscp)); \
        ck_assert_int_eq(rc_, (want)); \
    } while (0)

/* RFC 1071: the one's complement sum over a valid header is 0xffff. */
static unsigned header_sum(const unsigned char *h, size_t len)
{
    unsigned long sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += (unsigned long)((h[i] << 8) | h[i + 1]);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned)sum;
}

/* A UDP header from 192.168.0.1 to 192.168.0.199, TOS 0, checksum 0xb861. */
static const unsigned char known_hdr[20] = {
    0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
    0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
    0xc0, 0xa8, 0x00, 0xc7
};

START_TEST(test_script_matches_golden)
{
    struct bw_config cfg;
    char *got, *want;

    load(SHIPPED, &cfg);
    got = run_script(bw_dscp_script, &cfg, NULL);
    want = read_file(GOLDEN);
    ck_assert_str_eq(got, want);
    free(got);
    free(want);
}
END_TEST

START_TEST(test_script_interface_override)
{
    struct bw_config cfg;
    char *got;

    load(SHIPPED, &cfg);
    got = run_script(bw_dscp_script, &cfg, "bw0");
    ck_assert_msg(strstr(got, "iptables -t mangle -A POSTROUTING -o bw0 -j BWOPT\n") != NULL,
                  "no bw0 hook in:\n%s", got);
    ck_assert_msg(strstr(got, "eth0") == NULL, "eth0 still present:\n%s", got);
    free(got);
}
END_TEST

START_TEST(test_signatures_add_no_rules)
{
    struct bw_config shipped, sig;
    char *a, *b;

    load(SHIPPED, &shipped);
    load(SIGNATURES, &sig);
    a = run_script(bw_dscp_script, &shipped, NULL);
    b = run_script(bw_dscp_script, &sig, NULL);
    ck_assert_str_eq(b, a);
    free(a);
    free(b);
}
END_TEST

START_TEST(test_signature_only_app_has_no_rule)
{
    struct bw_config cfg;
    char *got;

    load(SHIPPED, &cfg);
    /* Turn every application into a signature-only one. */
    {
        int i;

        for (i = 0; i < cfg.napps; i++) {
            cfg.apps[i].port_lo = 0;
            cfg.apps[i].port_hi = 0;
            cfg.apps[i].sig = BW_SIG_HTTP;
        }
    }
    got = run_script(bw_dscp_script, &cfg, NULL);
    ck_assert_str_eq(got,
                     "iptables -t mangle -N BWOPT\n"
                     "iptables -t mangle -A POSTROUTING -o eth0 -j BWOPT\n");
    free(got);
}
END_TEST

START_TEST(test_clear_script)
{
    struct bw_config cfg;
    char *got;

    load(SHIPPED, &cfg);
    got = run_script(bw_dscp_clear_script, &cfg, "bw0");
    ck_assert_str_eq(got,
                     "iptables -t mangle -F BWOPT\n"
                     "iptables -t mangle -D POSTROUTING -o bw0 -j BWOPT\n"
                     "iptables -t mangle -X BWOPT\n");
    free(got);
}
END_TEST

START_TEST(test_rewrite_dscp46_checksum)
{
    unsigned char h[20];

    memcpy(h, known_hdr, sizeof h);
    ck_assert_int_eq(header_sum(h, sizeof h), 0xffff);   /* fixture is valid */
    EXPECT_REWRITE(h, sizeof h, 46, 0);
    ck_assert_int_eq(h[1], 0xb8);
    ck_assert_int_eq(header_sum(h, sizeof h), 0xffff);
    /* RFC 1624: 0xb861 - 0x00b8 */
    ck_assert_int_eq((h[10] << 8) | h[11], 0xb7a9);
    /* nothing else changed */
    ck_assert(memcmp(h, known_hdr, 1) == 0);
    ck_assert(memcmp(h + 2, known_hdr + 2, 8) == 0);
    ck_assert(memcmp(h + 12, known_hdr + 12, 8) == 0);
}
END_TEST

START_TEST(test_rewrite_keeps_ecn)
{
    unsigned char h[20];
    unsigned ecn;

    for (ecn = 0; ecn < 4; ecn++) {
        memcpy(h, known_hdr, sizeof h);
        h[1] = (unsigned char)(0x28 | ecn);   /* DSCP 10 + ECN */
        EXPECT_REWRITE(h, sizeof h, 46, 0);
        ck_assert_int_eq(h[1], 0xb8 | ecn);
        ck_assert_int_eq(header_sum(h, sizeof h), 0xffff);

        EXPECT_REWRITE(h, sizeof h, 0, 0);
        ck_assert_int_eq(h[1], ecn);
        ck_assert_int_eq(header_sum(h, sizeof h), 0xffff);
    }
}
END_TEST

START_TEST(test_rewrite_covers_options)
{
    /* IHL 6: one 4-byte option word is part of the checksummed header. */
    unsigned char h[28] = {
        0x46, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0a,
        0x0a, 0x00, 0x00, 0x14, 0x94, 0x04, 0x00, 0x00,
        0xaa, 0xbb, 0xcc, 0xdd                  /* first payload bytes */
    };

    EXPECT_REWRITE(h, sizeof h, 34, 0);
    ck_assert_int_eq(h[1], 0x88);
    ck_assert_int_eq(header_sum(h, 24), 0xffff);
    ck_assert_int_eq(h[24], 0xaa);
    ck_assert_int_eq(h[27], 0xdd);
}
END_TEST

START_TEST(test_rewrite_rejects_bad_input)
{
    unsigned char h[20], v6[20];

    memcpy(h, known_hdr, sizeof h);
    EXPECT_REWRITE(h, 19, 46, -1);       /* truncated */
    EXPECT_REWRITE(h, sizeof h, 64, -1); /* DSCP out of range */
    ck_assert(memcmp(h, known_hdr, sizeof h) == 0);

    memcpy(v6, known_hdr, sizeof v6);
    v6[0] = 0x65;                                           /* version 6 */
    EXPECT_REWRITE(v6, sizeof v6, 46, -1);
    ck_assert_int_eq(v6[1], 0x00);

    memcpy(h, known_hdr, sizeof h);
    h[0] = 0x46;                                            /* IHL 6 > 20 bytes */
    EXPECT_REWRITE(h, sizeof h, 46, -1);
    h[0] = 0x44;                                            /* IHL 4 < minimum */
    EXPECT_REWRITE(h, sizeof h, 46, -1);
    ck_assert_int_eq(h[1], 0x00);
}
END_TEST

Suite *dscp_suite(void)
{
    Suite *s = suite_create("dscp");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_script_matches_golden);
    tcase_add_test(tc, test_script_interface_override);
    tcase_add_test(tc, test_signatures_add_no_rules);
    tcase_add_test(tc, test_signature_only_app_has_no_rule);
    tcase_add_test(tc, test_clear_script);
    tcase_add_test(tc, test_rewrite_dscp46_checksum);
    tcase_add_test(tc, test_rewrite_keeps_ecn);
    tcase_add_test(tc, test_rewrite_covers_options);
    tcase_add_test(tc, test_rewrite_rejects_bad_input);
    suite_add_tcase(s, tc);
    return s;
}
