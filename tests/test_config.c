#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <check.h>

#include "../src/config.h"
#include "test_util.h"

#define SHIPPED "config/policies.conf"
#define FIXTURES "tests/fixtures/conf/"

/* Writes text to a fresh temp file and loads it. Returns bw_config_load's result. */
static int load_text(const char *text, struct bw_config *cfg, char *err, size_t errlen)
{
    char path[] = "/tmp/bwopt_conf_XXXXXX";
    int fd = mkstemp(path);
    FILE *f;
    int rc;

    ck_assert_msg(fd >= 0, "mkstemp failed");
    close(fd);
    f = fopen(path, "w");
    ck_assert_msg(f != NULL, "fopen %s failed", path);
    fputs(text, f);
    fclose(f);
    rc = bw_config_load(path, cfg, err, errlen);
    unlink(path);
    return rc;
}

/* A minimal valid file whose line 8 is "voice.burst=<burst>". */
static int load_with_burst(const char *burst, struct bw_config *cfg, char *err, size_t errlen)
{
    char text[1024];

    snprintf(text, sizeof text,
             "[global]\n"
             "interface=eth1\n"
             "total_bandwidth=2000000\n"
             "default_class=bulk\n"
             "[classes]\n"
             "voice.bandwidth=25%%\n"
             "voice.dscp=46\n"
             "voice.burst=%s\n"
             "bulk.bandwidth=10%%\n"
             "bulk.dscp=0\n"
             "bulk.burst=16k\n", burst);
    return load_text(text, cfg, err, errlen);
}

START_TEST(test_shipped_config_counts)
{
    struct bw_config cfg;
    char err[256] = "";

    ck_assert_msg(bw_config_load(SHIPPED, &cfg, err, sizeof err) == 0, "load failed: %s", err);
    ck_assert_int_eq(cfg.nclasses, 4);
    ck_assert_int_eq(cfg.napps, 8);
    ASSERT_U64_EQ(cfg.total_bps, 100000000ULL);
    ck_assert_str_eq(cfg.iface, "eth0");
    ck_assert_int_eq(cfg.default_class, 3);
    ck_assert_str_eq(cfg.classes[cfg.default_class].name, "best_effort");
}
END_TEST

START_TEST(test_shipped_config_classes)
{
    struct bw_config cfg;
    char err[256] = "";
    int hp;

    ck_assert_msg(bw_config_load(SHIPPED, &cfg, err, sizeof err) == 0, "load failed: %s", err);
    hp = bw_config_find_class(&cfg, "high_priority");
    ck_assert_int_eq(hp, 0);
    ASSERT_U64_EQ(cfg.classes[hp].rate_bps, 30000000ULL);
    ck_assert_int_eq(cfg.classes[hp].pct, 30);
    ck_assert_int_eq(cfg.classes[hp].dscp, 46);
    ck_assert_str_eq(cfg.classes[hp].burst, "32k");
    ck_assert_int_eq(cfg.classes[hp].classid_minor, 10);
    ck_assert_int_eq(cfg.classes[hp].prio, 0);

    ck_assert_str_eq(cfg.classes[1].name, "medium_priority");
    ASSERT_U64_EQ(cfg.classes[1].rate_bps, 40000000ULL);
    ck_assert_str_eq(cfg.classes[2].name, "low_priority");
    ck_assert_int_eq(cfg.classes[2].dscp, 18);
    ck_assert_str_eq(cfg.classes[3].burst, "256k");
    ck_assert_int_eq(cfg.classes[3].classid_minor, 40);
    ck_assert_int_eq(cfg.classes[3].prio, 3);
    ck_assert_int_eq(bw_config_find_class(&cfg, "nope"), -1);
}
END_TEST

START_TEST(test_shipped_config_apps)
{
    struct bw_config cfg;
    char err[256] = "";
    int i, rtp = -1, sip = -1;

    ck_assert_msg(bw_config_load(SHIPPED, &cfg, err, sizeof err) == 0, "load failed: %s", err);
    for (i = 0; i < cfg.napps; i++) {
        if (strcmp(cfg.apps[i].name, "rtp") == 0)
            rtp = i;
        if (strcmp(cfg.apps[i].name, "sip") == 0)
            sip = i;
    }
    ck_assert_msg(rtp >= 0 && sip >= 0, "rtp/sip apps missing");
    ck_assert_int_eq(cfg.apps[rtp].port_lo, 10000);
    ck_assert_int_eq(cfg.apps[rtp].port_hi, 20000);
    ck_assert_int_eq(cfg.apps[rtp].class_idx, 0);
    ck_assert_int_eq(cfg.apps[sip].port_lo, 5060);
    ck_assert_int_eq(cfg.apps[sip].port_hi, 5060);
    ck_assert_int_eq(cfg.apps[sip].sig, BW_SIG_NONE);
    ck_assert_str_eq(cfg.apps[cfg.napps - 1].name, "ftp");
    ck_assert_int_eq(cfg.apps[cfg.napps - 1].class_idx, 2);
}
END_TEST

START_TEST(test_shipped_config_monitoring_and_autotune_defaults)
{
    struct bw_config cfg;
    char err[256] = "";

    ck_assert_msg(bw_config_load(SHIPPED, &cfg, err, sizeof err) == 0, "load failed: %s", err);
    ck_assert_int_eq(cfg.update_interval, 30);
    ck_assert_str_eq(cfg.log_file, "/var/log/bandwidth_optimizer.log");
    ck_assert_str_eq(cfg.database, "/var/lib/bandwidth_optimizer/metrics.db");
    ck_assert_int_eq(cfg.tune.enabled, 0);
    ck_assert_int_eq(cfg.tune.window, 10);
    ck_assert_int_eq(cfg.tune.low_watermark, 50);
    ck_assert_int_eq(cfg.tune.high_watermark, 90);
    ck_assert_int_eq(cfg.tune.min_share, 50);
    ck_assert_int_eq(cfg.tune.hysteresis, 5);
}
END_TEST

START_TEST(test_autotune_section_overrides)
{
    struct bw_config cfg;
    char err[256] = "";
    char text[2048];

    snprintf(text, sizeof text, "%s",
             "[global]\ninterface=eth0\ntotal_bandwidth=1000000\ndefault_class=b\n"
             "[classes]\na.bandwidth=50%\na.dscp=10\na.burst=1k\n"
             "b.bandwidth=50%\nb.dscp=0\nb.burst=1k\n"
             "[autotune]\nenabled=1\nwindow=4\nlow_watermark=30\nhigh_watermark=80\n"
             "min_share=25\nhysteresis=10\n");
    ck_assert_msg(load_text(text, &cfg, err, sizeof err) == 0, "load failed: %s", err);
    ck_assert_int_eq(cfg.tune.enabled, 1);
    ck_assert_int_eq(cfg.tune.window, 4);
    ck_assert_int_eq(cfg.tune.low_watermark, 30);
    ck_assert_int_eq(cfg.tune.high_watermark, 80);
    ck_assert_int_eq(cfg.tune.min_share, 25);
    ck_assert_int_eq(cfg.tune.hysteresis, 10);
    ck_assert_int_eq(cfg.napps, 0);
}
END_TEST

START_TEST(test_autotune_bad_watermarks_rejected)
{
    struct bw_config cfg;
    char err[256] = "";

    ck_assert_int_eq(load_text("[global]\ninterface=eth0\ntotal_bandwidth=1000\ndefault_class=b\n"
                               "[classes]\nb.bandwidth=10%\nb.dscp=0\nb.burst=1k\n"
                               "[autotune]\nlow_watermark=95\n",
                               &cfg, err, sizeof err), -1);
    ck_assert_msg(strstr(err, "watermark") != NULL, "unexpected error: %s", err);
}
END_TEST

START_TEST(test_comments_and_whitespace_ignored)
{
    struct bw_config cfg;
    char err[256] = "";
    const char *text =
        "# leading comment\n"
        "\n"
        "   [global]   # section comment\n"
        "  interface = eth2   # trailing\n"
        "total_bandwidth=  5000000  # 5 Mbps\n"
        "\tdefault_class=bulk\t\n"
        "[classes]\n"
        "   # indented comment\n"
        "voice.bandwidth = 60% # share\n"
        "voice.dscp=46#tight comment\n"
        "voice.burst=8k\n"
        "bulk.bandwidth=40%\n"
        "bulk.dscp=0\n"
        "bulk.burst=8k\n"
        "[applications]\n"
        "  sip.port = 5060  # signalling\n"
        "sip.class = voice\n"
        "[monitoring]\n"
        "update_interval = 5 # seconds\n"
        "log_file = /tmp/x.log\n"
        "database=/tmp/x.db   \n";

    ck_assert_msg(load_text(text, &cfg, err, sizeof err) == 0, "load failed: %s", err);
    ck_assert_str_eq(cfg.iface, "eth2");
    ASSERT_U64_EQ(cfg.total_bps, 5000000ULL);
    ck_assert_int_eq(cfg.nclasses, 2);
    ck_assert_int_eq(cfg.classes[0].pct, 60);
    ck_assert_int_eq(cfg.classes[0].dscp, 46);
    ASSERT_U64_EQ(cfg.classes[0].rate_bps, 3000000ULL);
    ck_assert_int_eq(cfg.default_class, 1);
    ck_assert_int_eq(cfg.napps, 1);
    ck_assert_int_eq(cfg.apps[0].port_lo, 5060);
    ck_assert_int_eq(cfg.update_interval, 5);
    ck_assert_str_eq(cfg.log_file, "/tmp/x.log");
    ck_assert_str_eq(cfg.database, "/tmp/x.db");
}
END_TEST

START_TEST(test_burst_suffixes)
{
    struct bw_config cfg;
    char err[256] = "";

    ck_assert_msg(load_with_burst("32k", &cfg, err, sizeof err) == 0, "32k: %s", err);
    ck_assert_str_eq(cfg.classes[0].burst, "32k");
    ck_assert_msg(load_with_burst("1m", &cfg, err, sizeof err) == 0, "1m: %s", err);
    ck_assert_str_eq(cfg.classes[0].burst, "1m");
    ck_assert_msg(load_with_burst("1500", &cfg, err, sizeof err) == 0, "1500: %s", err);

    err[0] = '\0';
    ck_assert_int_eq(load_with_burst("32x", &cfg, err, sizeof err), -1);
    ck_assert_msg(strstr(err, ":8:") != NULL, "no line number: %s", err);
    ck_assert_int_eq(load_with_burst("k", &cfg, err, sizeof err), -1);
    ck_assert_int_eq(load_with_burst("32kk", &cfg, err, sizeof err), -1);
    ck_assert_int_eq(load_with_burst("", &cfg, err, sizeof err), -1);
}
END_TEST

START_TEST(test_signature_and_port_forms)
{
    struct bw_config cfg;
    char err[256] = "";
    const char *text =
        "[global]\ninterface=eth0\ntotal_bandwidth=1000000\ndefault_class=b\n"
        "[classes]\na.bandwidth=50%\na.dscp=10\na.burst=1k\n"
        "b.bandwidth=50%\nb.dscp=0\nb.burst=1k\n"
        "[applications]\n"
        "web.signature=http\nweb.class=a\n"
        "voip.port=5060\nvoip.signature=sip\nvoip.class=a\n"
        "game.port_range=27000-27015\ngame.class=b\n";

    ck_assert_msg(load_text(text, &cfg, err, sizeof err) == 0, "load failed: %s", err);
    ck_assert_int_eq(cfg.napps, 3);
    ck_assert_int_eq(cfg.apps[0].sig, BW_SIG_HTTP);
    ck_assert_int_eq(cfg.apps[0].port_lo, 0);
    ck_assert_int_eq(cfg.apps[1].sig, BW_SIG_SIP);
    ck_assert_int_eq(cfg.apps[1].port_hi, 5060);
    ck_assert_int_eq(cfg.apps[2].port_lo, 27000);
    ck_assert_int_eq(cfg.apps[2].port_hi, 27015);
    ck_assert_int_eq(cfg.apps[2].class_idx, 1);
    ck_assert_str_eq(bw_sig_name(BW_SIG_TLS), "tls");
}
END_TEST

START_TEST(test_missing_file)
{
    struct bw_config cfg;
    char err[256] = "";

    ck_assert_int_eq(bw_config_load("/nonexistent/policies.conf", &cfg, err, sizeof err), -1);
    ck_assert_msg(strstr(err, "/nonexistent/policies.conf") != NULL, "unexpected error: %s", err);
}
END_TEST

static const struct {
    const char *file;
    const char *line_tag;   /* ":LINE:" expected in the message */
    const char *word;       /* word expected in the message */
} error_cases[] = {
    { FIXTURES "bad_dscp.conf",         ":8:",  "dscp" },
    { FIXTURES "over_100.conf",         ":10:", "100" },
    { FIXTURES "unknown_class.conf",    ":16:", "video" },
    { FIXTURES "unknown_key.conf",      ":16:", "priority" },
    { FIXTURES "bad_range.conf",        ":15:", "range" },
    { FIXTURES "no_default.conf",       ":4:",  "missing" },
    { FIXTURES "dup_dscp.conf",         ":11:", "34" },
    { FIXTURES "dscp0_nondefault.conf", ":8:",  "default" },
};

START_TEST(test_error_fixture)
{
    struct bw_config cfg;
    char err[256] = "";

    ck_assert_msg(bw_config_load(error_cases[_i].file, &cfg, err, sizeof err) == -1,
                  "%s loaded without error", error_cases[_i].file);
    ck_assert_msg(strstr(err, error_cases[_i].line_tag) != NULL,
                  "%s: expected %s in '%s'", error_cases[_i].file, error_cases[_i].line_tag, err);
    ck_assert_msg(strstr(err, error_cases[_i].word) != NULL,
                  "%s: expected '%s' in '%s'", error_cases[_i].file, error_cases[_i].word, err);
}
END_TEST

START_TEST(test_more_invalid_values)
{
    struct bw_config cfg;
    char err[256] = "";
    const char *head =
        "[global]\ninterface=eth0\ntotal_bandwidth=1000000\ndefault_class=b\n"
        "[classes]\nb.bandwidth=50%\nb.dscp=0\nb.burst=1k\n";
    const char *tails[] = {
        "[applications]\nx.port=0\nx.class=b\n",
        "[applications]\nx.port=65536\nx.class=b\n",
        "[applications]\nx.port=80a\nx.class=b\n",
        "[applications]\nx.port_range=10-\nx.class=b\n",
        "[applications]\nx.port=80\n",
        "[applications]\nx.port=80\nx.port_range=1-2\nx.class=b\n",
        "[applications]\nx.signature=ftp\nx.class=b\n",
        "[applications]\nx.class=b\n",
        "[bogus]\nfoo=1\n",
        "[monitoring]\nupdate_interval=0\n",
        "no section line\n",
        "[classes]\nc.bandwidth=5\nc.dscp=1\nc.burst=1k\n",
        "[classes]\nc.dscp=1\nc.burst=1k\n",
        "[classes]\nthis_class_name_is_far_too_long_for_it.dscp=1\n",
    };
    size_t i;

    for (i = 0; i < sizeof tails / sizeof tails[0]; i++) {
        char text[1024];

        snprintf(text, sizeof text, "%s%s", head, tails[i]);
        err[0] = '\0';
        ck_assert_msg(load_text(text, &cfg, err, sizeof err) == -1,
                      "accepted invalid tail %u: %s", (unsigned)i, tails[i]);
        ck_assert_msg(err[0] != '\0', "no error message for tail %u", (unsigned)i);
    }
}
END_TEST

START_TEST(test_class_limit)
{
    struct bw_config cfg;
    char err[256] = "";
    char text[4096];
    size_t n;
    int i;

    n = (size_t)snprintf(text, sizeof text,
                         "[global]\ninterface=eth0\ntotal_bandwidth=1000\ndefault_class=c0\n"
                         "[classes]\n");
    for (i = 0; i < 9; i++)
        n += (size_t)snprintf(text + n, sizeof text - n,
                              "c%d.bandwidth=10%%\nc%d.dscp=%d\nc%d.burst=1k\n", i, i, i, i);
    ck_assert_int_eq(load_text(text, &cfg, err, sizeof err), -1);
    ck_assert_msg(strstr(err, "too many") != NULL, "unexpected error: %s", err);
}
END_TEST

/* The interface name ends up in tc/iptables command lines run by /bin/sh. */
START_TEST(test_interface_name_validated)
{
    struct bw_config cfg;
    char err[256];
    const char *good[] = { "eth0", "bw0", "br-lan.10", "wlan0_x", "abcdefghijklmno" };
    const char *bad[] = {
        "eth0;touch /tmp/bwopt_pwned", "eth0|id", "$(id)", "a`id`", "eth 0", "a&b",
        "x>y", "'eth0'", "../x", "a/b", ".", "..", "abcdefghijklmnop", "eth0\\n",
        "-eth0", "--help"
    };
    size_t i;

    for (i = 0; i < sizeof good / sizeof good[0]; i++) {
        char text[512];

        ck_assert_msg(bw_iface_valid(good[i]), "rejected valid name %s", good[i]);
        snprintf(text, sizeof text,
                 "[global]\ninterface=%s\ntotal_bandwidth=1000\ndefault_class=b\n"
                 "[classes]\nb.bandwidth=50%%\nb.dscp=0\nb.burst=1k\n", good[i]);
        err[0] = '\0';
        ck_assert_msg(load_text(text, &cfg, err, sizeof err) == 0, "%s: %s", good[i], err);
        ck_assert_str_eq(cfg.iface, good[i]);
    }
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char text[512];

        ck_assert_msg(!bw_iface_valid(bad[i]), "accepted invalid name %s", bad[i]);
        snprintf(text, sizeof text,
                 "[global]\ninterface=%s\ntotal_bandwidth=1000\ndefault_class=b\n"
                 "[classes]\nb.bandwidth=50%%\nb.dscp=0\nb.burst=1k\n", bad[i]);
        err[0] = '\0';
        ck_assert_msg(load_text(text, &cfg, err, sizeof err) == -1, "loaded interface %s", bad[i]);
        ck_assert_msg(strstr(err, ":2:") != NULL && strstr(err, "interface") != NULL,
                      "%s: unexpected error '%s'", bad[i], err);
    }
    ck_assert(!bw_iface_valid(""));
    ck_assert(!bw_iface_valid(NULL));
}
END_TEST

Suite *config_suite(void)
{
    Suite *s = suite_create("config");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_shipped_config_counts);
    tcase_add_test(tc, test_shipped_config_classes);
    tcase_add_test(tc, test_shipped_config_apps);
    tcase_add_test(tc, test_shipped_config_monitoring_and_autotune_defaults);
    tcase_add_test(tc, test_autotune_section_overrides);
    tcase_add_test(tc, test_autotune_bad_watermarks_rejected);
    tcase_add_test(tc, test_comments_and_whitespace_ignored);
    tcase_add_test(tc, test_burst_suffixes);
    tcase_add_test(tc, test_signature_and_port_forms);
    tcase_add_test(tc, test_missing_file);
    tcase_add_loop_test(tc, test_error_fixture, 0,
                        (int)(sizeof error_cases / sizeof error_cases[0]));
    tcase_add_test(tc, test_more_invalid_values);
    tcase_add_test(tc, test_class_limit);
    tcase_add_test(tc, test_interface_name_validated);
    suite_add_tcase(s, tc);
    return s;
}
