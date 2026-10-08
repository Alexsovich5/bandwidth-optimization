#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <check.h>

#include "../src/exec.h"

static char dir[64];
static char marker[96];

static void setup(void)
{
    strcpy(dir, "/tmp/bwopt_exec.XXXXXX");
    ck_assert(mkdtemp(dir) != NULL);
    snprintf(marker, sizeof marker, "%s/marker", dir);
}

static void teardown(void)
{
    unlink(marker);
    rmdir(dir);
}

static int exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static char *slurp(FILE *f)
{
    size_t cap = 4096, len;
    char *buf = malloc(cap);

    ck_assert(buf != NULL);
    rewind(f);
    len = fread(buf, 1, cap - 1, f);
    buf[len] = '\0';
    return buf;
}

START_TEST(test_dry_run_prints_lines)
{
    char script[256];
    FILE *f = tmpfile();
    char *got;
    int rc;

    ck_assert(f != NULL);
    snprintf(script, sizeof script, "tc qdisc del dev bw0 root\ntouch %s\nfalse\n", marker);
    rc = bw_exec_run(script, BW_EXEC_DRY_RUN, f);
    ck_assert_int_eq(rc, 0);
    got = slurp(f);
    fclose(f);
    ck_assert_str_eq(got, script);
    ck_assert_msg(!exists(marker), "dry run executed a command");
    free(got);
}
END_TEST

START_TEST(test_dry_run_adds_final_newline)
{
    FILE *f = tmpfile();
    char *got;
    int rc;

    ck_assert(f != NULL);
    rc = bw_exec_run("echo a\n\necho b", BW_EXEC_DRY_RUN, f);
    ck_assert_int_eq(rc, 0);
    got = slurp(f);
    fclose(f);
    ck_assert_str_eq(got, "echo a\necho b\n");
    free(got);
}
END_TEST

START_TEST(test_strict_runs_all_lines_on_success)
{
    char script[256];
    int rc;

    snprintf(script, sizeof script, "true\ntouch %s", marker);
    rc = bw_exec_run(script, 0, NULL);
    ck_assert_int_eq(rc, 0);
    ck_assert_msg(exists(marker), "second line did not run");
}
END_TEST

START_TEST(test_strict_stops_at_first_failure)
{
    char script[256];
    int rc;

    snprintf(script, sizeof script, "exit 3\ntouch %s\n", marker);
    rc = bw_exec_run(script, 0, NULL);
    ck_assert_msg(rc != 0, "failing command returned 0 in strict mode");
    ck_assert_msg(!exists(marker), "line after the failure ran");
}
END_TEST

START_TEST(test_ignore_errors_continues)
{
    char script[256];
    int rc;

    snprintf(script, sizeof script,
             "ls /nonexistent/bwopt\nfalse\ntouch %s\n", marker);
    rc = bw_exec_run(script, BW_EXEC_IGNORE_ERRORS, NULL);
    ck_assert_int_eq(rc, 0);
    ck_assert_msg(exists(marker), "line after the failure did not run");
}
END_TEST

Suite *exec_suite(void)
{
    Suite *s = suite_create("exec");
    TCase *tc = tcase_create("core");

    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_dry_run_prints_lines);
    tcase_add_test(tc, test_dry_run_adds_final_newline);
    tcase_add_test(tc, test_strict_runs_all_lines_on_success);
    tcase_add_test(tc, test_strict_stops_at_first_failure);
    tcase_add_test(tc, test_ignore_errors_continues);
    suite_add_tcase(s, tc);
    return s;
}
