#include <ctype.h>
#include <string.h>
#include <check.h>

#include "../src/version.h"
#include "test_util.h"

/* Accepts MAJOR.MINOR.PATCH, each a run of digits with no leading zero. */
static int is_semver(const char *s)
{
    int part;

    for (part = 0; part < 3; part++) {
        const char *start = s;

        if (!isdigit((unsigned char)*s))
            return 0;
        while (isdigit((unsigned char)*s))
            s++;
        if (s - start > 1 && *start == '0')
            return 0;
        if (part < 2) {
            if (*s != '.')
                return 0;
            s++;
        }
    }
    return *s == '\0';
}

START_TEST(test_version_non_empty)
{
    ck_assert(strlen(BWOPT_VERSION) > 0);
}
END_TEST

START_TEST(test_version_is_semver)
{
    ck_assert_msg(is_semver(BWOPT_VERSION), "not semver: %s", BWOPT_VERSION);
}
END_TEST

START_TEST(test_semver_checker_rejects_bad_strings)
{
    ck_assert(!is_semver(""));
    ck_assert(!is_semver("1.0"));
    ck_assert(!is_semver("1.0.0.0"));
    ck_assert(!is_semver("v1.0.0"));
    ck_assert(!is_semver("01.0.0"));
    ck_assert(is_semver("10.2.33"));
}
END_TEST

START_TEST(test_u64_assert_helper)
{
    ASSERT_U64_EQ(10000000000ULL, 10000000000ULL);
}
END_TEST

Suite *version_suite(void)
{
    Suite *s = suite_create("version");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_version_non_empty);
    tcase_add_test(tc, test_version_is_semver);
    tcase_add_test(tc, test_semver_checker_rejects_bad_strings);
    tcase_add_test(tc, test_u64_assert_helper);
    suite_add_tcase(s, tc);
    return s;
}
