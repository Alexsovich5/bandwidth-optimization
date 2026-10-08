#include <stdlib.h>
#include <check.h>

Suite *version_suite(void);

int main(void)
{
    SRunner *sr;
    int failed;

    sr = srunner_create(version_suite());

    srunner_run_all(sr, CK_NORMAL);
    failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
