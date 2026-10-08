#include <stdlib.h>
#include <check.h>

Suite *version_suite(void);
Suite *config_suite(void);
Suite *packet_suite(void);
Suite *signatures_suite(void);
Suite *classifier_suite(void);
Suite *capture_suite(void);
Suite *dscp_suite(void);

int main(void)
{
    SRunner *sr;
    int failed;

    sr = srunner_create(version_suite());
    srunner_add_suite(sr, config_suite());
    srunner_add_suite(sr, packet_suite());
    srunner_add_suite(sr, signatures_suite());
    srunner_add_suite(sr, classifier_suite());
    srunner_add_suite(sr, capture_suite());
    srunner_add_suite(sr, dscp_suite());

    srunner_run_all(sr, CK_NORMAL);
    failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
