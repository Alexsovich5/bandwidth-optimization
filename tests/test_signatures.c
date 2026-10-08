#include <string.h>
#include <check.h>

#include "../src/signatures.h"

#define MATCH_STR(s) bw_signature_match((const u_char *)(s), strlen(s))

START_TEST(test_http_methods)
{
    ck_assert_int_eq(MATCH_STR("GET / HTTP/1.1\r\n"), BW_SIG_HTTP);
    ck_assert_int_eq(MATCH_STR("GET /"), BW_SIG_HTTP);
    ck_assert_int_eq(MATCH_STR("POST /form HTTP/1.0\r\n"), BW_SIG_HTTP);
    ck_assert_int_eq(MATCH_STR("POST "), BW_SIG_HTTP);
    ck_assert_int_eq(MATCH_STR("HEAD /index.html HTTP/1.1\r\n"), BW_SIG_HTTP);
    ck_assert_int_eq(MATCH_STR("PUT /x HTTP/1.1\r\n"), BW_SIG_HTTP);
    ck_assert_int_eq(MATCH_STR("DELETE /x HTTP/1.1\r\n"), BW_SIG_HTTP);
    ck_assert_int_eq(MATCH_STR("OPTIONS * HTTP/1.1\r\n"), BW_SIG_HTTP);
}
END_TEST

START_TEST(test_http_negatives)
{
    ck_assert_int_eq(MATCH_STR("GET"), BW_SIG_NONE);      /* no separator yet */
    ck_assert_int_eq(MATCH_STR("GETX / HTTP/1.1"), BW_SIG_NONE);
    ck_assert_int_eq(MATCH_STR("get / HTTP/1.1"), BW_SIG_NONE);
    ck_assert_int_eq(MATCH_STR("HTTP/1.1 200 OK\r\n"), BW_SIG_NONE);
    ck_assert_int_eq(MATCH_STR(" GET /"), BW_SIG_NONE);
}
END_TEST

START_TEST(test_sip_request_and_status)
{
    ck_assert_int_eq(MATCH_STR("INVITE sip:bob@10.0.0.20 SIP/2.0\r\n"), BW_SIG_SIP);
    ck_assert_int_eq(MATCH_STR("REGISTER sip:example.net SIP/2.0\r\n"), BW_SIG_SIP);
    ck_assert_int_eq(MATCH_STR("BYE sips:bob@10.0.0.20 SIP/2.0\r\n"), BW_SIG_SIP);
    /* OPTIONS is both an HTTP and a SIP method: the URI scheme decides. */
    ck_assert_int_eq(MATCH_STR("OPTIONS sip:bob@10.0.0.20 SIP/2.0\r\n"), BW_SIG_SIP);
    ck_assert_int_eq(MATCH_STR("SIP/2.0 200 OK\r\n"), BW_SIG_SIP);
    ck_assert_int_eq(MATCH_STR("SIP/2.0 180"), BW_SIG_SIP);
}
END_TEST

START_TEST(test_sip_negatives)
{
    ck_assert_int_eq(MATCH_STR("INVITE"), BW_SIG_NONE);
    ck_assert_int_eq(MATCH_STR("INVITE http://x"), BW_SIG_NONE);
    ck_assert_int_eq(MATCH_STR("SIP/2.0"), BW_SIG_NONE);     /* no status code */
    ck_assert_int_eq(MATCH_STR("SIP/1.0 200 OK"), BW_SIG_NONE);
    ck_assert_int_eq(MATCH_STR("SIP!"), BW_SIG_NONE);
}
END_TEST

START_TEST(test_tls_record_header)
{
    /* Handshake record, TLS 1.0, length 0x00c4, then a ClientHello. */
    static const u_char hello[] = { 0x16, 0x03, 0x01, 0x00, 0xc4, 0x01, 0x00, 0x00, 0xc0 };
    static const u_char ssl3[] = { 0x16, 0x03, 0x00, 0x00, 0x2f };
    static const u_char tls12[] = { 0x16, 0x03, 0x03, 0x00, 0x2f };

    ck_assert_int_eq(bw_signature_match(hello, sizeof hello), BW_SIG_TLS);
    ck_assert_int_eq(bw_signature_match(ssl3, sizeof ssl3), BW_SIG_TLS);
    ck_assert_int_eq(bw_signature_match(tls12, sizeof tls12), BW_SIG_TLS);
}
END_TEST

START_TEST(test_tls_negatives)
{
    static const u_char app_data[] = { 0x17, 0x03, 0x01, 0x00, 0x20 };
    static const u_char bad_minor[] = { 0x16, 0x03, 0x04, 0x00, 0x20 };
    static const u_char bad_major[] = { 0x16, 0x02, 0x01, 0x00, 0x20 };
    static const u_char short_hdr[] = { 0x16, 0x03, 0x01, 0x00 };

    ck_assert_int_eq(bw_signature_match(app_data, sizeof app_data), BW_SIG_NONE);
    ck_assert_int_eq(bw_signature_match(bad_minor, sizeof bad_minor), BW_SIG_NONE);
    ck_assert_int_eq(bw_signature_match(bad_major, sizeof bad_major), BW_SIG_NONE);
    ck_assert_int_eq(bw_signature_match(short_hdr, sizeof short_hdr), BW_SIG_NONE);
}
END_TEST

START_TEST(test_random_and_short)
{
    static const u_char noise[] = { 0x9e, 0x21, 0xf0, 0x07, 0x5a, 0xc3, 0x11, 0x88,
                                    0x00, 0xff, 0x42, 0x3d, 0x6b, 0xe4, 0x90, 0x2c };
    static const u_char one[] = { 0x16 };

    ck_assert_int_eq(bw_signature_match(noise, sizeof noise), BW_SIG_NONE);
    ck_assert_int_eq(bw_signature_match(one, sizeof one), BW_SIG_NONE);
    ck_assert_int_eq(bw_signature_match((const u_char *)"", 0), BW_SIG_NONE);
    ck_assert_int_eq(bw_signature_match(NULL, 0), BW_SIG_NONE);
    /* The length bounds the match even when more bytes follow in memory. */
    ck_assert_int_eq(bw_signature_match((const u_char *)"GET / HTTP/1.1", 3), BW_SIG_NONE);
    ck_assert_int_eq(bw_signature_match((const u_char *)"SIP/2.0 200 OK", 7), BW_SIG_NONE);
}
END_TEST

Suite *signatures_suite(void)
{
    Suite *s = suite_create("signatures");
    TCase *tc = tcase_create("match");

    tcase_add_test(tc, test_http_methods);
    tcase_add_test(tc, test_http_negatives);
    tcase_add_test(tc, test_sip_request_and_status);
    tcase_add_test(tc, test_sip_negatives);
    tcase_add_test(tc, test_tls_record_header);
    tcase_add_test(tc, test_tls_negatives);
    tcase_add_test(tc, test_random_and_short);
    suite_add_tcase(s, tc);
    return s;
}
