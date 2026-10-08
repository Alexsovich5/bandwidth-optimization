#include <string.h>

#include "signatures.h"

static const char *const http_methods[] = {
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH"
};

static const char *const sip_methods[] = {
    "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "PRACK", "SUBSCRIBE",
    "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE"
};

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

/* True when buf[0..len) starts with the bytes of s. */
static int starts_with(const u_char *buf, size_t len, const char *s)
{
    size_t n = strlen(s);

    return len >= n && memcmp(buf, s, n) == 0;
}

/*
 * If the payload starts with one of the methods followed by a space,
 * returns the offset just past that space, otherwise 0.
 */
static size_t method_prefix(const u_char *buf, size_t len,
                            const char *const *methods, size_t nmethods)
{
    size_t i;

    for (i = 0; i < nmethods; i++) {
        size_t n = strlen(methods[i]);

        if (len > n && memcmp(buf, methods[i], n) == 0 && buf[n] == ' ')
            return n + 1;
    }
    return 0;
}

static int is_digit(u_char c)
{
    return c >= '0' && c <= '9';
}

static int sip_match(const u_char *buf, size_t len)
{
    size_t off = method_prefix(buf, len, sip_methods, NELEM(sip_methods));

    if (off != 0)
        return starts_with(buf + off, len - off, "sip:")
            || starts_with(buf + off, len - off, "sips:");
    /* Status line: "SIP/2.0 " and a three-digit code. */
    return len >= 11 && memcmp(buf, "SIP/2.0 ", 8) == 0
        && is_digit(buf[8]) && is_digit(buf[9]) && is_digit(buf[10]);
}

static int tls_match(const u_char *buf, size_t len)
{
    /* content type 22 (handshake), version 3.0 .. 3.3, 2-byte length */
    return len >= 5 && buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x03;
}

enum bw_sig bw_signature_match(const u_char *payload, size_t len)
{
    if (payload == NULL || len == 0)
        return BW_SIG_NONE;
    /* SIP first: OPTIONS is also an HTTP method, the "sip:" URI decides. */
    if (sip_match(payload, len))
        return BW_SIG_SIP;
    if (method_prefix(payload, len, http_methods, NELEM(http_methods)) != 0)
        return BW_SIG_HTTP;
    if (tls_match(payload, len))
        return BW_SIG_TLS;
    return BW_SIG_NONE;
}
