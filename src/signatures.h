#ifndef BWOPT_SIGNATURES_H
#define BWOPT_SIGNATURES_H

#include <stddef.h>
#include <sys/types.h>

#include "config.h"

/*
 * Looks at the first bytes of an L4 payload and reports which of the
 * known signatures it starts with:
 *   BW_SIG_SIP  - "<METHOD> sip:" / "<METHOD> sips:" request line, or a
 *                 "SIP/2.0 NNN" status line
 *   BW_SIG_HTTP - an HTTP request method followed by a space
 *   BW_SIG_TLS  - a TLS handshake record header 0x16 0x03 0x00..0x03 plus
 *                 its two length bytes
 * Never reads past len. Returns BW_SIG_NONE when nothing matches.
 */
enum bw_sig bw_signature_match(const u_char *payload, size_t len);

#endif
