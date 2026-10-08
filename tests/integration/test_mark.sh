#!/bin/bash
# DSCP rule generation (dscp-script) and the pcap rewrite testing aid
# (mark). Run from the repository root after `make fixtures`.
set -e

fail() { echo "FAIL: $*" >&2; exit 1; }

OUT=tests/fixtures/out
IN="$OUT/mixed.pcap"
[ -s "$IN" ] || fail "$IN missing; run make fixtures"

TMP=$(mktemp -d /tmp/bwopt_mark.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# --- dscp-script -------------------------------------------------------

./bwopt dscp-script > "$TMP/rules" || fail "dscp-script exited non-zero"
diff -u tests/golden/policies.iptables "$TMP/rules" || fail "dscp-script differs from golden"

for opt in -i --interface; do
    ./bwopt dscp-script "$opt" bw0 > "$TMP/rules_bw0" || fail "dscp-script $opt bw0 failed"
    sed 's/-o eth0 /-o bw0 /' tests/golden/policies.iptables \
        | diff -u - "$TMP/rules_bw0" || fail "dscp-script $opt bw0 output wrong"
done

./bwopt dscp-script -c tests/fixtures/conf/signatures.conf > "$TMP/rules_sig" \
    || fail "dscp-script with signatures.conf failed"
cmp -s "$TMP/rules" "$TMP/rules_sig" || fail "signatures changed the iptables rules"

rc=0
./bwopt dscp-script -c tests/fixtures/conf/bad_dscp.conf > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "dscp-script with a bad config exited $rc, expected 2"

# --- mark --------------------------------------------------------------

MARKED="$TMP/marked.pcap"
./bwopt mark -r "$IN" -w "$MARKED" > /dev/null || fail "mark exited non-zero"
[ -s "$MARKED" ] || fail "mark wrote no output"

# Rewriting a header byte never changes frame sizes.
[ "$(wc -c < "$IN")" -eq "$(wc -c < "$MARKED")" ] || fail "marked file size differs"
cmp -s -n 24 "$IN" "$MARKED" || fail "pcap file header changed"

# Every classified packet now carries its class DSCP.
declare -A want=([high_priority]=46 [medium_priority]=34 [low_priority]=18 [best_effort]=0)
before=$(./bwopt classify -r "$IN")
after=$(./bwopt classify -r "$MARKED") || fail "classify of the marked file failed"
[ "$(printf '%s\n' "$after" | wc -l)" -eq 19 ] || fail "marked file lost packets"

while read -r line; do
    class=${line##* class=}
    [ "$class" = unclassified ] && continue
    dscp=$(printf '%s\n' "$line" | sed -n 's/.* dscp=\([0-9]*\) .*/\1/p')
    [ "$dscp" = "${want[$class]}" ] || fail "class $class has dscp=$dscp: $line"
done <<< "$after"

# Only the DSCP may differ: the same lines with dscp= removed.
strip() { sed 's/ dscp=[0-9]*//'; }
[ "$(printf '%s\n' "$before" | strip)" = "$(printf '%s\n' "$after" | strip)" ] \
    || fail "marking changed more than the DSCP"

printf '%s\n' "$after" | grep -qx \
    '6 tcp 192.168.1.10:51000 -> 10.0.0.20:22 len=75 dscp=34 class=medium_priority' \
    || fail "packet 6 not marked 34"
printf '%s\n' "$after" | grep -qx \
    '10 tcp 192.168.1.10:51002 -> 10.0.0.20:80 len=89 dscp=18 class=low_priority' \
    || fail "packet 10 not marked 18"
printf '%s\n' "$after" | grep -qx \
    '17 udp 192.168.1.10 -> 10.0.0.20 len=98 dscp=0 class=best_effort' \
    || fail "fragment tail not marked 0"

# Non-IP frames (18 and 19, at the end of the file) are byte-for-byte
# unchanged. Each record is a 16-byte header plus the frame (caplen equals
# len in the fixtures).
off=24
while read -r line; do
    n=${line%% *}
    [ "$n" -ge 18 ] && break
    len=$(printf '%s\n' "$line" | sed -n 's/.* len=\([0-9]*\) .*/\1/p')
    off=$((off + 16 + len))
done <<< "$before"
tail -c +$((off + 1)) "$IN" > "$TMP/in_tail"
tail -c +$((off + 1)) "$MARKED" > "$TMP/out_tail"
[ "$(wc -c < "$TMP/in_tail")" -eq $((2 * 16 + 42 + 62)) ] || fail "non-IP range offset wrong"
cmp "$TMP/in_tail" "$TMP/out_tail" || fail "non-IP frames changed"

# A capture with only non-IP frames comes out identical.
./bwopt mark -r "$OUT/nonip.pcap" -w "$TMP/nonip.pcap" > /dev/null || fail "mark nonip failed"
cmp "$OUT/nonip.pcap" "$TMP/nonip.pcap" || fail "nonip.pcap changed by mark"

# Signatures apply to mark: the HTTP request on 8080 becomes low_priority.
./bwopt mark -c tests/fixtures/conf/signatures.conf -r "$IN" -w "$TMP/sig.pcap" > /dev/null \
    || fail "mark with signatures.conf failed"
./bwopt classify -r "$TMP/sig.pcap" | grep -q '^15 .* dscp=18 class=best_effort$' \
    || fail "signature match not marked 18"

# Usage and runtime errors.
rc=0
./bwopt mark -r "$IN" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "mark without -w exited $rc, expected 2"
rc=0
./bwopt mark -w "$TMP/x.pcap" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "mark without -r exited $rc, expected 2"
rc=0
./bwopt mark -r /nonexistent.pcap -w "$TMP/x.pcap" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "mark of a missing file exited $rc, expected 1"
rc=0
./bwopt mark -r "$IN" -w /nonexistent/dir/x.pcap > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "mark to an unwritable path exited $rc, expected 1"

echo "test_mark: ok"
