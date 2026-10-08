#!/bin/bash
# Offline classification of the generated pcap fixtures. Run from the
# repository root after `make fixtures`.
set -e

fail() { echo "FAIL: $*" >&2; exit 1; }

OUT=tests/fixtures/out
for f in mixed vlan nonip; do
    [ -s "$OUT/$f.pcap" ] || fail "$OUT/$f.pcap missing; run make fixtures"
done

# --summary matches the expected table exactly.
./bwopt classify -r "$OUT/mixed.pcap" --summary > /tmp/bwopt_summary.$$ \
    || fail "classify --summary exited non-zero"
diff -u tests/expected/mixed.summary /tmp/bwopt_summary.$$ || fail "summary differs"
rm -f /tmp/bwopt_summary.$$

# Per-packet output: one line per packet, every line in the SPEC format.
lines=$(./bwopt classify -r "$OUT/mixed.pcap") || fail "classify exited non-zero"
count=$(printf '%s\n' "$lines" | wc -l)
[ "$count" -eq 19 ] || fail "expected 19 lines, got $count"

ip='[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
l4="^[0-9]+ (tcp|udp) $ip:[0-9]+ -> $ip:[0-9]+ len=[0-9]+ dscp=[0-9]+ class=[a-z_]+\$"
noport="^[0-9]+ (tcp|udp|ip/[0-9]+) $ip -> $ip len=[0-9]+ dscp=[0-9]+ class=[a-z_]+\$"
nonip='^[0-9]+ ethertype=0x[0-9a-f]{4} len=[0-9]+ class=unclassified$'
bad=$(printf '%s\n' "$lines" | grep -Ev "$l4|$noport|$nonip" || true)
[ -z "$bad" ] || fail "lines not in the per-packet format: $bad"

# Indexes are 1-based and consecutive.
idx=$(printf '%s\n' "$lines" | awk '{print $1}' | tr '\n' ' ')
[ "$idx" = "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 " ] || fail "indexes: $idx"

expect_line() {
    printf '%s\n' "$lines" | grep -qx -- "$1" || fail "missing line: $1"
}
expect_line '1 udp 192.168.1.10:40000 -> 10.0.0.20:5060 len=76 dscp=46 class=high_priority'
expect_line '2 udp 10.0.0.20:5060 -> 192.168.1.10:40000 len=58 dscp=46 class=high_priority'
expect_line '3 udp 192.168.1.10:16000 -> 10.0.0.20:16002 len=214 dscp=46 class=high_priority'
expect_line '7 tcp 10.0.0.20:22 -> 192.168.1.10:51000 len=75 dscp=0 class=medium_priority'
expect_line '8 tcp 192.168.1.10:51001 -> 10.0.0.20:443 len=118 dscp=0 class=medium_priority'
expect_line '10 tcp 192.168.1.10:51002 -> 10.0.0.20:80 len=89 dscp=0 class=low_priority'
expect_line '12 tcp 192.168.1.10:51003 -> 10.0.0.20:21 len=70 dscp=0 class=low_priority'
expect_line '13 udp 192.168.1.10:40001 -> 10.0.0.20:9999 len=142 dscp=0 class=best_effort'
expect_line '15 tcp 192.168.1.10:51004 -> 10.0.0.20:8080 len=82 dscp=0 class=best_effort'
expect_line '16 ip/1 192.168.1.10 -> 10.0.0.20 len=74 dscp=0 class=best_effort'
expect_line '17 udp 192.168.1.10 -> 10.0.0.20 len=98 dscp=0 class=best_effort'
expect_line '18 ethertype=0x0806 len=42 class=unclassified'
expect_line '19 ethertype=0x86dd len=62 class=unclassified'

# The VLAN-tagged copy gives the same classes as the untagged capture.
plain=$(printf '%s\n' "$lines" | sed 's/.* class=//')
tagged=$(./bwopt classify -r "$OUT/vlan.pcap" | sed 's/.* class=//') \
    || fail "classify vlan.pcap exited non-zero"
[ "$plain" = "$tagged" ] || fail "vlan classes differ: $tagged"
# ... and each tagged frame is 4 bytes longer.
vlen=$(./bwopt classify -r "$OUT/vlan.pcap" | sed -n '1p' | grep -o 'len=[0-9]*')
[ "$vlen" = "len=80" ] || fail "vlan frame 1 $vlen, expected len=80"

# A capture with only non-IP frames is entirely unclassified.
nonip_out=$(./bwopt classify -r "$OUT/nonip.pcap") || fail "classify nonip.pcap failed"
n=$(printf '%s\n' "$nonip_out" | wc -l)
[ "$n" -eq 3 ] || fail "nonip.pcap: expected 3 lines, got $n"
printf '%s\n' "$nonip_out" | grep -qv 'class=unclassified$' && fail "nonip frame classified: $nonip_out"
printf '%s\n' "$nonip_out" | grep -q 'ethertype=0x88cc' || fail "LLDP frame missing: $nonip_out"
./bwopt classify -r "$OUT/nonip.pcap" --summary | grep -q '^unclassified  *3  *' \
    || fail "nonip summary has no unclassified=3 row"

# Frames cut short by the snap length: the ones that do not decode are
# printed from the capture lengths only and counted as unclassified.
[ -s "$OUT/truncated.pcap" ] || fail "$OUT/truncated.pcap missing; run make fixtures"
trunc=$(./bwopt classify -r "$OUT/truncated.pcap") || fail "classify truncated.pcap failed"
want='1 undecoded caplen=10 len=76 class=unclassified
2 undecoded caplen=20 len=76 class=unclassified
3 undecoded caplen=40 len=76 class=unclassified
4 udp 192.168.1.10:40000 -> 10.0.0.20:5060 len=76 dscp=46 class=high_priority
5 undecoded caplen=50 len=75 class=unclassified'
[ "$trunc" = "$want" ] || fail "truncated.pcap output:
$trunc"
./bwopt classify -r "$OUT/truncated.pcap" --summary | grep -q '^unclassified  *4  *' \
    || fail "truncated.pcap summary has no unclassified=4 row"

# A missing file exits 1 with the pcap error message.
rc=0
err=$(./bwopt classify -r /nonexistent.pcap 2>&1 >/dev/null) || rc=$?
[ "$rc" -eq 1 ] || fail "missing pcap exited $rc, expected 1"
echo "$err" | grep -q '/nonexistent.pcap: No such file or directory' \
    || fail "missing pcap error: $err"

# classify without -r is a usage error.
rc=0
./bwopt classify > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "classify without -r exited $rc, expected 2"

# A bad config is a config error even with a valid capture.
rc=0
./bwopt classify -c tests/fixtures/conf/bad_dscp.conf -r "$OUT/mixed.pcap" \
    > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "bad config exited $rc, expected 2"

# -c selects the policy: with signatures.conf, the HTTP request on port 8080
# matches the http signature and moves from best_effort to low_priority.
./bwopt classify -c tests/fixtures/conf/signatures.conf -r "$OUT/mixed.pcap" \
    | grep -qx '15 tcp 192.168.1.10:51004 -> 10.0.0.20:8080 len=82 dscp=0 class=low_priority' \
    || fail "classify -c signatures.conf output wrong"

echo "test_classify: ok"
