#!/bin/bash
# HTB shaping script generation (tc-script). Run from the repository root.
set -e

fail() { echo "FAIL: $*" >&2; exit 1; }

TMP=$(mktemp -d /tmp/bwopt_tc.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

./bwopt tc-script > "$TMP/tc" || fail "tc-script exited non-zero"
diff -u tests/golden/policies.tc "$TMP/tc" || fail "tc-script differs from golden"

for opt in -i --interface; do
    ./bwopt tc-script $opt bw0 > "$TMP/tc.$opt" || fail "tc-script $opt bw0 exited non-zero"
    sed 's/dev eth0 /dev bw0 /' tests/golden/policies.tc | diff -u - "$TMP/tc.$opt" \
        || fail "tc-script $opt bw0 did not substitute the interface"
done

./bwopt tc-script -c tests/fixtures/conf/one_class.conf > "$TMP/one" \
    || fail "tc-script on one_class.conf exited non-zero"
if grep -q '^tc filter' "$TMP/one"; then
    fail "one-class config produced filters"
fi

rc=0
./bwopt tc-script -c tests/fixtures/conf/bad_dscp.conf > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "tc-script on bad_dscp.conf exited $rc, expected 2"

echo "test_tc_script: ok"
