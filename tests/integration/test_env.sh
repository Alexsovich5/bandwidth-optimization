#!/bin/bash
# Checks that the image's valgrind runs on this CPU and that the host kernel
# accepts a mangle-table DSCP rule (needs NET_ADMIN).
set -e

fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    iptables -t mangle -F BWTEST 2>/dev/null || true
    iptables -t mangle -X BWTEST 2>/dev/null || true
}
trap cleanup EXIT

valgrind -q --error-exitcode=1 /bin/true || fail "valgrind /bin/true failed"

cleanup
iptables -t mangle -N BWTEST || fail "cannot create mangle chain"
iptables -t mangle -A BWTEST -j DSCP --set-dscp 46 || fail "DSCP target rejected"
iptables -t mangle -S BWTEST | grep -q -- '--set-dscp 0x2e' \
    || fail "DSCP rule not listed"

echo "test_env: ok"
