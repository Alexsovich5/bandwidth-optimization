#!/bin/bash
# apply and clear on a dummy interface: the generated tc tree and BWOPT
# chain are installed, steer UDP traffic into the right HTB classes, and
# are removed again. Needs NET_ADMIN. Run from the repository root.
set -e

. tests/integration/lib.sh

TMP=$(mktemp -d /tmp/bwopt_apply.XXXXXX)
cleanup() {
    ./bwopt clear -i "$BW_IFACE" > /dev/null 2>&1 || true
    bw0_remove
    rm -rf "$TMP"
}
trap cleanup EXIT

# --- dry run (needs no interface) --------------------------------------

{
    echo "tc qdisc del dev bw0 root"
    echo "iptables -t mangle -F BWOPT"
    echo "iptables -t mangle -D POSTROUTING -o bw0 -j BWOPT"
    echo "iptables -t mangle -X BWOPT"
    sed 's/dev eth0 /dev bw0 /' tests/golden/policies.tc
    sed 's/-o eth0 /-o bw0 /' tests/golden/policies.iptables
} > "$TMP/apply.dry"
./bwopt apply -i bw0 --dry-run > "$TMP/apply.out" || fail "apply --dry-run exited non-zero"
diff -u "$TMP/apply.dry" "$TMP/apply.out" || fail "apply --dry-run output wrong"

head -4 "$TMP/apply.dry" > "$TMP/clear.dry"
./bwopt clear --interface bw0 --dry-run > "$TMP/clear.out" || fail "clear --dry-run failed"
diff -u "$TMP/clear.dry" "$TMP/clear.out" || fail "clear --dry-run output wrong"

rc=0
./bwopt apply -c tests/fixtures/conf/bad_dscp.conf --dry-run > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "apply with a bad config exited $rc, expected 2"

# --- live --------------------------------------------------------------

if ! bw0_create; then
    echo "test_apply: SKIP (ip link add bw0 type dummy is not permitted here)"
    exit 0
fi

tc qdisc show dev bw0 | grep -q htb && fail "fresh bw0 already has an htb qdisc"
iptables -t mangle -S BWOPT > /dev/null 2>&1 && fail "BWOPT chain exists before apply"

./bwopt apply -i bw0 > "$TMP/apply1.log" 2>&1 || { cat "$TMP/apply1.log"; fail "first apply failed"; }

tc class show dev bw0 > "$TMP/classes"
expect_class() {
    grep -q "^class htb $1 .*rate $2 ceil 100000Kbit" "$TMP/classes" \
        || { cat "$TMP/classes"; fail "class $1 with rate $2 missing"; }
}
expect_class 1:1 100000Kbit
expect_class 1:10 30000Kbit
expect_class 1:20 40000Kbit
expect_class 1:30 20000Kbit
expect_class 1:40 10000Kbit

# iptables -S prints the golden rules with the match module and hex DSCP.
{
    echo "-N BWOPT"
    sed -n 's/^iptables -t mangle \(-A BWOPT .*\)$/\1/p' tests/golden/policies.iptables \
        | while read -r line; do
            proto=$(printf '%s\n' "$line" | sed 's/.* -p \([a-z]*\) .*/\1/')
            dscp=${line##* }
            printf '%s\n' "$line" \
                | sed "s/ -p $proto / -p $proto -m $proto /; s/--set-dscp $dscp\$/--set-dscp $(printf '0x%02x' "$dscp")/"
        done
} > "$TMP/rules.want"
iptables -t mangle -S BWOPT > "$TMP/rules.got" || fail "BWOPT chain missing after apply"
diff -u "$TMP/rules.want" "$TMP/rules.got" || fail "BWOPT rules differ from golden"
iptables -t mangle -S POSTROUTING | grep -qx -- '-A POSTROUTING -o bw0 -j BWOPT' \
    || fail "BWOPT not hooked into POSTROUTING for bw0"

# Marked traffic lands in its class.
declare -A before
for id in 1:10 1:20 1:30 1:40; do
    before[$id]=$(class_packets $id)
done
send_udp 5060 5
send_udp 443 5
send_udp 80 5
send_udp 9999 5
delta() { echo $(( $(class_packets "$1") - ${before[$1]} )); }
[ "$(delta 1:10)" -eq 5 ] || fail "1:10 (port 5060) counted $(delta 1:10), expected 5"
[ "$(delta 1:20)" -eq 5 ] || fail "1:20 (port 443) counted $(delta 1:20), expected 5"
[ "$(delta 1:30)" -eq 5 ] || fail "1:30 (port 80) counted $(delta 1:30), expected 5"
[ "$(delta 1:40)" -ge 5 ] || fail "1:40 (port 9999) counted $(delta 1:40), expected >= 5"

# apply can be run again over an existing policy.
./bwopt apply -i bw0 > "$TMP/apply2.log" 2>&1 || { cat "$TMP/apply2.log"; fail "second apply failed"; }
[ "$(iptables -t mangle -S POSTROUTING | grep -c -- '-j BWOPT')" -eq 1 ] \
    || fail "second apply duplicated the POSTROUTING hook"
tc class show dev bw0 | grep -q '^class htb 1:40 ' || fail "tree missing after second apply"

# clear removes everything; a second clear fails and names the command.
./bwopt clear -i bw0 || fail "clear failed"
tc qdisc show dev bw0 | grep -q htb && fail "htb qdisc left after clear"
iptables -t mangle -S BWOPT > /dev/null 2>&1 && fail "BWOPT chain left after clear"
iptables -t mangle -S POSTROUTING | grep -q -- '-j BWOPT' && fail "POSTROUTING hook left"

rc=0
./bwopt clear -i bw0 > "$TMP/clear2.out" 2> "$TMP/clear2.err" || rc=$?
[ "$rc" -eq 1 ] || fail "second clear exited $rc, expected 1"
grep -q 'command failed.*: tc qdisc del dev bw0 root$' "$TMP/clear2.err" \
    || { cat "$TMP/clear2.err"; fail "second clear did not name the failing command"; }

echo "test_apply: ok"
