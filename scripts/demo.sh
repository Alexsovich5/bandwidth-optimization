#!/bin/bash
# Demo on a dummy interface: applies config/policies.conf to bw0, sends
# mixed UDP traffic while `bwopt monitor` runs for 5 s, then prints the
# stored per-class report and the HTB class counters.
# Needs NET_ADMIN; run from the repository root (docker compose run --rm demo).
set -e

. tests/integration/lib.sh

DB=/tmp/demo.db
LOG=/tmp/demo.log

cleanup() {
    ./bwopt clear -i "$BW_IFACE" > /dev/null 2>&1 || true
    bw0_remove
}
trap cleanup EXIT

make -s bwopt

bw0_create || fail "cannot create the dummy interface $BW_IFACE (NET_ADMIN missing?)"
rm -f "$DB" "$LOG"

echo "== apply policy to $BW_IFACE"
./bwopt apply -i "$BW_IFACE"

echo "== monitor $BW_IFACE for 5 s while sending traffic"
./bwopt monitor -i "$BW_IFACE" --interval 1 --duration 5 --db "$DB" --log "$LOG" &
MON_PID=$!
sleep 1
# SIP and RTP (high_priority), HTTPS (medium_priority), HTTP (low_priority)
# and an unlisted port (best_effort).
for round in 1 2 3; do
    send_udp 5060 20
    send_udp 10500 30
    send_udp 443 25
    send_udp 80 15
    send_udp 9999 10
    sleep 1
done
wait "$MON_PID"

echo "== bwopt report --db $DB"
./bwopt report --db "$DB"

echo "== monitor log ($LOG)"
cat "$LOG"

echo "== tc -s class show dev $BW_IFACE"
tc -s class show dev "$BW_IFACE"
