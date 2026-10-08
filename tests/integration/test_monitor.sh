#!/bin/bash
# Offline monitor runs over the generated mixed.pcap, checked through
# sqlite3 and the report command, then live runs on the dummy interface
# bw0 (needs NET_ADMIN). Run from the repository root after `make fixtures`.
set -e

. tests/integration/lib.sh

OUT=tests/fixtures/out
DB=/tmp/bwopt_monitor.$$.db
TMP=$(mktemp -d /tmp/bwopt_monitor.XXXXXX)
cleanup() {
    [ -n "$LIVE_PID" ] && kill "$LIVE_PID" 2> /dev/null || true
    bw0_remove
    rm -rf "$DB" "$TMP"
}
trap cleanup EXIT

[ -s "$OUT/mixed.pcap" ] || fail "$OUT/mixed.pcap missing; run make fixtures"
rm -f "$DB"

# mixed.pcap holds 19 frames 100 ms apart, so a 1 s interval gives two
# flushes (the second one at end of file) of 5 rows each.
./bwopt monitor -r "$OUT/mixed.pcap" --interval 1 --db "$DB" > /dev/null \
    || fail "monitor -r exited non-zero"

rows=$(sqlite3 "$DB" 'SELECT COUNT(*) FROM samples')
[ "$rows" -eq 10 ] || fail "expected 10 sample rows, got $rows"
times=$(sqlite3 "$DB" 'SELECT DISTINCT ts FROM samples ORDER BY ts' | tr '\n' ' ')
[ "$times" = "1000000001 1000000002 " ] || fail "flush times: $times"
ifaces=$(sqlite3 "$DB" 'SELECT DISTINCT iface FROM samples')
[ "$ifaces" = "eth0" ] || fail "iface column: $ifaces"

# Per-class packet and byte sums equal the classify summary, including
# the unclassified row, in config order.
{
    printf '%-16s %8s %10s\n' class packets bytes
    for c in high_priority medium_priority low_priority best_effort unclassified; do
        sqlite3 -separator ' ' "$DB" \
            "SELECT SUM(packets), SUM(bytes) FROM samples WHERE class = '$c'" |
            while read -r p b; do printf '%-16s %8s %10s\n' "$c" "$p" "$b"; done
    done
} > "$DB.summary"
diff -u tests/expected/mixed.summary "$DB.summary" || { rm -f "$DB.summary"; fail "sums differ"; }
rm -f "$DB.summary"

# Rates use packet timestamps: high_priority sent 776 bytes in the first second.
bps=$(sqlite3 "$DB" "SELECT bps FROM samples WHERE ts = 1000000001 AND class = 'high_priority'")
[ "$bps" = "6208" ] || fail "high_priority bps in the first interval: $bps"

# report matches the expected table exactly.
./bwopt report --db "$DB" > "$DB.report" || fail "report exited non-zero"
diff -u tests/expected/mixed.report "$DB.report" || { rm -f "$DB.report"; fail "report differs"; }

# --iface and --since filter the rows.
./bwopt report --db "$DB" --iface eth0 | cmp -s - "$DB.report" || fail "--iface eth0 differs"
rm -f "$DB.report"
n=$(./bwopt report --db "$DB" --iface eth9 | wc -l)
[ "$n" -eq 2 ] || fail "--iface eth9 should give a header and a note, got $n lines"
./bwopt report --db "$DB" --since 1000000002 | grep -q '^eth0  *low_priority  *1  *2  *143  *1144  *1144$' \
    || fail "--since did not keep only the last interval"

# The default interval comes from update_interval (30 s): one final flush.
rm -f "$DB"
./bwopt monitor -r "$OUT/mixed.pcap" --db "$DB" > /dev/null || fail "monitor without --interval failed"
rows=$(sqlite3 "$DB" 'SELECT COUNT(*) FROM samples')
[ "$rows" -eq 5 ] || fail "expected 5 rows with the 30 s interval, got $rows"

# A second run over the same capture would duplicate (ts, iface, class): exit 1.
rc=0
./bwopt monitor -r "$OUT/mixed.pcap" --db "$DB" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "duplicate samples exited $rc, expected 1"

# A database path that cannot be opened exits 1 with the SQLite error.
rc=0
err=$(./bwopt monitor -r "$OUT/mixed.pcap" --db /nonexistent/dir/m.db 2>&1 >/dev/null) || rc=$?
[ "$rc" -eq 1 ] || fail "unopenable db exited $rc, expected 1"
echo "$err" | grep -q '/nonexistent/dir/m.db: unable to open database file' \
    || fail "unopenable db error: $err"

# Without --db the shipped database path is used; its directory does not exist here.
rc=0
err=$(./bwopt monitor -r "$OUT/mixed.pcap" 2>&1 >/dev/null) || rc=$?
[ "$rc" -eq 1 ] || fail "default db exited $rc, expected 1"
echo "$err" | grep -q '/var/lib/bandwidth_optimizer/metrics.db' || fail "default db error: $err"

# report on a missing database is an error, not a new empty file.
rc=0
./bwopt report --db /tmp/bwopt_missing.$$.db > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "report on a missing db exited $rc, expected 1"
[ ! -e /tmp/bwopt_missing.$$.db ] || fail "report created the missing db"

# Usage errors.
for args in "monitor" "monitor -r $OUT/mixed.pcap --interval 0" \
            "monitor -r $OUT/mixed.pcap --interval x" "report" "report --db $DB --since x" \
            "monitor -i lo -r $OUT/mixed.pcap" "monitor -i lo --duration 0" \
            "monitor -i lo --duration x"; do
    rc=0
    ./bwopt $args > /dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || fail "'$args' exited $rc, expected 2"
done

# A missing capture exits 1.
rc=0
./bwopt monitor -r /nonexistent.pcap --db "$DB" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "missing pcap exited $rc, expected 1"

# --- live --------------------------------------------------------------

# An interface that does not exist, or a log file that cannot be opened, exits 1.
rc=0
err=$(./bwopt monitor -i nosuch0 --duration 1 --db "$TMP/e.db" --log "$TMP/e.log" 2>&1 >/dev/null) \
    || rc=$?
[ "$rc" -eq 1 ] || fail "unknown interface exited $rc, expected 1"
echo "$err" | grep -q nosuch0 || fail "unknown interface error: $err"
rc=0
err=$(./bwopt monitor -i lo --duration 1 --db "$TMP/e.db" --log /nonexistent/dir/l.log 2>&1 >/dev/null) \
    || rc=$?
[ "$rc" -eq 1 ] || fail "unopenable log exited $rc, expected 1"
echo "$err" | grep -q '/nonexistent/dir/l.log' || fail "unopenable log error: $err"

if ! bw0_create; then
    echo "test_monitor: live part SKIP (ip link add bw0 type dummy is not permitted here)"
    echo "test_monitor: ok"
    exit 0
fi

# sums CLASS: "packets bytes" stored for CLASS on bw0 in database $1.
sums() {
    sqlite3 -separator ' ' "$1" \
        "SELECT COALESCE(SUM(packets),0), COALESCE(SUM(bytes),0) FROM samples
         WHERE iface = 'bw0' AND class = '$2'"
}

# --duration: 20 one-byte datagrams to 5060 (43-byte frames) land in
# high_priority, and the log has a start line, flush lines and a stop line.
LDB=$TMP/l.db
LLOG=$TMP/l.log
start=$(date +%s)
./bwopt monitor -i bw0 --interval 1 --duration 3 --db "$LDB" --log "$LLOG" > "$TMP/l.out" 2>&1 &
LIVE_PID=$!
sleep 1
send_udp 5060 20
rc=0
wait "$LIVE_PID" || rc=$?
LIVE_PID=
end=$(date +%s)
[ "$rc" -eq 0 ] || { cat "$TMP/l.out"; fail "live monitor exited $rc"; }
elapsed=$((end - start))
[ "$elapsed" -ge 2 ] && [ "$elapsed" -le 5 ] || fail "--duration 3 ran for ${elapsed}s"
[ "$(sums "$LDB" high_priority)" = "20 860" ] \
    || fail "high_priority on bw0: $(sums "$LDB" high_priority), expected 20 860"
[ "$(sums "$LDB" medium_priority)" = "0 0" ] || fail "medium_priority got traffic"
flushes=$(sqlite3 "$LDB" "SELECT COUNT(DISTINCT ts) FROM samples WHERE iface = 'bw0'")
[ "$flushes" -ge 2 ] || fail "expected at least 2 wall-clock flushes, got $flushes"
grep -q 'monitor started on bw0' "$LLOG" || { cat "$LLOG"; fail "no start line in the log"; }
grep -q 'monitor stopped' "$LLOG" || { cat "$LLOG"; fail "no stop line in the log"; }
n=$(grep -c ' flush ' "$LLOG")
[ "$n" -eq "$flushes" ] || { cat "$LLOG"; fail "$n flush lines for $flushes flushes"; }

# The log is appended to, not truncated.
./bwopt monitor -i bw0 --duration 1 --db "$TMP/a.db" --log "$LLOG" > /dev/null \
    || fail "second live run failed"
n=$(grep -c 'monitor started on bw0' "$LLOG")
[ "$n" -eq 2 ] || fail "log has $n start lines after two runs, expected 2"

# SIGTERM with a 30 s interval: only the final flush can write the rows.
TDB=$TMP/t.db
./bwopt monitor -i bw0 --interval 30 --db "$TDB" --log "$TMP/t.log" > "$TMP/t.out" 2>&1 &
LIVE_PID=$!
sleep 1
send_udp 443 5
sleep 0.5
kill -TERM "$LIVE_PID"
rc=0
wait "$LIVE_PID" || rc=$?
LIVE_PID=
[ "$rc" -eq 0 ] || { cat "$TMP/t.out"; fail "SIGTERM run exited $rc, expected 0"; }
[ "$(sums "$TDB" medium_priority)" = "5 215" ] \
    || fail "medium_priority after SIGTERM: $(sums "$TDB" medium_priority), expected 5 215"
grep -q 'monitor stopped' "$TMP/t.log" || fail "no stop line after SIGTERM"

# SIGINT stops it the same way.
./bwopt monitor -i bw0 --interval 30 --db "$TMP/i.db" --log "$TMP/i.log" > /dev/null 2>&1 &
LIVE_PID=$!
sleep 1
kill -INT "$LIVE_PID"
rc=0
wait "$LIVE_PID" || rc=$?
LIVE_PID=
[ "$rc" -eq 0 ] || fail "SIGINT run exited $rc, expected 0"
rows=$(sqlite3 "$TMP/i.db" 'SELECT COUNT(*) FROM samples')
[ "$rows" -eq 5 ] || fail "SIGINT run wrote $rows rows, expected 5"

echo "test_monitor: ok"
