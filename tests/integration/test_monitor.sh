#!/bin/bash
# Offline monitor runs over the generated mixed.pcap, checked through
# sqlite3 and the report command. Run from the repository root after
# `make fixtures`.
set -e

fail() { echo "FAIL: $*" >&2; exit 1; }

OUT=tests/fixtures/out
DB=/tmp/bwopt_monitor.$$.db
trap 'rm -f "$DB"' EXIT

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
            "monitor -r $OUT/mixed.pcap --interval x" "report" "report --db $DB --since x"; do
    rc=0
    ./bwopt $args > /dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || fail "'$args' exited $rc, expected 2"
done

# A missing capture exits 1.
rc=0
./bwopt monitor -r /nonexistent.pcap --db "$DB" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "missing pcap exited $rc, expected 1"

echo "test_monitor: ok"
