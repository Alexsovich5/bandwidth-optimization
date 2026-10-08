#!/bin/bash
# autotune and monitor --autotune against a database seeded with sqlite3:
# a saturated high_priority and an idle best_effort move 5 Mbit from 1:40
# to 1:10 with tc class change, keeping burst and prio. The live parts need
# NET_ADMIN and the dummy interface bw0. Run from the repository root.
set -e

. tests/integration/lib.sh

OUT=tests/fixtures/out
TMP=$(mktemp -d /tmp/bwopt_autotune.XXXXXX)
LIVE_PID=
cleanup() {
    [ -n "$LIVE_PID" ] && kill "$LIVE_PID" 2> /dev/null || true
    ./bwopt clear -i "$BW_IFACE" > /dev/null 2>&1 || true
    bw0_remove
    rm -rf "$TMP"
}
trap cleanup EXIT

# seed DB IFACE FIRST_TS: 10 samples per class ending at FIRST_TS..FIRST_TS+9
# with high_priority at 100% of 30 Mbit, medium and low priority at 60% of
# their configured rate and best_effort idle.
seed() {
    local i ts
    {
        echo "PRAGMA user_version = 1;"
        echo "CREATE TABLE IF NOT EXISTS samples (ts INTEGER NOT NULL, iface TEXT NOT NULL,"
        echo "  class TEXT NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL,"
        echo "  bps INTEGER NOT NULL, PRIMARY KEY (ts, iface, class));"
        echo "CREATE TABLE IF NOT EXISTS tuning (ts INTEGER NOT NULL, iface TEXT NOT NULL,"
        echo "  class TEXT NOT NULL, old_rate INTEGER NOT NULL, new_rate INTEGER NOT NULL);"
        echo "BEGIN;"
        for ((i = 0; i < 10; i++)); do
            ts=$(($3 + i))
            echo "INSERT INTO samples VALUES ($ts, '$2', 'high_priority', 2500, 3750000, 30000000);"
            echo "INSERT INTO samples VALUES ($ts, '$2', 'medium_priority', 2000, 3000000, 24000000);"
            echo "INSERT INTO samples VALUES ($ts, '$2', 'low_priority', 1000, 1500000, 12000000);"
            echo "INSERT INTO samples VALUES ($ts, '$2', 'best_effort', 0, 0, 0);"
            echo "INSERT INTO samples VALUES ($ts, '$2', 'unclassified', 3, 200, 160);"
        done
        echo "COMMIT;"
    } | sqlite3 "$1"
}

tuning_rows() { sqlite3 "$1" "SELECT COUNT(*) FROM tuning"; }

# --- usage errors --------------------------------------------------------

rc=0
./bwopt autotune > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "autotune without --db exited $rc, expected 2"
rc=0
./bwopt autotune --db /nonexistent/dir/m.db > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "autotune with a missing database exited $rc, expected 1"

# --- print only (needs no interface) ---------------------------------------

seed "$TMP/print.db" bw0 1000
./bwopt autotune --db "$TMP/print.db" -i bw0 > "$TMP/print.out" || fail "autotune (print) failed"
cat > "$TMP/print.want" << 'EOF'
tc class change dev bw0 parent 1:1 classid 1:10 htb rate 35000000bit ceil 100000000bit burst 32k prio 0
tc class change dev bw0 parent 1:1 classid 1:40 htb rate 5000000bit ceil 100000000bit burst 256k prio 3
EOF
diff -u "$TMP/print.want" "$TMP/print.out" || fail "autotune printed the wrong change lines"
[ "$(tuning_rows "$TMP/print.db")" -eq 0 ] || fail "autotune without --apply recorded tuning rows"

# Samples of another interface are not used.
./bwopt autotune --db "$TMP/print.db" -i bw9 > "$TMP/other.out" || fail "autotune -i bw9 failed"
grep -q '^tc ' "$TMP/other.out" && fail "autotune -i bw9 used the samples of bw0"

# Fewer than window samples: nothing to do.
sqlite3 "$TMP/print.db" "DELETE FROM samples WHERE ts > 1004"
./bwopt autotune --db "$TMP/print.db" -i bw0 > "$TMP/short.out" || fail "autotune (short) failed"
grep -q '^tc ' "$TMP/short.out" && fail "autotune ran with fewer than window samples"

# monitor --autotune --dry-run: samples newer than mixed.pcap are the last
# window, so the first flush computes the change, which is only printed.
[ -s "$OUT/mixed.pcap" ] || fail "$OUT/mixed.pcap missing; run make fixtures"
seed "$TMP/dry.db" eth0 2000000000
./bwopt monitor -r "$OUT/mixed.pcap" --interval 1 --db "$TMP/dry.db" --autotune --dry-run \
    > "$TMP/dry.out" || fail "monitor --autotune --dry-run failed"
grep -q '^autotune (dry run): tc class change dev eth0 parent 1:1 classid 1:40 htb rate 5000000bit' \
    "$TMP/dry.out" || { cat "$TMP/dry.out"; fail "monitor --dry-run did not print the change"; }
[ "$(tuning_rows "$TMP/dry.db")" -eq 0 ] || fail "monitor --dry-run recorded tuning rows"

# --- live ------------------------------------------------------------------

if ! bw0_create; then
    echo "test_autotune: SKIP live part (ip link add bw0 type dummy is not permitted here)"
    exit 0
fi
./bwopt apply -i bw0 > /dev/null || fail "apply failed"

class_line() { tc class show dev bw0 classid "$1"; }
expect() {
    class_line "$1" | grep -q "$2" || { class_line "$1"; fail "class $1 lacks '$2'"; }
}

DB=$TMP/live.db
seed "$DB" bw0 1000

./bwopt autotune --db "$DB" -i bw0 > /dev/null || fail "autotune (print) failed"
expect 1:40 'rate 10000Kbit'
expect 1:10 'rate 30000Kbit'

./bwopt autotune --db "$DB" -i bw0 --apply > "$TMP/apply1.out" \
    || { cat "$TMP/apply1.out"; fail "autotune --apply failed"; }
expect 1:40 'rate 5000Kbit ceil 100000Kbit burst 256Kb'
expect 1:40 'prio 3'
expect 1:10 'rate 35000Kbit ceil 100000Kbit burst 32Kb'
expect 1:10 'prio 0'
expect 1:20 'rate 40000Kbit .*burst 64Kb'
expect 1:20 'prio 1'
[ "$(tuning_rows "$DB")" -eq 2 ] || fail "expected 2 tuning rows, got $(tuning_rows "$DB")"
rows=$(sqlite3 -separator ' ' "$DB" "SELECT iface, class, old_rate, new_rate FROM tuning ORDER BY class")
[ "$rows" = "bw0 best_effort 10000000 5000000
bw0 high_priority 30000000 35000000" ] || fail "tuning rows: $rows"

# The same samples again: targets come from configured rates, so nothing changes.
./bwopt autotune --db "$DB" -i bw0 --apply > "$TMP/apply2.out" || fail "second autotune failed"
grep -q '^tc ' "$TMP/apply2.out" && fail "second autotune printed changes"
[ "$(tuning_rows "$DB")" -eq 2 ] || fail "second autotune added tuning rows"
expect 1:40 'rate 5000Kbit'
expect 1:10 'rate 35000Kbit'

# monitor --autotune on the live interface: re-apply the configured tree,
# seed samples newer than the live flushes, and the first flush moves the rates.
./bwopt apply -i bw0 > /dev/null || fail "re-apply failed"
DB2=$TMP/monitor.db
seed "$DB2" bw0 2000000000
./bwopt monitor -i bw0 --interval 1 --duration 2 --autotune --db "$DB2" --log "$TMP/m.log" \
    > "$TMP/monitor.out" 2>&1 || { cat "$TMP/monitor.out"; fail "monitor --autotune failed"; }
expect 1:40 'rate 5000Kbit .*burst 256Kb'
expect 1:10 'rate 35000Kbit .*burst 32Kb'
[ "$(tuning_rows "$DB2")" -eq 2 ] || fail "monitor --autotune: expected 2 tuning rows"
grep -q 'autotune: best_effort 10000000 -> 5000000 bit/s' "$TMP/m.log" \
    || { cat "$TMP/m.log"; fail "monitor log has no autotune line"; }

echo "test_autotune: ok"
