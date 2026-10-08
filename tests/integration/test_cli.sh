#!/bin/bash
# CLI exit codes and version output. Run from the repository root.
set -e

fail() { echo "FAIL: $*" >&2; exit 1; }

out=$(./bwopt --version)
[ "$out" = "bwopt 0.1.0" ] || fail "--version printed '$out'"

./bwopt --help > /tmp/bwopt_help.$$ || fail "--help exited non-zero"
grep -q '^Usage: bwopt' /tmp/bwopt_help.$$ || fail "--help has no usage line"
rm -f /tmp/bwopt_help.$$

rc=0
./bwopt > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "no subcommand exited $rc, expected 2"

rc=0
./bwopt no-such-command > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "unknown subcommand exited $rc, expected 2"

echo "test_cli: ok"
