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

# check-config: the shipped file is valid and the class table is printed.
out=$(./bwopt check-config -c config/policies.conf) || fail "check-config on shipped config failed"
for name in high_priority medium_priority low_priority best_effort; do
    echo "$out" | grep -q "^$name " || fail "class table has no row for $name"
done
echo "$out" | grep -q '^high_priority  *30% *46 *30000000 *32k *1:10 *0$' \
    || fail "high_priority row wrong: $out"

# --config is the long form of -c.
long=$(./bwopt check-config --config config/policies.conf) || fail "--config form failed"
[ "$out" = "$long" ] || fail "--config output differs from -c output"

# The default config path is config/policies.conf.
dflt=$(./bwopt check-config) || fail "check-config without -c failed"
[ "$out" = "$dflt" ] || fail "default config output differs from -c output"

rc=0
err=$(./bwopt check-config -c tests/fixtures/conf/bad_dscp.conf 2>&1 >/dev/null) || rc=$?
[ "$rc" -eq 2 ] || fail "bad_dscp.conf exited $rc, expected 2"
echo "$err" | grep -q 'bad_dscp.conf:8:' || fail "bad_dscp.conf error has no line number: $err"

rc=0
./bwopt check-config --config tests/fixtures/conf/dup_dscp.conf > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "dup_dscp.conf via --config exited $rc, expected 2"

rc=0
./bwopt check-config -c /nonexistent.conf > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || fail "missing config exited $rc, expected 2"

# README doc check: no badges, no claimed efficiency figure, and the Layout
# tree lists exactly the files tracked by git.
[ -f README.md ] || fail "README.md missing"
if grep -q 'img.shields.io' README.md; then fail "README has a shields.io badge"; fi
if grep -q 'Status-Complete' README.md; then fail "README has a Status-Complete badge"; fi
if grep -iE '[0-9]+% (bandwidth )?efficiency' README.md; then
    fail "README claims an efficiency figure"
fi

# The Layout block is the first fenced block after "## Layout". Each line is a
# file or a directory ending in "/", indented two spaces per level.
layout=$(awk '
    /^## Layout/ { inlayout = 1; next }
    inlayout && /^```/ { if (inblock) exit; inblock = 1; next }
    inblock { print }' README.md | awk '
    {
        match($0, /^ */)
        depth = RLENGTH / 2
        name = substr($0, RLENGTH + 1)
        if (name == "") next
        prefix = ""
        for (i = 0; i < depth; i++) prefix = prefix dir[i]
        if (name ~ /\/$/) { dir[depth] = name; next }
        print prefix name
    }' | sort)
[ -n "$layout" ] || fail "README has no Layout block"

for f in $layout; do
    [ -e "$f" ] || fail "README Layout names $f, which does not exist"
done

if [ ! -d .git ]; then
    echo "test_cli: skipping git ls-files comparison (.git is not in the mount)"
elif ! command -v git > /dev/null 2>&1; then
    echo "test_cli: skipping git ls-files comparison (git is not installed)"
else
    tracked=$(git ls-files | sort)
    if [ "$layout" != "$tracked" ]; then
        diff <(echo "$tracked") <(echo "$layout") >&2 || true
        fail "README Layout tree differs from git ls-files (< git, > README)"
    fi
fi

echo "test_cli: ok"
