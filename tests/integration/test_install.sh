#!/bin/bash
# Staged `make install`: the binary goes to $(DESTDIR)$(PREFIX)/sbin and the
# policy file to $(DESTDIR)/etc/bwopt/. Run from the repository root.
set -e

. tests/integration/lib.sh

STAGE=$(mktemp -d /tmp/bwopt_stage.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT

make install DESTDIR="$STAGE" PREFIX=/usr > "$STAGE.log" 2>&1 \
    || { cat "$STAGE.log"; rm -f "$STAGE.log"; fail "make install failed"; }
rm -f "$STAGE.log"

[ -f "$STAGE/usr/sbin/bwopt" ] || fail "usr/sbin/bwopt not installed"
[ -x "$STAGE/usr/sbin/bwopt" ] || fail "usr/sbin/bwopt is not executable"
[ -f "$STAGE/etc/bwopt/policies.conf" ] || fail "etc/bwopt/policies.conf not installed"
cmp -s config/policies.conf "$STAGE/etc/bwopt/policies.conf" \
    || fail "installed policies.conf differs from config/policies.conf"
perm=$(stat -c %a "$STAGE/etc/bwopt/policies.conf")
[ "$perm" = "644" ] || fail "policies.conf mode is $perm, expected 644"

# Nothing else is installed.
files=$(cd "$STAGE" && find . -type f | sort | tr '\n' ' ')
[ "$files" = "./etc/bwopt/policies.conf ./usr/sbin/bwopt " ] || fail "installed files: $files"

out=$("$STAGE/usr/sbin/bwopt" --version)
[ "$out" = "bwopt 0.1.0" ] || fail "staged binary printed '$out'"

# The staged config is accepted by the staged binary.
"$STAGE/usr/sbin/bwopt" check-config -c "$STAGE/etc/bwopt/policies.conf" > /dev/null \
    || fail "staged binary rejects the staged config"

echo "test_install: ok"
