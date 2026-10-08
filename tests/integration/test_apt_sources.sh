#!/bin/bash
# Package retrieval for the image stays authenticated: every Dockerfile and
# apt file in the repository is free of signature bypasses and plain-HTTP
# sources, and docker/apt/fetch-debs.sh keeps its HTTPS-only download and
# gpgv / SHA256 checks. Run from the repository root.
set -e

fail() { echo "FAIL: $*" >&2; exit 1; }

TMP=$(mktemp -d /tmp/bwopt_apt.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

BYPASS='--allow-unauthenticated|--force-yes|trusted=yes|AllowUnauthenticated|--no-check-gpg|allow-insecure|http://'

# Prints every forbidden line of the given files as FILE:LINE:TEXT.
scan() {
    grep -nHiE -- "$BYPASS" "$@" || true
}

# The scanner itself must catch each form of the bypass.
cat > "$TMP/Dockerfile.bad" <<'EOF'
RUN echo 'deb http://archive.debian.org/debian wheezy main' > /etc/apt/sources.list
RUN echo 'APT::Get::AllowUnauthenticated "true";' > /etc/apt/apt.conf.d/10archive
RUN apt-get install -y --force-yes make
RUN apt-get install -y --allow-unauthenticated make
RUN echo 'deb [trusted=yes] https://example.invalid/debian wheezy main' > /etc/apt/sources.list
RUN apt-get -o Acquire::AllowInsecureRepositories=true --no-check-gpg update
EOF
found=$(scan "$TMP/Dockerfile.bad" | wc -l)
[ "$found" -eq 6 ] || fail "scanner found $found of 6 bypass lines"

# Every Dockerfile and apt configuration file in the repository.
files=$(find . -path ./.git -prune -o -path ./tests/fixtures/out -prune -o -type f \
        \( -name 'Dockerfile*' -o -name '*.dockerfile' -o -path './docker/apt/*' \
           -o -name '*.list' -o -name '*.sources' -o -path '*apt.conf*' \) -print | sort)
echo "$files" | grep -qx './Dockerfile' || fail "Dockerfile not found by the scan"
echo "$files" | grep -qx './docker/apt/fetch-debs.sh' || fail "docker/apt not found by the scan"
# shellcheck disable=SC2086
bad=$(scan $files)
[ -z "$bad" ] || fail "unauthenticated or plain-HTTP package source:
$bad"

# Every package source is an HTTPS URL.
grep -v '^ *#' docker/apt/sources.conf | awk 'NF { print $2 }' > "$TMP/urls"
[ -s "$TMP/urls" ] || fail "docker/apt/sources.conf lists no sources"
if grep -v '^https://' "$TMP/urls"; then
    fail "docker/apt/sources.conf has a non-HTTPS source"
fi

# fetch-debs.sh: HTTPS only (redirects too), Release signature checked with
# gpgv against the Debian keyrings, Packages and every .deb checked by SHA256.
f=docker/apt/fetch-debs.sh
grep -q -- "--proto '=https' --proto-redir '=https'" "$f" || fail "$f allows non-HTTPS downloads"
grep -q 'gpgv --status-fd' "$f" || fail "$f does not verify Release with gpgv"
grep -q 'debian-archive-keyring.gpg' "$f" || fail "$f does not use the archive keyring"
grep -q 'debian-archive-removed-keys.gpg' "$f" || fail "$f does not use the removed keys"
grep -q 'VALIDSIG' "$f" || fail "$f does not require a valid signature"
[ "$(grep -c '^ *check_sha256 "' "$f")" -ge 2 ] || fail "$f does not check Packages and .deb SHA256"

# The wheezy stage installs from the verified set only: dpkg, no apt-get.
wheezy=$(awk '/^FROM debian:wheezy/ { s = 1 } s' Dockerfile)
[ -n "$wheezy" ] || fail "Dockerfile has no debian:wheezy stage"
if echo "$wheezy" | grep -q 'apt-get'; then fail "the wheezy stage runs apt-get"; fi
echo "$wheezy" | grep -q 'dpkg -i' || fail "the wheezy stage does not install the verified debs"

# Inside the image, apt has no sources and no bypass settings left.
if [ -d /etc/apt ] && [ -e /opt/asan ]; then
    srcs=$(cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true)
    [ -z "$srcs" ] || fail "the image still has apt sources: $srcs"
    if apt-config dump | grep -iE 'AllowUnauthenticated "(true|1)"|AllowInsecure'; then
        fail "apt in the image allows unauthenticated packages"
    fi
fi

echo "test_apt_sources: ok"
