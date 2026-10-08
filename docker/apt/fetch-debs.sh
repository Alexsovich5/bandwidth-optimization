#!/bin/bash
# fetch-debs.sh SOURCES LOCK OUTDIR
#
# Downloads the exact package versions listed in LOCK into OUTDIR and
# verifies the whole chain before anything is used:
#   1. dists/<dist>/Release and Release.gpg over HTTPS, checked with gpgv
#      against the Debian archive keyrings (current and removed keys; the
#      wheezy and squeeze keys have expired, which does not make their
#      signatures any less checkable), and the Release Codename;
#   2. main/binary-amd64/Packages.gz against its SHA256 in Release;
#   3. each .deb against its SHA256 in Packages.
# Any failure aborts with a non-zero exit status.
set -euo pipefail

SOURCES=$1
LOCK=$2
OUT=$3

KEYRINGS="/usr/share/keyrings/debian-archive-keyring.gpg
/usr/share/keyrings/debian-archive-removed-keys.gpg"
INDEX=main/binary-amd64/Packages.gz
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

die() { echo "fetch-debs: $*" >&2; exit 1; }

# HTTPS only, including redirects; three attempts for a flaky network.
fetch() {
    local i
    for i in 1 2 3; do
        if curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
                --connect-timeout 30 --max-time 900 -o "$2" "$1"; then
            return 0
        fi
        sleep $((i * 5))
    done
    die "cannot download $1"
}

check_sha256() {
    local got
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] || die "$3: SHA256 $got, expected $2"
}

source_field() {
    awk -v n="$1" -v col="$2" '$1 == n { print $col; found = 1 } END { exit !found }' \
        <(grep -v '^[[:space:]]*#' "$SOURCES")
}

# Verifies Release for one source and leaves its Packages file in $WORK.
prepare_source() {
    local name=$1 base dist codename keyargs="" k status sum
    base=$(source_field "$name" 2) || die "unknown source '$name'"
    dist=$(source_field "$name" 3)
    codename=$(source_field "$name" 4)
    case "$base" in https://*) ;; *) die "$name: base URL must be https" ;; esac

    fetch "$base/dists/$dist/Release" "$WORK/$name.Release"
    fetch "$base/dists/$dist/Release.gpg" "$WORK/$name.Release.gpg"
    for k in $KEYRINGS; do
        [ -s "$k" ] || die "missing keyring $k"
        keyargs="$keyargs --keyring $k"
    done
    # shellcheck disable=SC2086
    status=$(gpgv --status-fd 1 $keyargs "$WORK/$name.Release.gpg" "$WORK/$name.Release" \
             2> "$WORK/$name.gpgv") || { cat "$WORK/$name.gpgv" >&2; die "$name: bad Release signature"; }
    echo "$status" | grep -q '^\[GNUPG:\] VALIDSIG ' || die "$name: no valid Release signature"
    if echo "$status" | grep -qE '^\[GNUPG:\] (BADSIG|ERRSIG|REVKEYSIG) '; then
        die "$name: Release has a bad or unverifiable signature"
    fi
    grep -qx "Codename: $codename" "$WORK/$name.Release" \
        || die "$name: Release is not for $codename"
    echo "$name: Release signature verified ($(echo "$status" | awk '/VALIDSIG/ { print $3 }' | tr '\n' ' '))"

    sum=$(awk -v f="$INDEX" '
        /^SHA256:/ { s = 1; next }
        /^[^ ]/    { s = 0 }
        s && $3 == f { print $1; exit }' "$WORK/$name.Release")
    [ -n "$sum" ] || die "$name: no SHA256 for $INDEX in Release"
    fetch "$base/dists/$dist/$INDEX" "$WORK/$name.Packages.gz"
    check_sha256 "$WORK/$name.Packages.gz" "$sum" "$name $INDEX"
    gzip -dc "$WORK/$name.Packages.gz" > "$WORK/$name.Packages"
    echo "$base" > "$WORK/$name.base"
}

# Prints "Filename SHA256" of one package version from a verified index.
lookup() {
    awk -v p="$2" -v v="$3" '
        BEGIN { RS = ""; FS = "\n" }
        {
            pkg = ver = file = sum = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^Package: /)  pkg  = substr($i, 10)
                if ($i ~ /^Version: /)  ver  = substr($i, 10)
                if ($i ~ /^Filename: /) file = substr($i, 11)
                if ($i ~ /^SHA256: /)   sum  = substr($i, 9)
            }
            if (pkg == p && ver == v && file != "" && sum != "") { print file, sum; found = 1; exit }
        }
        END { exit !found }' "$WORK/$1.Packages"
}

mkdir -p "$OUT"
n=0
while read -r src pkg ver; do
    case "$src" in ''|'#'*) continue ;; esac
    [ -n "$ver" ] || die "$LOCK: '$src $pkg' has no version"
    [ -f "$WORK/$src.Packages" ] || prepare_source "$src"
    entry=$(lookup "$src" "$pkg" "$ver") || die "$src has no $pkg $ver"
    file=${entry% *}
    sum=${entry#* }
    deb="$OUT/$(basename "$file")"
    fetch "$(cat "$WORK/$src.base")/$file" "$deb"
    check_sha256 "$deb" "$sum" "$pkg $ver"
    n=$((n + 1))
done < "$LOCK"
echo "fetch-debs: $n packages from $LOCK verified into $OUT"
