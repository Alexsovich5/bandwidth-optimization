# Shared helpers for the integration scripts that need a network interface.
# Source from a script run with bash -e from the repository root.

BW_IFACE=bw0
BW_ADDR=10.99.0.1/24
BW_PEER=10.99.0.2

fail() { echo "FAIL: $*" >&2; exit 1; }

# Creates the dummy interface bw0 with 10.99.0.1/24 and brings it up.
# Returns 1 (and leaves nothing behind) when dummy links are not permitted.
bw0_create() {
    ip link del "$BW_IFACE" > /dev/null 2>&1 || true
    ip link add "$BW_IFACE" type dummy 2> /dev/null || return 1
    # Best effort: without IPv6 the interface sends no ND/MLD frames. procps
    # (sysctl) is not in the image, so the setting is written to /proc/sys
    # directly; it may be read-only in the container.
    { echo 1 > "/proc/sys/net/ipv6/conf/$BW_IFACE/disable_ipv6"; } 2> /dev/null || true
    ip addr add "$BW_ADDR" dev "$BW_IFACE"
    ip link set "$BW_IFACE" up
}

bw0_remove() {
    ip link del "$BW_IFACE" > /dev/null 2>&1 || true
}

# send_udp PORT N: sends N one-byte UDP datagrams to 10.99.0.2:PORT via bw0.
send_udp() {
    local i
    for ((i = 0; i < $2; i++)); do
        printf x > "/dev/udp/$BW_PEER/$1"
    done
}

# class_packets CLASSID: the "Sent ... pkt" counter of an HTB class on bw0.
class_packets() {
    tc -s class show dev "$BW_IFACE" | awk -v id="$1" '
        $1 == "class" { cur = $3 }
        $1 == "Sent" && cur == id { print $4; exit }'
}
