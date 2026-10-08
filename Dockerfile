FROM debian:wheezy

RUN printf '%s\n' \
        'deb http://archive.debian.org/debian wheezy main' \
        'deb http://archive.debian.org/debian-security wheezy/updates main' \
        > /etc/apt/sources.list \
    && printf '%s\n' \
        'Acquire::Check-Valid-Until "false";' \
        'APT::Get::AllowUnauthenticated "true";' \
        > /etc/apt/apt.conf.d/10archive \
    && apt-get update \
    && apt-get install -y --force-yes --no-install-recommends \
        build-essential=11.5 gcc-4.7=4.7.2-5 make=3.81-8.2 \
        libc6-dev=2.13-38+deb7u12 libc-dev-bin=2.13-38+deb7u12 libc6-dbg=2.13-38+deb7u12 \
        libpcap0.8-dev=1.3.0-1 \
        libsqlite3-0=3.7.13-1+deb7u2 libsqlite3-dev=3.7.13-1+deb7u2 sqlite3=3.7.13-1+deb7u2 \
        check=0.9.8-2 iproute=20120521-3+b3 iptables=1.4.14-3.1 pkg-config=0.26-1 \
        valgrind=1:3.7.0-6 git=1:1.7.10.4-1+wheezy3 git-man=1:1.7.10.4-1+wheezy3 \
    && rm -rf /var/lib/apt/lists/* \
    && gcc --version && valgrind --version && iptables -V && git --version

WORKDIR /src
