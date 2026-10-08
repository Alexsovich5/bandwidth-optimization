# Stage 1: download and verify every package on a current Debian, over HTTPS
# from snapshot.debian.org (see docker/apt/fetch-debs.sh).
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS fetch

RUN for i in 1 2 3; do apt-get update && break; sleep 10; done \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gpgv debian-archive-keyring \
    && rm -rf /var/lib/apt/lists/*

COPY docker/apt/ /apt/
RUN bash /apt/fetch-debs.sh /apt/sources.conf /apt/period.lock /debs/period \
    && bash /apt/fetch-debs.sh /apt/sources.conf /apt/asan.lock /debs/asan \
    && mkdir -p /opt/asan/tmp /opt/asan/build \
    && for d in /debs/asan/*.deb; do dpkg-deb -x "$d" /opt/asan; done

# Stage 2: the wheezy build and test image. Packages come only from the
# verified set above; the image has no apt sources at all.
FROM debian:wheezy@sha256:2259b099d947443e44bbd1c94967c785361af8fd22df48a08a3942e2d5630849

RUN --mount=type=bind,from=fetch,source=/debs/period,target=/tmp/debs \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list \
    && dpkg -i /tmp/debs/*.deb \
    && gcc --version && valgrind --version && iptables -V && git --version

COPY --from=fetch /opt/asan /opt/asan
RUN chroot /opt/asan /usr/bin/gcc-4.8 --version

WORKDIR /src
