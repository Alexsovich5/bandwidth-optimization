#ifndef BWOPT_CAPTURE_H
#define BWOPT_CAPTURE_H

#include <stddef.h>
#include <sys/types.h>
#include <pcap/pcap.h>

/*
 * Thin wrapper over a libpcap handle. Only link types the decoder knows
 * (DLT_EN10MB and DLT_LINUX_SLL) are accepted.
 */
struct bw_capture {
    pcap_t *pcap;
    int dlt;
};

/* Called once per frame with the handle's link type. */
typedef void (*bw_capture_handler)(u_char *user, int dlt,
                                   const struct pcap_pkthdr *hdr,
                                   const u_char *bytes);

/*
 * Opens a capture file. Returns 0 on success, or -1 with the libpcap (or
 * link type) error message in err.
 */
int bw_capture_open_offline(struct bw_capture *cap, const char *path,
                            char *err, size_t errlen);

/*
 * Opens a live capture on iface. timeout_ms is the read timeout, so a
 * loop returns regularly even without traffic. Returns 0 or -1 as above.
 */
int bw_capture_open_live(struct bw_capture *cap, const char *iface, int snaplen,
                         int promisc, int timeout_ms, char *err, size_t errlen);

int bw_capture_datalink(const struct bw_capture *cap);

/*
 * Delivers up to count frames (count < 0: until the end of a file, an
 * error or bw_capture_break()) to handler. Returns the number of frames
 * delivered, or -1 on a read error (see bw_capture_error()).
 */
int bw_capture_loop(struct bw_capture *cap, int count,
                    bw_capture_handler handler, u_char *user);

/* bw_capture_dispatch() result after bw_capture_break() */
#define BW_CAPTURE_BROKEN -2

/*
 * Delivers the frames of one read to handler: on a live capture, what
 * arrived before the read timeout (possibly none), on a file, one buffer.
 * Returns the number of frames delivered (0 at the end of a file or when
 * the timeout passed without traffic), -1 on a read error, or
 * BW_CAPTURE_BROKEN when bw_capture_break() was called first.
 */
int bw_capture_dispatch(struct bw_capture *cap, bw_capture_handler handler, u_char *user);

/*
 * Makes a running loop or the next dispatch return; safe to call from a
 * signal handler.
 */
void bw_capture_break(struct bw_capture *cap);

const char *bw_capture_error(const struct bw_capture *cap);

void bw_capture_close(struct bw_capture *cap);

#endif
