#include <stdio.h>
#include <string.h>

#include "capture.h"

/* State passed through libpcap's u_char *user argument. */
struct relay {
    bw_capture_handler handler;
    u_char *user;
    int dlt;
    int count;
};

static void relay_frame(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
    struct relay *r = (struct relay *)arg;

    r->count++;
    r->handler(r->user, r->dlt, hdr, bytes);
}

static int check_link(struct bw_capture *cap, const char *name, char *err, size_t errlen)
{
    cap->dlt = pcap_datalink(cap->pcap);
    if (cap->dlt == DLT_EN10MB || cap->dlt == DLT_LINUX_SLL)
        return 0;
    snprintf(err, errlen, "%s: unsupported link type %d (%s)", name, cap->dlt,
             pcap_datalink_val_to_name(cap->dlt) ? pcap_datalink_val_to_name(cap->dlt)
                                                 : "unknown");
    pcap_close(cap->pcap);
    cap->pcap = NULL;
    return -1;
}

int bw_capture_open_offline(struct bw_capture *cap, const char *path,
                            char *err, size_t errlen)
{
    char ebuf[PCAP_ERRBUF_SIZE];

    memset(cap, 0, sizeof(*cap));
    ebuf[0] = '\0';
    cap->pcap = pcap_open_offline(path, ebuf);
    if (cap->pcap == NULL) {
        snprintf(err, errlen, "%s", ebuf);
        return -1;
    }
    return check_link(cap, path, err, errlen);
}

int bw_capture_open_live(struct bw_capture *cap, const char *iface, int snaplen,
                         int promisc, int timeout_ms, char *err, size_t errlen)
{
    char ebuf[PCAP_ERRBUF_SIZE];

    memset(cap, 0, sizeof(*cap));
    ebuf[0] = '\0';
    cap->pcap = pcap_open_live(iface, snaplen, promisc, timeout_ms, ebuf);
    if (cap->pcap == NULL) {
        snprintf(err, errlen, "%s", ebuf);
        return -1;
    }
    return check_link(cap, iface, err, errlen);
}

int bw_capture_datalink(const struct bw_capture *cap)
{
    return cap->dlt;
}

int bw_capture_loop(struct bw_capture *cap, int count,
                    bw_capture_handler handler, u_char *user)
{
    struct relay r;
    int rc;

    r.handler = handler;
    r.user = user;
    r.dlt = cap->dlt;
    r.count = 0;
    rc = pcap_loop(cap->pcap, count, relay_frame, (u_char *)&r);
    if (rc == -1)
        return -1;
    return r.count;
}

void bw_capture_break(struct bw_capture *cap)
{
    if (cap->pcap != NULL)
        pcap_breakloop(cap->pcap);
}

const char *bw_capture_error(const struct bw_capture *cap)
{
    return cap->pcap != NULL ? pcap_geterr(cap->pcap) : "capture not open";
}

void bw_capture_close(struct bw_capture *cap)
{
    if (cap->pcap != NULL)
        pcap_close(cap->pcap);
    cap->pcap = NULL;
}
