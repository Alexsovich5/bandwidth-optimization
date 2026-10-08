#ifndef BWOPT_CONFIG_H
#define BWOPT_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define BW_MAX_CLASSES 8
#define BW_MAX_APPS    64
#define BW_NAME_MAX    32   /* including the terminating NUL */
#define BW_IFACE_MAX   16   /* IFNAMSIZ, including the terminating NUL */

/* Payload signature an application may request with <app>.signature. */
enum bw_sig {
    BW_SIG_NONE = 0,
    BW_SIG_HTTP,
    BW_SIG_SIP,
    BW_SIG_TLS
};

struct bw_class {
    char name[BW_NAME_MAX];
    unsigned pct;              /* guaranteed share of total_bandwidth, 0..100 */
    unsigned dscp;             /* 0..63 */
    char burst[16];            /* N, Nk or Nm, passed to tc as-is */
    uint64_t rate_bps;         /* pct * total_bps / 100 */
    unsigned classid_minor;    /* 10 * (index + 1) */
    unsigned prio;             /* order of first appearance, 0 = highest */
};

struct bw_app {
    char name[BW_NAME_MAX];
    uint16_t port_lo, port_hi; /* 0/0 when the app only has a signature */
    int class_idx;
    enum bw_sig sig;
};

struct bw_autotune_cfg {
    int enabled;
    unsigned window;           /* samples per class considered */
    unsigned low_watermark;    /* % utilisation below which a class may lend */
    unsigned high_watermark;   /* % utilisation at or above which a class may borrow */
    unsigned min_share;        /* % of the configured rate a class always keeps */
    unsigned hysteresis;       /* % change below which no tc change is issued */
};

struct bw_config {
    char iface[BW_IFACE_MAX];
    uint64_t total_bps;
    int default_class;
    struct bw_class classes[BW_MAX_CLASSES];
    int nclasses;
    struct bw_app apps[BW_MAX_APPS];
    int napps;
    unsigned update_interval;
    char log_file[256];
    char database[256];
    struct bw_autotune_cfg tune;
};

/*
 * Parses and validates a policy file. Returns 0 on success. On failure
 * returns -1 and writes "PATH:LINE: message" (or "PATH: message" when the
 * problem has no single line) into err.
 */
int bw_config_load(const char *path, struct bw_config *out, char *err, size_t errlen);

/*
 * True when s can be used as an interface name: 1-15 characters from
 * [A-Za-z0-9_.-], not starting with '-' and not "." or "..". Interface
 * names end up in tc and iptables command lines run through /bin/sh, so
 * every name from the policy file or the command line is checked with this.
 */
int bw_iface_valid(const char *s);

/* Index of the class called name, or -1. */
int bw_config_find_class(const struct bw_config *cfg, const char *name);

/* "http", "sip", "tls" or "none". */
const char *bw_sig_name(enum bw_sig sig);

#endif
