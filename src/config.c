/*
 * Policy file parser and validator.
 *
 * The format is INI-style: "[section]" headers, "key=value" lines and '#'
 * comments, which may also follow a value on the same line. Leading and
 * trailing whitespace around sections, keys and values is ignored.
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#define LINE_MAX_LEN   1024
#define MAX_TOTAL_BPS  100000000000000ULL   /* 100 Tbit/s keeps pct * total in range */
#define MAX_WINDOW     100000

enum section {
    SEC_NONE = 0,
    SEC_GLOBAL,
    SEC_CLASSES,
    SEC_APPLICATIONS,
    SEC_MONITORING,
    SEC_AUTOTUNE
};

/* Line numbers of what has been seen so far; 0 means "not set". */
struct class_lines {
    int first, pct, dscp, burst;
};

struct app_lines {
    int first, port, range, class_, sig;
    char class_name[BW_NAME_MAX];
};

struct parser {
    const char *path;
    char *err;
    size_t errlen;
    int line;
    enum section sec;
    struct bw_config *cfg;
    struct class_lines cl[BW_MAX_CLASSES];
    struct app_lines al[BW_MAX_APPS];
    unsigned pct_sum;
    char default_name[BW_NAME_MAX];
    int default_line;
    int iface_line, total_line;
    int interval_line, log_line, db_line;
    int enabled_line, window_line, low_line, high_line, min_share_line, hyst_line;
};

static int fail(struct parser *p, int line, const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    if (p->err != NULL && p->errlen > 0) {
        if (line > 0)
            snprintf(p->err, p->errlen, "%s:%d: %s", p->path, line, msg);
        else
            snprintf(p->err, p->errlen, "%s: %s", p->path, msg);
    }
    return -1;
}

static char *trim(char *s)
{
    char *end;

    while (isspace((unsigned char)*s))
        s++;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';
    return s;
}

/* Decimal digits only, no sign, no overflow past max. */
static int parse_uint(const char *s, unsigned long long max, unsigned long long *out)
{
    unsigned long long v = 0;

    if (*s == '\0')
        return -1;
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s))
            return -1;
        if (v > (max - (unsigned long long)(*s - '0')) / 10)
            return -1;
        v = v * 10 + (unsigned long long)(*s - '0');
    }
    *out = v;
    return 0;
}

static int valid_name(const char *s)
{
    size_t n = strlen(s);

    if (n == 0 || n >= BW_NAME_MAX)
        return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '_' && *s != '-')
            return 0;
    return 1;
}

/* N, Nk or Nm with N > 0. */
static int valid_burst(const char *s)
{
    const char *d = s;
    unsigned long long v = 0;

    while (isdigit((unsigned char)*d)) {
        v = v * 10 + (unsigned long long)(*d - '0');
        if (v > 1000000000ULL)
            return 0;
        d++;
    }
    if (d == s || v == 0)
        return 0;
    if (*d == '\0')
        return 1;
    return (d[0] == 'k' || d[0] == 'm') && d[1] == '\0';
}

static int parse_port(const char *s, uint16_t *out)
{
    unsigned long long v;

    if (parse_uint(s, 65535, &v) != 0 || v == 0)
        return -1;
    *out = (uint16_t)v;
    return 0;
}

static int copy_value(struct parser *p, char *dst, size_t dstlen, const char *key,
                      const char *val)
{
    if (*val == '\0')
        return fail(p, p->line, "%s must not be empty", key);
    if (strlen(val) >= dstlen)
        return fail(p, p->line, "%s is longer than %u characters", key,
                    (unsigned)(dstlen - 1));
    strcpy(dst, val);
    return 0;
}

static int set_once(struct parser *p, int *seen_line, const char *key)
{
    if (*seen_line != 0)
        return fail(p, p->line, "duplicate key '%s' (first set on line %d)", key, *seen_line);
    *seen_line = p->line;
    return 0;
}

int bw_config_find_class(const struct bw_config *cfg, const char *name)
{
    int i;

    for (i = 0; i < cfg->nclasses; i++)
        if (strcmp(cfg->classes[i].name, name) == 0)
            return i;
    return -1;
}

const char *bw_sig_name(enum bw_sig sig)
{
    switch (sig) {
    case BW_SIG_HTTP: return "http";
    case BW_SIG_SIP:  return "sip";
    case BW_SIG_TLS:  return "tls";
    default:          return "none";
    }
}

static int parse_sig(const char *s, enum bw_sig *out)
{
    if (strcmp(s, "http") == 0)
        *out = BW_SIG_HTTP;
    else if (strcmp(s, "sip") == 0)
        *out = BW_SIG_SIP;
    else if (strcmp(s, "tls") == 0)
        *out = BW_SIG_TLS;
    else
        return -1;
    return 0;
}

static int global_key(struct parser *p, const char *key, const char *val)
{
    struct bw_config *cfg = p->cfg;
    unsigned long long v;

    if (strcmp(key, "interface") == 0) {
        if (set_once(p, &p->iface_line, key) != 0)
            return -1;
        return copy_value(p, cfg->iface, sizeof cfg->iface, key, val);
    }
    if (strcmp(key, "total_bandwidth") == 0) {
        if (set_once(p, &p->total_line, key) != 0)
            return -1;
        if (parse_uint(val, MAX_TOTAL_BPS, &v) != 0 || v == 0)
            return fail(p, p->line, "total_bandwidth '%s' is not a positive number of bit/s",
                        val);
        cfg->total_bps = v;
        return 0;
    }
    if (strcmp(key, "default_class") == 0) {
        if (set_once(p, &p->default_line, key) != 0)
            return -1;
        if (!valid_name(val))
            return fail(p, p->line, "invalid class name '%s'", val);
        strcpy(p->default_name, val);
        return 0;
    }
    return fail(p, p->line, "unknown key '%s' in [global]", key);
}

/* Splits "name.attr" in place. */
static int split_dotted(struct parser *p, char *key, char **name, char **attr,
                        const char *section)
{
    char *dot = strchr(key, '.');

    if (dot == NULL)
        return fail(p, p->line, "unknown key '%s' in [%s]", key, section);
    *dot = '\0';
    *name = key;
    *attr = dot + 1;
    if (!valid_name(*name))
        return fail(p, p->line, "invalid name '%s' (letters, digits, '_' or '-', at most %d)",
                    *name, BW_NAME_MAX - 1);
    return 0;
}

static int class_key(struct parser *p, char *key, const char *val)
{
    struct bw_config *cfg = p->cfg;
    struct bw_class *c;
    struct class_lines *cl;
    char *name, *attr;
    unsigned long long v;
    int idx, i;

    if (split_dotted(p, key, &name, &attr, "classes") != 0)
        return -1;
    idx = bw_config_find_class(cfg, name);
    if (idx < 0) {
        if (cfg->nclasses >= BW_MAX_CLASSES)
            return fail(p, p->line, "too many classes (at most %d)", BW_MAX_CLASSES);
        idx = cfg->nclasses++;
        c = &cfg->classes[idx];
        strcpy(c->name, name);
        c->classid_minor = 10u * (unsigned)(idx + 1);
        c->prio = (unsigned)idx;
        p->cl[idx].first = p->line;
    }
    c = &cfg->classes[idx];
    cl = &p->cl[idx];

    if (strcmp(attr, "bandwidth") == 0) {
        char num[32];
        size_t n = strlen(val);

        if (set_once(p, &cl->pct, "bandwidth") != 0)
            return -1;
        if (n < 2 || n >= sizeof num || val[n - 1] != '%')
            return fail(p, p->line, "%s.bandwidth '%s' must be a percentage such as 30%%",
                        name, val);
        memcpy(num, val, n - 1);
        num[n - 1] = '\0';
        if (parse_uint(num, 100, &v) != 0)
            return fail(p, p->line, "%s.bandwidth '%s' must be 0%%-100%%", name, val);
        c->pct = (unsigned)v;
        p->pct_sum += c->pct;
        if (p->pct_sum > 100)
            return fail(p, p->line, "class shares add up to %u%%, more than 100%%", p->pct_sum);
        return 0;
    }
    if (strcmp(attr, "dscp") == 0) {
        if (set_once(p, &cl->dscp, "dscp") != 0)
            return -1;
        if (parse_uint(val, 63, &v) != 0)
            return fail(p, p->line, "%s.dscp '%s' must be 0-63", name, val);
        /* DSCP 0 is reserved for the default class; finish() reports misuse of it. */
        for (i = 0; v != 0 && i < cfg->nclasses; i++)
            if (i != idx && p->cl[i].dscp != 0 && cfg->classes[i].dscp == (unsigned)v)
                return fail(p, p->line, "dscp %llu is already used by class %s", v,
                            cfg->classes[i].name);
        c->dscp = (unsigned)v;
        return 0;
    }
    if (strcmp(attr, "burst") == 0) {
        if (set_once(p, &cl->burst, "burst") != 0)
            return -1;
        if (strlen(val) >= sizeof c->burst || !valid_burst(val))
            return fail(p, p->line, "%s.burst '%s' must be N, Nk or Nm", name, val);
        strcpy(c->burst, val);
        return 0;
    }
    return fail(p, p->line, "unknown key '%s.%s' in [classes]", name, attr);
}

static int app_key(struct parser *p, char *key, const char *val)
{
    struct bw_config *cfg = p->cfg;
    struct bw_app *a;
    struct app_lines *al;
    char *name, *attr;
    int idx;

    if (split_dotted(p, key, &name, &attr, "applications") != 0)
        return -1;
    for (idx = 0; idx < cfg->napps; idx++)
        if (strcmp(cfg->apps[idx].name, name) == 0)
            break;
    if (idx == cfg->napps) {
        if (cfg->napps >= BW_MAX_APPS)
            return fail(p, p->line, "too many applications (at most %d)", BW_MAX_APPS);
        cfg->napps++;
        a = &cfg->apps[idx];
        strcpy(a->name, name);
        a->class_idx = -1;
        a->sig = BW_SIG_NONE;
        p->al[idx].first = p->line;
    }
    a = &cfg->apps[idx];
    al = &p->al[idx];

    if (strcmp(attr, "port") == 0) {
        if (set_once(p, &al->port, "port") != 0)
            return -1;
        if (al->range != 0)
            return fail(p, p->line, "%s has both port and port_range", name);
        if (parse_port(val, &a->port_lo) != 0)
            return fail(p, p->line, "%s.port '%s' must be 1-65535", name, val);
        a->port_hi = a->port_lo;
        return 0;
    }
    if (strcmp(attr, "port_range") == 0) {
        char buf[32];
        char *dash;

        if (set_once(p, &al->range, "port_range") != 0)
            return -1;
        if (al->port != 0)
            return fail(p, p->line, "%s has both port and port_range", name);
        if (strlen(val) >= sizeof buf || (dash = strchr(strcpy(buf, val), '-')) == NULL)
            return fail(p, p->line, "%s.port_range '%s' must be LO-HI", name, val);
        *dash = '\0';
        if (parse_port(buf, &a->port_lo) != 0 || parse_port(dash + 1, &a->port_hi) != 0
            || a->port_lo > a->port_hi)
            return fail(p, p->line,
                        "%s.port_range '%s' must be LO-HI with 1 <= LO <= HI <= 65535",
                        name, val);
        return 0;
    }
    if (strcmp(attr, "class") == 0) {
        if (set_once(p, &al->class_, "class") != 0)
            return -1;
        if (!valid_name(val))
            return fail(p, p->line, "invalid class name '%s'", val);
        strcpy(al->class_name, val);
        return 0;
    }
    if (strcmp(attr, "signature") == 0) {
        if (set_once(p, &al->sig, "signature") != 0)
            return -1;
        if (parse_sig(val, &a->sig) != 0)
            return fail(p, p->line, "%s.signature '%s' must be http, sip or tls", name, val);
        return 0;
    }
    return fail(p, p->line, "unknown key '%s.%s' in [applications]", name, attr);
}

static int monitoring_key(struct parser *p, const char *key, const char *val)
{
    struct bw_config *cfg = p->cfg;
    unsigned long long v;

    if (strcmp(key, "update_interval") == 0) {
        if (set_once(p, &p->interval_line, key) != 0)
            return -1;
        if (parse_uint(val, 86400, &v) != 0 || v == 0)
            return fail(p, p->line, "update_interval '%s' must be 1-86400 seconds", val);
        cfg->update_interval = (unsigned)v;
        return 0;
    }
    if (strcmp(key, "log_file") == 0) {
        if (set_once(p, &p->log_line, key) != 0)
            return -1;
        return copy_value(p, cfg->log_file, sizeof cfg->log_file, key, val);
    }
    if (strcmp(key, "database") == 0) {
        if (set_once(p, &p->db_line, key) != 0)
            return -1;
        return copy_value(p, cfg->database, sizeof cfg->database, key, val);
    }
    return fail(p, p->line, "unknown key '%s' in [monitoring]", key);
}

static int autotune_key(struct parser *p, const char *key, const char *val)
{
    struct bw_autotune_cfg *t = &p->cfg->tune;
    unsigned long long v;
    unsigned *dst;
    int *seen;
    unsigned long long lo = 0, hi = 100;

    if (strcmp(key, "enabled") == 0) {
        if (set_once(p, &p->enabled_line, key) != 0)
            return -1;
        if (strcmp(val, "0") != 0 && strcmp(val, "1") != 0)
            return fail(p, p->line, "enabled '%s' must be 0 or 1", val);
        t->enabled = val[0] == '1';
        return 0;
    }
    if (strcmp(key, "window") == 0) {
        dst = &t->window; seen = &p->window_line; lo = 1; hi = MAX_WINDOW;
    } else if (strcmp(key, "low_watermark") == 0) {
        dst = &t->low_watermark; seen = &p->low_line;
    } else if (strcmp(key, "high_watermark") == 0) {
        dst = &t->high_watermark; seen = &p->high_line;
    } else if (strcmp(key, "min_share") == 0) {
        dst = &t->min_share; seen = &p->min_share_line;
    } else if (strcmp(key, "hysteresis") == 0) {
        dst = &t->hysteresis; seen = &p->hyst_line;
    } else {
        return fail(p, p->line, "unknown key '%s' in [autotune]", key);
    }
    if (set_once(p, seen, key) != 0)
        return -1;
    if (parse_uint(val, hi, &v) != 0 || v < lo)
        return fail(p, p->line, "%s '%s' must be %llu-%llu", key, val, lo, hi);
    *dst = (unsigned)v;
    return 0;
}

static int section_header(struct parser *p, char *s)
{
    size_t n = strlen(s);
    char *name;

    if (s[n - 1] != ']')
        return fail(p, p->line, "malformed section header '%s'", s);
    s[n - 1] = '\0';
    name = trim(s + 1);
    if (strcmp(name, "global") == 0)
        p->sec = SEC_GLOBAL;
    else if (strcmp(name, "classes") == 0)
        p->sec = SEC_CLASSES;
    else if (strcmp(name, "applications") == 0)
        p->sec = SEC_APPLICATIONS;
    else if (strcmp(name, "monitoring") == 0)
        p->sec = SEC_MONITORING;
    else if (strcmp(name, "autotune") == 0)
        p->sec = SEC_AUTOTUNE;
    else
        return fail(p, p->line, "unknown section [%s]", name);
    return 0;
}

static int parse_line(struct parser *p, char *raw)
{
    char *hash = strchr(raw, '#');
    char *s, *eq, *key, *val;

    if (hash != NULL)
        *hash = '\0';
    s = trim(raw);
    if (*s == '\0')
        return 0;
    if (*s == '[')
        return section_header(p, s);

    eq = strchr(s, '=');
    if (eq == NULL)
        return fail(p, p->line, "expected key=value, got '%s'", s);
    *eq = '\0';
    key = trim(s);
    val = trim(eq + 1);
    if (*key == '\0')
        return fail(p, p->line, "missing key before '='");

    switch (p->sec) {
    case SEC_GLOBAL:       return global_key(p, key, val);
    case SEC_CLASSES:      return class_key(p, key, val);
    case SEC_APPLICATIONS: return app_key(p, key, val);
    case SEC_MONITORING:   return monitoring_key(p, key, val);
    case SEC_AUTOTUNE:     return autotune_key(p, key, val);
    default:               return fail(p, p->line, "key '%s' outside of any section", key);
    }
}

/* Cross-checks that need the whole file. */
static int finish(struct parser *p)
{
    struct bw_config *cfg = p->cfg;
    int i;

    if (p->total_line == 0)
        return fail(p, 0, "[global] total_bandwidth is not set");
    if (cfg->nclasses == 0)
        return fail(p, 0, "no classes defined");

    for (i = 0; i < cfg->nclasses; i++) {
        struct bw_class *c = &cfg->classes[i];

        if (p->cl[i].pct == 0)
            return fail(p, p->cl[i].first, "class %s has no bandwidth", c->name);
        if (p->cl[i].dscp == 0)
            return fail(p, p->cl[i].first, "class %s has no dscp", c->name);
        if (p->cl[i].burst == 0)
            return fail(p, p->cl[i].first, "class %s has no burst", c->name);
        c->rate_bps = cfg->total_bps * c->pct / 100;
    }

    if (p->default_line == 0)
        return fail(p, 0, "[global] default_class is not set");
    cfg->default_class = bw_config_find_class(cfg, p->default_name);
    if (cfg->default_class < 0)
        return fail(p, p->default_line, "default_class '%s' is not a defined class",
                    p->default_name);

    for (i = 0; i < cfg->nclasses; i++)
        if (i != cfg->default_class && cfg->classes[i].dscp == 0)
            return fail(p, p->cl[i].dscp,
                        "class %s uses dscp 0, which only the default class (%s) may use",
                        cfg->classes[i].name, p->default_name);

    for (i = 0; i < cfg->napps; i++) {
        struct bw_app *a = &cfg->apps[i];
        struct app_lines *al = &p->al[i];

        if (al->class_ == 0)
            return fail(p, al->first, "application %s has no class", a->name);
        a->class_idx = bw_config_find_class(cfg, al->class_name);
        if (a->class_idx < 0)
            return fail(p, al->class_, "application %s refers to unknown class '%s'",
                        a->name, al->class_name);
        if (al->port == 0 && al->range == 0 && al->sig == 0)
            return fail(p, al->first, "application %s has no port, port_range or signature",
                        a->name);
    }

    if (cfg->tune.low_watermark >= cfg->tune.high_watermark)
        return fail(p, p->low_line > p->high_line ? p->low_line : p->high_line,
                    "low_watermark (%u) must be below high_watermark (%u)",
                    cfg->tune.low_watermark, cfg->tune.high_watermark);
    return 0;
}

int bw_config_load(const char *path, struct bw_config *out, char *err, size_t errlen)
{
    struct parser *p;
    char buf[LINE_MAX_LEN];
    FILE *f;
    int rc = 0;

    if (err != NULL && errlen > 0)
        err[0] = '\0';

    p = calloc(1, sizeof *p);
    if (p == NULL) {
        if (err != NULL && errlen > 0)
            snprintf(err, errlen, "%s: out of memory", path);
        return -1;
    }
    p->path = path;
    p->err = err;
    p->errlen = errlen;
    p->cfg = out;

    memset(out, 0, sizeof *out);
    strcpy(out->iface, "eth0");
    out->default_class = -1;
    out->update_interval = 30;
    out->tune.enabled = 0;
    out->tune.window = 10;
    out->tune.low_watermark = 50;
    out->tune.high_watermark = 90;
    out->tune.min_share = 50;
    out->tune.hysteresis = 5;

    f = fopen(path, "r");
    if (f == NULL) {
        rc = fail(p, 0, "cannot open: %s", strerror(errno));
        free(p);
        return rc;
    }

    while (rc == 0 && fgets(buf, sizeof buf, f) != NULL) {
        size_t n = strlen(buf);

        p->line++;
        if (n == sizeof buf - 1 && buf[n - 1] != '\n' && !feof(f)) {
            rc = fail(p, p->line, "line longer than %d characters", LINE_MAX_LEN - 2);
            break;
        }
        rc = parse_line(p, buf);
    }
    if (rc == 0 && ferror(f))
        rc = fail(p, 0, "read error: %s", strerror(errno));
    fclose(f);

    if (rc == 0)
        rc = finish(p);
    free(p);
    return rc;
}
