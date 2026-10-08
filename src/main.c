/*
 * Bandwidth Optimization Engine
 *
 * Real-time traffic classification and QoS management system
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "config.h"
#include "version.h"

#define EXIT_USAGE 2

static volatile sig_atomic_t running = 1;

static void signal_handler(int signum)
{
    (void)signum;
    running = 0;
}

static void usage(FILE *out)
{
    fprintf(out,
            "Usage: bwopt [--version | --help]\n"
            "       bwopt <command> [-c FILE] [-i IFACE] [options]\n"
            "\n"
            "Commands:\n"
            "  check-config           validate the policy file and print its classes\n"
            "\n"
            "Options:\n"
            "  -c, --config FILE      policy file (default config/policies.conf)\n"
            "  -i, --interface IFACE  network interface (default eth0)\n"
            "  --version              print the version and exit\n"
            "  --help                 print this help and exit\n");
}

static int load_config(const char *path, struct bw_config *cfg)
{
    char err[512];

    if (bw_config_load(path, cfg, err, sizeof err) != 0) {
        fprintf(stderr, "bwopt: %s\n", err);
        return -1;
    }
    return 0;
}

static void print_port(const struct bw_app *a, char *buf, size_t len)
{
    if (a->port_lo == 0)
        snprintf(buf, len, "-");
    else if (a->port_lo == a->port_hi)
        snprintf(buf, len, "%u", (unsigned)a->port_lo);
    else
        snprintf(buf, len, "%u-%u", (unsigned)a->port_lo, (unsigned)a->port_hi);
}

static int cmd_check_config(const char *config_file)
{
    struct bw_config cfg;
    const struct bw_autotune_cfg *t = &cfg.tune;
    int i;

    if (load_config(config_file, &cfg) != 0)
        return EXIT_USAGE;

    printf("config %s: ok\n", config_file);
    printf("interface %s, total %" PRIu64 " bit/s, default class %s\n\n",
           cfg.iface, cfg.total_bps, cfg.classes[cfg.default_class].name);

    printf("%-16s %5s %4s %12s %6s %7s %4s\n",
           "class", "share", "dscp", "rate(bit/s)", "burst", "classid", "prio");
    for (i = 0; i < cfg.nclasses; i++) {
        const struct bw_class *c = &cfg.classes[i];
        char share[8], classid[16];

        snprintf(share, sizeof share, "%u%%", c->pct);
        snprintf(classid, sizeof classid, "1:%u", c->classid_minor);
        printf("%-16s %5s %4u %12" PRIu64 " %6s %7s %4u\n",
               c->name, share, c->dscp, c->rate_bps, c->burst, classid, c->prio);
    }

    printf("\n%-16s %-11s %-9s %s\n", "application", "port", "signature", "class");
    for (i = 0; i < cfg.napps; i++) {
        const struct bw_app *a = &cfg.apps[i];
        char port[16];

        print_port(a, port, sizeof port);
        printf("%-16s %-11s %-9s %s\n", a->name, port, bw_sig_name(a->sig),
               cfg.classes[a->class_idx].name);
    }

    printf("\nautotune %s: window=%u low_watermark=%u high_watermark=%u "
           "min_share=%u hysteresis=%u\n",
           t->enabled ? "enabled" : "disabled", t->window, t->low_watermark,
           t->high_watermark, t->min_share, t->hysteresis);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *interface = "eth0";
    const char *config_file = "config/policies.conf";
    const char *command = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("bwopt %s\n", BWOPT_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(stdout);
            return 0;
        } else if ((strcmp(argv[i], "--interface") == 0 || strcmp(argv[i], "-i") == 0)
                   && i + 1 < argc) {
            interface = argv[++i];
        } else if ((strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-c") == 0)
                   && i + 1 < argc) {
            config_file = argv[++i];
        } else if (argv[i][0] != '-' && command == NULL) {
            command = argv[i];
        } else {
            fprintf(stderr, "bwopt: unknown option '%s'\n", argv[i]);
            usage(stderr);
            return EXIT_USAGE;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (command == NULL) {
        usage(stderr);
        return EXIT_USAGE;
    }

    if (strcmp(command, "check-config") == 0)
        return cmd_check_config(config_file);

    (void)interface;
    fprintf(stderr, "bwopt: unknown command '%s'\n", command);
    usage(stderr);
    return EXIT_USAGE;
}
