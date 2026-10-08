/*
 * Bandwidth Optimization Engine
 *
 * Real-time traffic classification and QoS management system
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

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
            "Options:\n"
            "  -c, --config FILE      policy file (default config/policies.conf)\n"
            "  -i, --interface IFACE  network interface (default eth0)\n"
            "  --version              print the version and exit\n"
            "  --help                 print this help and exit\n");
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

    (void)interface;
    (void)config_file;
    fprintf(stderr, "bwopt: unknown command '%s'\n", command);
    usage(stderr);
    return EXIT_USAGE;
}
