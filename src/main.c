/*
 * Bandwidth Optimization Engine
 * Network Administrator - Etech Eritrea PLC (2013)
 * 
 * Real-time traffic classification and QoS management system
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <sqlite3.h>
#include <pthread.h>

#include "traffic_classifier.h"
#include "qos_engine.h"
#include "monitoring.h"
#include "web_dashboard.h"

static volatile int running = 1;

void signal_handler(int signum) {
    printf("Received signal %d, shutting down...\n", signum);
    running = 0;
}

int main(int argc, char *argv[]) {
    char *interface = "eth0";
    char *config_file = "config/policies.conf";
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--interface") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_file = argv[++i];
        }
    }
    
    printf("Bandwidth Optimization Engine v1.0\n");
    printf("Interface: %s\n", interface);
    printf("Config: %s\n", config_file);
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize components
    if (init_traffic_classifier() != 0) {
        fprintf(stderr, "Failed to initialize traffic classifier\n");
        return 1;
    }
    
    if (init_qos_engine(config_file) != 0) {
        fprintf(stderr, "Failed to initialize QoS engine\n");
        return 1;
    }
    
    if (init_monitoring() != 0) {
        fprintf(stderr, "Failed to initialize monitoring\n");
        return 1;
    }
    
    if (init_web_dashboard() != 0) {
        fprintf(stderr, "Failed to initialize web dashboard\n");
        return 1;
    }
    
    printf("System initialized successfully\n");
    
    // Main processing loop
    while (running) {
        // Process packets and apply QoS policies
        process_packets(interface);
        usleep(100000); // 100ms delay
    }
    
    // Cleanup
    cleanup_traffic_classifier();
    cleanup_qos_engine();
    cleanup_monitoring();
    cleanup_web_dashboard();
    
    printf("Shutdown complete\n");
    return 0;
}