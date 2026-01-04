/**
 * @file cli.c
 * @brief Command Line Interface (CLI) implementation.
 * @version 0.9.0
 *
 * Handles argument parsing, help display, and startup summary visualization.
 * Conforms to POSIX utility syntax guidelines.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "config.h"
#include "common.h"
#include "logger.h"

/**
 * @brief Prints the ASCII art banner to stdout.
 *
 * Uses ANSI cyan color code for visual distinction.
 */
static void print_banner() {
    printf("\033[1;36m"); // ANSI Cyan
    printf("  ____                                  ____  ____  _____ \n");
    printf(" |  _ \\ __ _ _ __  ___  ___  _ __ ___  | __ )|  _ \\|  ___|\n");
    printf(" | |_) / _` | '_ \\/ __|/ _ \\| '_ ` _ \\ |  _ \\| |_) | |_   \n");
    printf(" |  _ < (_| | | | \\__ \\ (_) | | | | | || |_) |  __/|  _|  \n");
    printf(" |_| \\_\\__,_|_| |_|___/\\___/|_| |_| |_||____/|_|   |_|   v%s\n", APP_VERSION);
    printf("\033[0m\n");
}

/**
 * @brief Displays the standard help message.
 *
 * Formats the output according to POSIX utility syntax conventions.
 *
 * @param prog_name The name of the executable (argv[0]).
 */
static void print_help(const char *prog_name) {
    print_banner();
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  -c, --config <file>     Load configuration from a specific file (Default: ./ransom.conf)\n");
    printf("  -l, --log-file <file>   Set path for service logs (Overrides config)\n");
    printf("      --write-limit <n>   Override the write operation threshold (Legacy)\n");
    printf("  -v, --verbose           Enable verbose debug output to stdout\n");
    printf("  -V, --version           Display version information and exit\n");
    printf("  -h, --help              Display this help message and exit\n");
    printf("\nExamples:\n");
    printf("  sudo %s --config /etc/ransom-bpf/prod.conf --verbose\n", prog_name);
    printf("  sudo %s --write-limit 50\n", prog_name);
}

/**
 * @brief Parses command-line arguments.
 *
 * Uses getopt_long to handle short (-c) and long (--config) options.
 * Updates the global configuration structure based on the arguments.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return CLI_ACTION_CONTINUE if execution should proceed,
 * CLI_ACTION_EXIT if the program should terminate (e.g., after help).
 */
int parse_arguments(int argc, char **argv) {
    int opt;
    int option_index = 0;

    static struct option long_options[] = {
        {"help",        no_argument,       0, 'h'},
        {"version",     no_argument,       0, 'V'},
        {"verbose",     no_argument,       0, 'v'},
        {"config",      required_argument, 0, 'c'},
        {"log-file",    required_argument, 0, 'l'},
        {"write-limit", required_argument, 0, 1001},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "hVvc:l:", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            print_help(argv[0]);
            return CLI_ACTION_EXIT;
        case 'V':
            printf("RansomBPF version %s\n", APP_VERSION);
            return CLI_ACTION_EXIT;
        case 'v':
            config.verbose_mode = 1;
            break;
        case 'c':
            strncpy(config.config_path, optarg, sizeof(config.config_path) - 1);
            break;
        case 'l':
            // Updates service_log path, overriding the legacy 'log_file' setting
            strncpy(config.service_log, optarg, sizeof(config.service_log) - 1);
            break;
        case 1001: // --write-limit
            config.write_threshold = atoi(optarg);
            break;
        default:
            return CLI_ACTION_EXIT;
        }
    }

    return CLI_ACTION_CONTINUE;
}

/**
 * @brief Prints a summary of the active configuration at startup.
 *
 * This function provides immediate visual feedback to the operator about
 * which log files are active, the current PID, and risk scoring parameters.
 */
void print_startup_summary() {
    print_banner();
    printf("--------------------------------------------------\n");
    printf(" ACTIVE CONFIGURATION\n");
    printf("--------------------------------------------------\n");
    printf(" PID            : %d\n", getpid());

    // Display all 3 log channels
    printf(" Service Log    : %s\n", config.service_log);
    printf(" Alert Log      : %s\n", config.alert_log);
    printf(" Audit Log      : %s\n", config.audit_log);

    printf(" Config Mode    : %s\n", config.verbose_mode ? "DEBUG (Verbose)" : "NORMAL");

    // Handle whitelist display (truncate if too long)
    if (strlen(config.whitelist_str) > 0) {
        if (strlen(config.whitelist_str) > 50)
            printf(" Whitelist      : %.47s... (Total %ld chars)\n", config.whitelist_str, strlen(config.whitelist_str));
        else
            printf(" Whitelist      : %s\n", config.whitelist_str);
    } else {
        printf(" Whitelist      : [EMPTY]\n");
    }

    printf("--------------------------------------------------\n");
    printf(" RISK SCORING ENGINE\n");
    printf("--------------------------------------------------\n");
    printf(" Risk Threshold : %d points\n", config.risk_threshold);
    printf(" Write Score    : %d\n", config.score_write);
    printf(" Rename Score   : %d\n", config.score_rename);
    printf(" Honeypot Score : %d\n", config.score_honeypot);
    printf("--------------------------------------------------\n\n");
}