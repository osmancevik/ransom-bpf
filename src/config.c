/**
 * @file config.c
 * @brief Configuration management implementation.
 * @version 0.9.0
 *
 * Handles the initialization of default application settings and parsing of
 * external configuration files (key=value format).
 *
 * Update Note (v0.9.0): Resolved GCC -Wformat-truncation warnings by using
 * precision specifiers in snprintf calls. This explicitly limits the input
 * size to match destination buffers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // Required for strcasecmp
#include "config.h"
#include "logger.h"

/**
 * @brief Global configuration instance.
 *
 * Holds the runtime configuration state accessible throughout the application.
 */
struct app_config config;

/**
 * @brief Initializes the global configuration with secure defaults.
 *
 * Sets up the default values for time windows, thresholds, risk scores,
 * and log file paths. Active blocking is disabled by default for safety.
 */
void init_config_defaults() {
    // --- Timing & Thresholds ---
    config.window_sec = DEFAULT_WINDOW_SEC;
    config.write_threshold = 15; // Legacy support
    config.rename_threshold = 5; // Legacy support

    // --- Risk Scoring Weights ---
    config.score_write = DEFAULT_SCORE_WRITE;
    config.score_rename = DEFAULT_SCORE_RENAME;
    config.score_unlink = DEFAULT_SCORE_UNLINK;
    config.score_honeypot = DEFAULT_SCORE_HONEYPOT;
    config.score_ext_penalty = DEFAULT_SCORE_EXT_PENALTY;

    config.risk_threshold = DEFAULT_RISK_THRESHOLD;

    // Phase 5: Active Blocking is DISABLED by default for safety reasons.
    // Must be explicitly enabled in the config file.
    config.active_blocking = 0;

    // --- Default Log File Paths ---
    // Use precision specifier to suppress truncation warnings for defaults
    snprintf(config.service_log, sizeof(config.service_log), "%s", DEFAULT_SERVICE_LOG);
    snprintf(config.alert_log, sizeof(config.alert_log), "%s", DEFAULT_ALERT_LOG);
    snprintf(config.audit_log, sizeof(config.audit_log), "%s", DEFAULT_AUDIT_LOG);

    // --- Operational States ---
    config.verbose_mode = 0;
    memset(config.whitelist_str, 0, sizeof(config.whitelist_str));
    memset(config.honeypot_file, 0, sizeof(config.honeypot_file));
    memset(config.config_path, 0, sizeof(config.config_path));
}

/**
 * @brief Loads and parses a configuration file.
 *
 * Reads the specified file line by line, parsing "KEY=VALUE" pairs.
 * Ignores comments (starting with #) and empty lines.
 *
 * @param filename Path to the configuration file.
 */
void load_config_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        // Logging is handled by the caller (main.c) if file is missing
        return;
    }

    char line[4096];
    while (fgets(line, sizeof(line), file)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        char key[128];
        char value[2048];

        // Parse KEY=VALUE
        // Note: %2047s prevents buffer overflow during scanning of 'value'
        if (sscanf(line, "%127[^=]=%2047s", key, value) == 2) {

            // Pre-process: Strip newline characters globally to keep logic clean
            value[strcspn(value, "\r\n")] = 0;

            // --- Timing & Thresholds ---
            if (strcmp(key, "WINDOW_SEC") == 0) config.window_sec = atoi(value);
            else if (strcmp(key, "RISK_THRESHOLD") == 0) config.risk_threshold = atoi(value);

            // --- Phase 5: Active Blocking Switch ---
            else if (strcmp(key, "ACTIVE_BLOCKING") == 0) {
                // Accept "true", "TRUE", or "1" as enabled
                if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
                    config.active_blocking = 1;
                } else {
                    config.active_blocking = 0;
                }
            }

            // --- Scoring Weights ---
            else if (strcmp(key, "SCORE_WRITE") == 0) config.score_write = atoi(value);
            else if (strcmp(key, "SCORE_RENAME") == 0) config.score_rename = atoi(value);
            else if (strcmp(key, "SCORE_UNLINK") == 0) config.score_unlink = atoi(value);
            else if (strcmp(key, "SCORE_HONEYPOT") == 0) config.score_honeypot = atoi(value);
            else if (strcmp(key, "SCORE_EXT_PENALTY") == 0) config.score_ext_penalty = atoi(value);

            // --- Log Configuration ---
            // Fix: GCC -Wformat-truncation warning.
            // We use "%.*s" to explicitly tell snprintf to read at most 'dest_size - 1' characters.
            // This satisfies the compiler that we are not blindly copying a 2048-byte buffer into a 256-byte one.
            else if (strcmp(key, "SERVICE_LOG") == 0) {
                snprintf(config.service_log, sizeof(config.service_log),
                         "%.*s", (int)(sizeof(config.service_log) - 1), value);
            }
            else if (strcmp(key, "ALERT_LOG") == 0) {
                snprintf(config.alert_log, sizeof(config.alert_log),
                         "%.*s", (int)(sizeof(config.alert_log) - 1), value);
            }
            else if (strcmp(key, "AUDIT_LOG") == 0) {
                snprintf(config.audit_log, sizeof(config.audit_log),
                         "%.*s", (int)(sizeof(config.audit_log) - 1), value);
            }
            // Backward Compatibility
            else if (strcmp(key, "LOG_FILE") == 0) {
                snprintf(config.service_log, sizeof(config.service_log),
                         "%.*s", (int)(sizeof(config.service_log) - 1), value);
            }

            // --- Lists & Targets ---
            else if (strcmp(key, "WHITELIST") == 0) {
                // Whitelist string is large (MAX_WHITELIST_LENGTH), likely no warning here, but safe to be consistent.
                snprintf(config.whitelist_str, sizeof(config.whitelist_str),
                         "%.*s", (int)(sizeof(config.whitelist_str) - 1), value);
            }
            else if (strcmp(key, "HONEYPOT_FILE") == 0) {
                snprintf(config.honeypot_file, sizeof(config.honeypot_file),
                         "%.*s", (int)(sizeof(config.honeypot_file) - 1), value);
            }
        }
    }
    fclose(file);
}