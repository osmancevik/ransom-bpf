/**
 * @file logger.c
 * @brief Multi-channel Logging System Implementation.
 * @version 0.9.0
 *
 * Implements a centralized logging facility that routes messages to three distinct channels:
 * - Service Log: Operational status and debug messages (human-readable).
 * - Alert Log: High-severity security incidents (JSON).
 * - Audit Log: Raw stream of system events (JSON).
 *
 * Update Note (v0.9.0): Integrated file and line number into the log format
 * to resolve unused parameter warnings and improve traceability.
 */

#include "logger.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

// --- STATIC FILE POINTERS (Channels) ---

/** @brief File pointer for general service logs (service.log). */
static FILE *f_service = NULL;

/** @brief File pointer for high-priority alerts (alerts.json). */
static FILE *f_alerts  = NULL;

/** @brief File pointer for raw audit events (audit.json). */
static FILE *f_audit   = NULL;

// --- HELPER FUNCTIONS ---

/**
 * @brief Generates a high-precision timestamp string.
 *
 * Format: "YYYY-MM-DD HH:MM:SS.mmm"
 *
 * @param buffer Output buffer.
 * @param size Size of the output buffer.
 */
static void get_timestamp(char *buffer, size_t size) {
    struct timeval tv;
    struct tm *tm_info;
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    char fmt_buffer[32];
    strftime(fmt_buffer, sizeof(fmt_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    snprintf(buffer, size, "%s.%03ld", fmt_buffer, tv.tv_usec / 1000);
}

/**
 * @brief Converts log level enum to string representation.
 * @param level Log severity level.
 * @return String literal (e.g., "INFO", "ALARM").
 */
static const char* get_level_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_ALARM: return "ALARM";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        default:              return "UNKNOWN";
    }
}

/**
 * @brief Returns the ANSI color code associated with a log level.
 * @param level Log severity level.
 * @return ANSI escape code string.
 */
static const char* get_level_color(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_INFO:  return ANSI_COLOR_GREEN;
        case LOG_LEVEL_WARN:  return ANSI_COLOR_YELLOW;
        case LOG_LEVEL_ERROR: return ANSI_COLOR_RED;
        case LOG_LEVEL_ALARM: return ANSI_COLOR_RED;
        case LOG_LEVEL_DEBUG: return ANSI_COLOR_BLUE;
        default:              return ANSI_COLOR_RESET;
    }
}

/**
 * @brief Escapes special characters for JSON string compatibility.
 *
 * Handles double quotes and backslashes to ensure valid JSON output.
 *
 * @param input Raw string.
 * @param output Output buffer.
 * @param out_len Size of the output buffer.
 */
static void json_escape(const char *input, char *output, size_t out_len) {
    size_t i = 0, j = 0;
    while (input[i] != '\0' && j < out_len - 2) {
        if (input[i] == '"' || input[i] == '\\') {
            output[j++] = '\\';
        }
        output[j++] = input[i++];
    }
    output[j] = '\0';
}

// --- CORE FUNCTIONS ---

/**
 * @brief Initializes the logging subsystem.
 *
 * Opens file streams for all configured log channels.
 * Prints error messages to stderr if a file cannot be opened.
 */
void init_logger() {
    // 1. Service Log
    if (strlen(config.service_log) > 0) {
        f_service = fopen(config.service_log, "a");
        if (!f_service) perror("Failed to open Service Log");
    }

    // 2. Alert Log
    if (strlen(config.alert_log) > 0) {
        f_alerts = fopen(config.alert_log, "a");
        if (!f_alerts) perror("Failed to open Alert Log");
    }

    // 3. Audit Log
    if (strlen(config.audit_log) > 0) {
        f_audit = fopen(config.audit_log, "a");
        if (!f_audit) perror("Failed to open Audit Log");
    }
}

/**
 * @brief Closes all active log file streams.
 */
void finalize_logger() {
    if (f_service) { fclose(f_service); f_service = NULL; }
    if (f_alerts)  { fclose(f_alerts);  f_alerts = NULL; }
    if (f_audit)   { fclose(f_audit);   f_audit = NULL; }
}

/**
 * @brief Custom print callback for libbpf integration.
 *
 * Redirects libbpf internal logs to the service log file or stderr
 * depending on the verbose mode setting.
 */
int logger_libbpf_print(enum libbpf_print_level level, const char *format, va_list args) {
    // If not in verbose mode, suppress info/debug logs from libbpf,
    // but allow warnings/errors. Redirect to file if open.
    if (!config.verbose_mode && level != LIBBPF_WARN) {
        if (f_service) {
            fprintf(f_service, "[LIBBPF] ");
            vfprintf(f_service, format, args);
            fflush(f_service);
        }
        return 0;
    }
    // In verbose mode, print to stderr as usual
    return vfprintf(stderr, format, args);
}

/**
 * @brief Logs a raw system event to the Audit Log (JSON).
 *
 * Captures the event details without risk analysis. Used for forensic auditing.
 */
void log_audit_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename)
{
    if (!f_audit) return;

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    char safe_filename[512];
    char safe_comm[64];

    json_escape(filename ? filename : "", safe_filename, sizeof(safe_filename));
    json_escape(comm ? comm : "", safe_comm, sizeof(safe_comm));

    // Simplified JSON structure (Event-centric)
    fprintf(f_audit,
        "{\"timestamp\": \"%s\", \"type\": \"%s\", "
        "\"pid\": %d, \"ppid\": %d, \"uid\": %d, \"comm\": \"%s\", "
        "\"filename\": \"%s\"}\n",
        timestamp, event_type, pid, ppid, uid, safe_comm, safe_filename);

    fflush(f_audit);
}

/**
 * @brief Logs a high-priority security alert to the Alert Log (JSON).
 *
 * Includes detailed risk context, reason, and score.
 */
void log_alert_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename,
                    const char *risk_reason,
                    int score)
{
    if (!f_alerts) return;

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    char safe_filename[512];
    char safe_comm[64];
    char safe_reason[128];

    json_escape(filename ? filename : "", safe_filename, sizeof(safe_filename));
    json_escape(comm ? comm : "", safe_comm, sizeof(safe_comm));
    json_escape(risk_reason ? risk_reason : "", safe_reason, sizeof(safe_reason));

    fprintf(f_alerts,
        "{\"timestamp\": \"%s\", \"level\": \"ALARM\", \"alert_type\": \"%s\", "
        "\"pid\": %d, \"ppid\": %d, \"uid\": %d, \"comm\": \"%s\", "
        "\"filename\": \"%s\", \"risk_reason\": \"%s\", \"score\": %d}\n",
        timestamp, event_type, pid, ppid, uid, safe_comm, safe_filename, safe_reason, score);

    fflush(f_alerts);
}

/**
 * @brief Standard logging function for service messages.
 *
 * Writes formatted messages to both stdout (with colors) and the service log file.
 */
void log_message(LogLevel level, const char *file, int line, const char *format, ...) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    int pid = getpid();
    const char *level_str = get_level_string(level);
    va_list args;

    // 1. TERMINAL OUTPUT (Human-readable with colors)
    if (config.verbose_mode || level != LOG_LEVEL_DEBUG) {
        va_start(args, format);
        fprintf(stdout, "%s", get_level_color(level));
        // FIX: Added file and line info to resolve unused parameter warnings
        fprintf(stdout, "[%s] [%-5s] [%d] [%s:%d] ", timestamp, level_str, pid, file, line);
        vfprintf(stdout, format, args);
        fprintf(stdout, "%s\n", ANSI_COLOR_RESET);
        va_end(args);
    }

    // 2. SERVICE LOG FILE (Persistent record)
    if (f_service) {
        va_start(args, format);
        // FIX: Added file and line info here as well
        fprintf(f_service, "[%s] [%-5s] [%d] [%s:%d] ", timestamp, level_str, pid, file, line);
        vfprintf(f_service, format, args);
        fprintf(f_service, "\n");

        // Always flush errors and alarms to ensure they are written immediately
        if (level == LOG_LEVEL_ERROR || level == LOG_LEVEL_ALARM) {
            fflush(f_service);
        }
        va_end(args);
    }
}