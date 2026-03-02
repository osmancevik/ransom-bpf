/* logger.h - v0.9.0 (Standardized) */
#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <bpf/libbpf.h>

/**
 * @file logger.h
 * @brief Multi-channel logging system.
 * * Supports distinct channels for system logs (service), raw events (audit),
 * and security alerts (alerts).
 */

/**
 * @brief Log severity levels.
 */
typedef enum {
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_ALARM,
    LOG_LEVEL_DEBUG
} LogLevel;

// ANSI Color Codes for Terminal Output
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

/**
 * @brief Initializes the logging subsystem and opens log files.
 */
void init_logger();

/**
 * @brief Closes all open log files and flushes buffers.
 */
void finalize_logger();

/**
 * @brief General purpose logging function.
 * * Writes to stdout (colored) and the service log file.
 * * @param level Severity level.
 * @param file Source file name (__FILE__).
 * @param line Line number (__LINE__).
 * @param format Printf-style format string.
 * @param ... Arguments for the format string.
 */
void log_message(LogLevel level, const char *file, int line, const char *format, ...);

/**
 * @brief Custom print callback for libbpf to redirect internal logs.
 */
int logger_libbpf_print(enum libbpf_print_level level, const char *format, va_list args);

/**
 * @brief Logs raw events to the audit file in JSON format.
 * * @param event_type Type of the event (e.g., "WRITE", "RENAME").
 * @param pid Process ID.
 * @param ppid Parent Process ID.
 * @param uid User ID.
 * @param comm Command name.
 * @param filename Associated filename.
 */
void log_audit_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename);

/**
 * @brief Logs high-risk security alerts to the alert file in JSON format.
 * * @param event_type Type of the alert (e.g., "RANSOMWARE_DETECTED").
 * @param pid Process ID.
 * @param ppid Parent Process ID.
 * @param uid User ID.
 * @param comm Command name.
 * @param filename Associated filename.
 * @param risk_reason The reason for the alert (e.g., "SUSPICIOUS EXTENSION").
 * @param score The calculated risk score at the time of the alert.
 */
void log_alert_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename,
                    const char *risk_reason,
                    int score);

// Helper Macros
#define LOG_INFO(...)  log_message(LOG_LEVEL_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_message(LOG_LEVEL_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERR(...)   log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ALARM(...) log_message(LOG_LEVEL_ALARM, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#endif // LOGGER_H