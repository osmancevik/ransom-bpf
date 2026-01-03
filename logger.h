/* logger.h - v0.9.0 (Separate Alert & Audit Logs) */
#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <bpf/libbpf.h>

typedef enum {
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_ALARM,
    LOG_LEVEL_DEBUG
} LogLevel;

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void init_logger();
void finalize_logger();
void log_message(LogLevel level, const char *file, int line, const char *format, ...);
int logger_libbpf_print(enum libbpf_print_level level, const char *format, va_list args);

// [YENI] Ozel JSON Loglama Fonksiyonlari
// 1. Audit Log: Ham olay akisi (audit.json)
void log_audit_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename);

// 2. Alert Log: Yuksek riskli alarmlar (alerts.json)
void log_alert_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename,
                    const char *risk_reason,
                    int score);

#define LOG_INFO(...)  log_message(LOG_LEVEL_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_message(LOG_LEVEL_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERR(...)   log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ALARM(...) log_message(LOG_LEVEL_ALARM, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#endif // LOGGER_H