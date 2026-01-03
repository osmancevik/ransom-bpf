/* logger.c - v0.9.0 (Multi-File Logging Implementation) */
#include "logger.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

// [YENI] 3 Ayri Dosya Pointer'i
static FILE *f_service = NULL; // service.log
static FILE *f_alerts  = NULL; // alerts.json
static FILE *f_audit   = NULL; // audit.json

// --- YARDIMCI FONKSIYONLAR ---

static void get_timestamp(char *buffer, size_t size) {
    struct timeval tv;
    struct tm *tm_info;
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    char fmt_buffer[32];
    strftime(fmt_buffer, sizeof(fmt_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    snprintf(buffer, size, "%s.%03ld", fmt_buffer, tv.tv_usec / 1000);
}

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

// --- ANA FONKSIYONLAR ---

void init_logger() {
    // 1. Service Log
    if (strlen(config.service_log) > 0) {
        f_service = fopen(config.service_log, "a");
        if (!f_service) perror("Service Log acilamadi");
    }

    // 2. Alert Log
    if (strlen(config.alert_log) > 0) {
        f_alerts = fopen(config.alert_log, "a");
        if (!f_alerts) perror("Alert Log acilamadi");
    }

    // 3. Audit Log
    if (strlen(config.audit_log) > 0) {
        f_audit = fopen(config.audit_log, "a");
        if (!f_audit) perror("Audit Log acilamadi");
    }
}

void finalize_logger() {
    if (f_service) { fclose(f_service); f_service = NULL; }
    if (f_alerts)  { fclose(f_alerts);  f_alerts = NULL; }
    if (f_audit)   { fclose(f_audit);   f_audit = NULL; }
}

int logger_libbpf_print(enum libbpf_print_level level, const char *format, va_list args) {
    if (!config.verbose_mode && level != LIBBPF_WARN) {
        if (f_service) {
            fprintf(f_service, "[LIBBPF] ");
            vfprintf(f_service, format, args);
            fflush(f_service);
        }
        return 0;
    }
    return vfprintf(stderr, format, args);
}

// [YENI] Audit Log (audit.json) -> Ham veriler
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

    // Sadelestirilmis JSON (Risk ve Skor yok, sadece olay)
    fprintf(f_audit,
        "{\"timestamp\": \"%s\", \"type\": \"%s\", "
        "\"pid\": %d, \"ppid\": %d, \"uid\": %d, \"comm\": \"%s\", "
        "\"filename\": \"%s\"}\n",
        timestamp, event_type, pid, ppid, uid, safe_comm, safe_filename);

    // Audit log cok yogun olabilir, her satirda flush performansi dusurebilir
    // Ancak veri butunlugu icin simdilik flush ediyoruz.
    fflush(f_audit);
}

// [YENI] Alert Log (alerts.json) -> Sadece kritik alarmlar
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

// System Log (service.log)
void log_message(LogLevel level, const char *file, int line, const char *format, ...) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    int pid = getpid();
    const char *level_str = get_level_string(level);
    va_list args;

    // 1. TERMINAL CIKTISI
    if (config.verbose_mode || level != LOG_LEVEL_DEBUG) {
        va_start(args, format);
        fprintf(stdout, "%s", get_level_color(level));
        fprintf(stdout, "[%s] [%-5s] [%d] ", timestamp, level_str, pid);
        vfprintf(stdout, format, args);
        fprintf(stdout, "%s\n", ANSI_COLOR_RESET);
        va_end(args);
    }

    // 2. SERVICE LOG DOSYASI
    if (f_service) {
        va_start(args, format);
        fprintf(f_service, "[%s] [%-5s] [%d] ", timestamp, level_str, pid);
        vfprintf(f_service, format, args);
        fprintf(f_service, "\n");
        if (level == LOG_LEVEL_ERROR || level == LOG_LEVEL_ALARM) {
            fflush(f_service);
        }
        va_end(args);
    }
}