#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include "logger.h"
#include "config.h" // Log dosyası yolunu almak için

static FILE *log_file_ptr = NULL;

// Renk Kodları (Sadece terminal için)
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void init_logger() {
    // Config'den gelen dosya yolunu kullan
    log_file_ptr = fopen(config.log_file, "a"); // 'a' = append (ekleme) modu
    if (!log_file_ptr) {
        fprintf(stderr, "[WARN] Log dosyasi (%s) acilamadi! Sadece ekrana yazilacak.\n", config.log_file);
    } else {
        LOG_INFO("--- Log Sistemi Baslatildi ---");
    }
}

void finalize_logger() {
    if (log_file_ptr) {
        LOG_INFO("--- Log Sistemi Kapatiliyor ---");
        fclose(log_file_ptr);
        log_file_ptr = NULL;
    }
}

// O anki zamanı "YYYY-MM-DD HH:MM:SS" formatında döndürür
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", t);
}

void log_message(enum log_level level, const char *format, ...) {
    va_list args;
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    // 1. Etiket Belirleme
    const char *label_txt;
    const char *color_code;

    switch (level) {
        case LEVEL_INFO:  label_txt = "INFO";  color_code = ANSI_COLOR_GREEN; break;
        case LEVEL_WARN:  label_txt = "WARN";  color_code = ANSI_COLOR_YELLOW; break;
        case LEVEL_ERROR: label_txt = "ERROR"; color_code = ANSI_COLOR_RED; break;
        case LEVEL_ALARM: label_txt = "ALARM"; color_code = ANSI_COLOR_RED; break; // Alarm da kırmızı
        case LEVEL_DEBUG: label_txt = "DEBUG"; color_code = ANSI_COLOR_BLUE; break;
        default:          label_txt = "LOG";   color_code = ANSI_COLOR_RESET; break;
    }

    // 2. Dosyaya Yazma (Varsa) - RENKSİZ ve ZAMAN DAMGALI
    if (log_file_ptr) {
        fprintf(log_file_ptr, "[%s] [%s] ", timestamp, label_txt);
        va_start(args, format);
        vfprintf(log_file_ptr, format, args);
        va_end(args);
        fprintf(log_file_ptr, "\n");
        fflush(log_file_ptr); // Kritik: Anında diske yaz (Crash durumunda veri kaybını önler)
    }

    // 3. Ekrana Yazma (Terminal) - RENKLİ ve SADE
    // ALARM ve ERROR ise stderr, diğerleri stdout
    FILE *target_stream = (level == LEVEL_ERROR || level == LEVEL_ALARM) ? stderr : stdout;
    
    fprintf(target_stream, "%s[%s]%s ", color_code, label_txt, ANSI_COLOR_RESET);
    va_start(args, format);
    vfprintf(target_stream, format, args);
    va_end(args);
    fprintf(target_stream, "\n");
}