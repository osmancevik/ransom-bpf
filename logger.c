/* logger.c */
#include "logger.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <sys/time.h> // gettimeofday icin
#include <unistd.h>   // getpid icin

static FILE *log_file = NULL;

void init_logger() {
    // DUZELTME: config.log_file dizisini doğrudan kullanıyoruz.
    // Eğer config dosyasından okunmadıysa varsayılan değer config.c içinde atanmış olmalı.
    // Yine de güvenlik için boş mu diye kontrol edelim.
    const char *path = (strlen(config.log_file) > 0) ? config.log_file : "ransom.log";
    
    log_file = fopen(path, "a");
    if (!log_file) {
        perror("Log dosyasi acilamadi (Dosyaya yazilamayacak)");
    }
}

void finalize_logger() {
    if (log_file) {
        fflush(log_file); // Tamponu bosalt
        fclose(log_file);
        log_file = NULL;
    }
}

// Milisaniye hassasiyetli zaman damgasi olusturur
// Format: YYYY-MM-DD HH:MM:SS.mmm
static void get_timestamp(char *buffer, size_t size) {
    struct timeval tv;
    struct tm *tm_info;
    
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);

    char fmt_buffer[32];
    strftime(fmt_buffer, sizeof(fmt_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Milisaniyeyi ekle
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
        case LOG_LEVEL_ALARM: return ANSI_COLOR_RED; // Alarm da kirmizi
        case LOG_LEVEL_DEBUG: return ANSI_COLOR_BLUE;
        default:              return ANSI_COLOR_RESET;
    }
}

void log_message(LogLevel level, const char *file, int line, const char *format, ...) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    int pid = getpid();
    const char *level_str = get_level_string(level);

    // Arguman listesini hazirla
    va_list args;
    
    // 1. TERMINAL CIKTISI (Renkli)
    // Format: [TIMESTAMP] [LEVEL] [PID] Message
    va_start(args, format);
    
    // Renk baslangici
    fprintf(stdout, "%s", get_level_color(level));
    
    // Standart On Ek: [2025-12-16 14:30:05.123] [INFO] [1234] 
    fprintf(stdout, "[%s] [%-5s] [%d] ", timestamp, level_str, pid);
    
    // Mesaj
    vfprintf(stdout, format, args);
    
    // Renk sifirlama ve yeni satir
    fprintf(stdout, "%s\n", ANSI_COLOR_RESET);
    
    va_end(args);

    // 2. DOSYA CIKTISI (Renksiz, Duz Metin)
    if (log_file) {
        va_start(args, format);
        
        // Format: [TIMESTAMP] [LEVEL] [PID] Message
        fprintf(log_file, "[%s] [%-5s] [%d] ", timestamp, level_str, pid);
        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");

        // Kritik hatalarda veya alarmlarda dosyaya hemen yazilmasini garantile
        if (level == LOG_LEVEL_ERROR || level == LOG_LEVEL_ALARM) {
            fflush(log_file);
        }

        va_end(args);
    }
}