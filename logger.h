#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

// Log Seviyeleri
typedef enum {
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_ALARM,
    LOG_LEVEL_DEBUG
} LogLevel;

// ANSI Renk Kodlari (Terminal icin)
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// Fonksiyon Prototipleri
void init_logger();
void finalize_logger();
void log_message(LogLevel level, const char *file, int line, const char *format, ...);

// Kolay kullanim makrolari
// __FILE__ ve __LINE__ hata ayiklama icin eklendi ama cikti formatinda istenmedigi icin arka planda kullanilacak
#define LOG_INFO(...)  log_message(LOG_LEVEL_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_message(LOG_LEVEL_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERR(...)   log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ALARM(...) log_message(LOG_LEVEL_ALARM, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#endif // LOGGER_H