#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

// Log Seviyeleri
enum log_level {
    LEVEL_INFO,
    LEVEL_WARN,
    LEVEL_ERROR,
    LEVEL_ALARM,
    LEVEL_DEBUG
};

// Fonksiyon Prototipleri
void init_logger();
void finalize_logger();
void log_message(enum log_level level, const char *format, ...);

// Kullanım kolaylığı için Makrolar (Eskisi gibi kullanmaya devam edebilirsin)
#define LOG_INFO(fmt, ...)  log_message(LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_message(LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   log_message(LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define LOG_ALARM(fmt, ...) log_message(LEVEL_ALARM, fmt, ##__VA_ARGS__)

#define DEBUG_MODE 1
#if DEBUG_MODE
#define LOG_DEBUG(fmt, ...) log_message(LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while (0)
#endif

#endif // LOGGER_H