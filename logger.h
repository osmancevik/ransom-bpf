#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

// Renk kodları
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// Log seviyeleri
#define LOG_INFO(fmt, ...)  fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  fprintf(stdout, ANSI_COLOR_YELLOW "[WARN] " fmt ANSI_COLOR_RESET "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   fprintf(stderr, ANSI_COLOR_RED "[ERROR] " fmt ANSI_COLOR_RESET "\n", ##__VA_ARGS__)
#define LOG_ALARM(fmt, ...) fprintf(stdout, ANSI_COLOR_RED "[ALARM] " fmt ANSI_COLOR_RESET "\n", ##__VA_ARGS__)

// Debug modu (İstenirse kapatılabilir)
#define DEBUG_MODE 1
#if DEBUG_MODE
#define LOG_DEBUG(fmt, ...) fprintf(stdout, ANSI_COLOR_BLUE "[DEBUG] " fmt ANSI_COLOR_RESET "\n", ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while (0)
#endif

#endif // LOGGER_H