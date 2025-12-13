#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "logger.h"

// Global değişkenin tanımlanması
struct app_config config;

void load_config(const char *filename) {
    // 1. Önce varsayılanları yükle (Güvenli başlangıç)
    config.window_sec = DEFAULT_WINDOW_SEC;
    config.write_threshold = DEFAULT_WRITE_THRESHOLD;
    config.rename_threshold = DEFAULT_RENAME_THRESHOLD;
    strncpy(config.log_file, DEFAULT_LOG_FILE, sizeof(config.log_file));
    config.verbose_mode = 0;

    FILE *file = fopen(filename, "r");
    if (!file) {
        LOG_WARN("Konfigurasyon dosyasi (%s) bulunamadi. Varsayilan ayarlar kullaniliyor.", filename);
        return;
    }

    char line[256];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        // Yorum satırlarını (#) ve boş satırları atla
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        char key[128], value[128];
        // Satırı "ANAHTAR=DEGER" formatında ayır
        if (sscanf(line, "%127[^=]=%127s", key, value) == 2) {
            
            if (strcmp(key, "WINDOW_SEC") == 0) {
                config.window_sec = atoi(value);
            } 
            else if (strcmp(key, "WRITE_THRESHOLD") == 0) {
                config.write_threshold = atoi(value);
            } 
            else if (strcmp(key, "RENAME_THRESHOLD") == 0) {
                config.rename_threshold = atoi(value);
            } 
            else if (strcmp(key, "LOG_FILE") == 0) {
                // Yeni satır karakterini temizle
                value[strcspn(value, "\n")] = 0;
                strncpy(config.log_file, value, sizeof(config.log_file));
            }
            else if (strcmp(key, "WHITELIST") == 0) {
                // Config dosyasından gelen whitelist string'ini struct'a kopyala
                value[strcspn(value, "\n")] = 0; // Varsa sondaki enter karakterini sil
                strncpy(config.whitelist_str, value, MAX_WHITELIST_LENGTH - 1);
                config.whitelist_str[MAX_WHITELIST_LENGTH - 1] = '\0'; // Null terminator garantisi
            }
        }
    }

    fclose(file);
    LOG_INFO("Konfigurasyon yuklendi: Pencere=%ds, YazmaLimiti=%d, RenameLimiti=%d", 
             config.window_sec, config.write_threshold, config.rename_threshold);
}