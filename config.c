/* config.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "logger.h"

struct app_config config;

void init_config_defaults() {
    config.window_sec = DEFAULT_WINDOW_SEC;
    config.write_threshold = DEFAULT_WRITE_THRESHOLD;
    config.rename_threshold = DEFAULT_RENAME_THRESHOLD;

    // --- YENİ: Puanlama Varsayılanları ---
    config.score_write = DEFAULT_SCORE_WRITE;
    config.score_rename = DEFAULT_SCORE_RENAME;
    config.score_unlink = DEFAULT_SCORE_UNLINK;
    config.score_honeypot = DEFAULT_SCORE_HONEYPOT;
    config.risk_threshold = DEFAULT_RISK_THRESHOLD;

    // Diğer ayarlar
    strncpy(config.log_file, DEFAULT_LOG_FILE, sizeof(config.log_file));
    config.verbose_mode = 0;
    memset(config.whitelist_str, 0, sizeof(config.whitelist_str));
    memset(config.honeypot_file, 0, sizeof(config.honeypot_file));
    memset(config.config_path, 0, sizeof(config.config_path));
}

void load_config_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        // Dosya yoksa sessizce devam et (Varsayılanlar kullanılır)
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        // Yorum satırlarını ve boş satırları atla
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        char key[128], value[128];
        // Basit "KEY=VALUE" ayrıştırma
        if (sscanf(line, "%127[^=]=%127s", key, value) == 2) {
            // Eski Ayarlar
            if (strcmp(key, "WINDOW_SEC") == 0) config.window_sec = atoi(value);
            else if (strcmp(key, "WRITE_THRESHOLD") == 0) config.write_threshold = atoi(value);
            else if (strcmp(key, "RENAME_THRESHOLD") == 0) config.rename_threshold = atoi(value);

            // --- YENİ: Puanlama Ayarları ---
            else if (strcmp(key, "SCORE_WRITE") == 0) config.score_write = atoi(value);
            else if (strcmp(key, "SCORE_RENAME") == 0) config.score_rename = atoi(value);
            else if (strcmp(key, "SCORE_UNLINK") == 0) config.score_unlink = atoi(value);
            else if (strcmp(key, "SCORE_HONEYPOT") == 0) config.score_honeypot = atoi(value);
            else if (strcmp(key, "RISK_THRESHOLD") == 0) config.risk_threshold = atoi(value);

            // Dosya Yolları ve Stringler
            else if (strcmp(key, "LOG_FILE") == 0) {
                value[strcspn(value, "\n")] = 0; // Sondaki newline karakterini temizle
                strncpy(config.log_file, value, sizeof(config.log_file) - 1);
            }
            else if (strcmp(key, "WHITELIST") == 0) {
                value[strcspn(value, "\n")] = 0;
                strncpy(config.whitelist_str, value, MAX_WHITELIST_LENGTH - 1);
            }
            else if (strcmp(key, "HONEYPOT_FILE") == 0) {
                value[strcspn(value, "\n")] = 0;
                strncpy(config.honeypot_file, value, sizeof(config.honeypot_file) - 1);
            }
        }
    }
    fclose(file);
}