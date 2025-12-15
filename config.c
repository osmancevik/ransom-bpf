#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "logger.h"

struct app_config config;

// 1. Sadece varsayılan değerleri atar (Sıfırlama yapar)
void init_config_defaults() {
    config.window_sec = DEFAULT_WINDOW_SEC;
    config.write_threshold = DEFAULT_WRITE_THRESHOLD;
    config.rename_threshold = DEFAULT_RENAME_THRESHOLD;
    strncpy(config.log_file, DEFAULT_LOG_FILE, sizeof(config.log_file));
    config.verbose_mode = 0;
    memset(config.whitelist_str, 0, sizeof(config.whitelist_str));
}

// 2. Verilen dosyadan ayarları okur ve mevcut ayarların üzerine yazar
void load_config_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        // Dosya yoksa sadece uyarı ver, programı durdurma (CLI'dan ayar gelebilir)
        LOG_WARN("Konfigurasyon dosyasi (%s) okunamadi.", filename);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        char key[128], value[128];
        if (sscanf(line, "%127[^=]=%127s", key, value) == 2) {
            if (strcmp(key, "WINDOW_SEC") == 0) config.window_sec = atoi(value);
            else if (strcmp(key, "WRITE_THRESHOLD") == 0) config.write_threshold = atoi(value);
            else if (strcmp(key, "RENAME_THRESHOLD") == 0) config.rename_threshold = atoi(value);
            else if (strcmp(key, "LOG_FILE") == 0) {
                value[strcspn(value, "\n")] = 0;
                strncpy(config.log_file, value, sizeof(config.log_file));
            }
            else if (strcmp(key, "WHITELIST") == 0) {
                value[strcspn(value, "\n")] = 0;
                strncpy(config.whitelist_str, value, MAX_WHITELIST_LENGTH - 1);
            }
        }
    }
    fclose(file);
    LOG_INFO("Ayarlar dosyalardan yuklendi: %s", filename);
}