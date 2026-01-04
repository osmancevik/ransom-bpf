/* config.c - v0.9.5 (Active Blocking Switch) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // strcasecmp icin gerekli
#include "config.h"
#include "logger.h"

struct app_config config;

void init_config_defaults() {
    config.window_sec = DEFAULT_WINDOW_SEC;
    config.write_threshold = 15;
    config.rename_threshold = 5;

    config.score_write = DEFAULT_SCORE_WRITE;
    config.score_rename = DEFAULT_SCORE_RENAME;
    config.score_unlink = DEFAULT_SCORE_UNLINK;
    config.score_honeypot = DEFAULT_SCORE_HONEYPOT;
    config.score_ext_penalty = DEFAULT_SCORE_EXT_PENALTY;

    config.risk_threshold = DEFAULT_RISK_THRESHOLD;

    // [YENI] Faz 5: Aktif Engelleme Varsayilan Olarak KAPALI (Guvenlik)
    config.active_blocking = 0;

    // [YENI] Varsayilan dosya yollari
    strncpy(config.service_log, DEFAULT_SERVICE_LOG, sizeof(config.service_log));
    strncpy(config.alert_log, DEFAULT_ALERT_LOG, sizeof(config.alert_log));
    strncpy(config.audit_log, DEFAULT_AUDIT_LOG, sizeof(config.audit_log));

    config.verbose_mode = 0;
    memset(config.whitelist_str, 0, sizeof(config.whitelist_str));
    memset(config.honeypot_file, 0, sizeof(config.honeypot_file));
    memset(config.config_path, 0, sizeof(config.config_path));
}

void load_config_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) return;

    char line[4096];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        char key[128];
        char value[2048];

        if (sscanf(line, "%127[^=]=%2047s", key, value) == 2) {

            if (strcmp(key, "WINDOW_SEC") == 0) config.window_sec = atoi(value);
            else if (strcmp(key, "RISK_THRESHOLD") == 0) config.risk_threshold = atoi(value);

            // [YENI] Faz 5: Aktif Engelleme Parametresi
            else if (strcmp(key, "ACTIVE_BLOCKING") == 0) {
                // "true", "TRUE" veya "1" gelirse aktif et
                if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
                    config.active_blocking = 1;
                } else {
                    config.active_blocking = 0;
                }
            }

            // Puanlar
            else if (strcmp(key, "SCORE_WRITE") == 0) config.score_write = atoi(value);
            else if (strcmp(key, "SCORE_RENAME") == 0) config.score_rename = atoi(value);
            else if (strcmp(key, "SCORE_UNLINK") == 0) config.score_unlink = atoi(value);
            else if (strcmp(key, "SCORE_HONEYPOT") == 0) config.score_honeypot = atoi(value);
            else if (strcmp(key, "SCORE_EXT_PENALTY") == 0) config.score_ext_penalty = atoi(value);

            // [YENI] Log Dosyalari
            else if (strcmp(key, "SERVICE_LOG") == 0) {
                value[strcspn(value, "\n")] = 0;
                strncpy(config.service_log, value, sizeof(config.service_log) - 1);
            }
            else if (strcmp(key, "ALERT_LOG") == 0) {
                value[strcspn(value, "\n")] = 0;
                strncpy(config.alert_log, value, sizeof(config.alert_log) - 1);
            }
            else if (strcmp(key, "AUDIT_LOG") == 0) {
                value[strcspn(value, "\n")] = 0;
                strncpy(config.audit_log, value, sizeof(config.audit_log) - 1);
            }
            // Geri Uyumluluk (Eski 'LOG_FILE' parametresi gelirse service log yap)
            else if (strcmp(key, "LOG_FILE") == 0) {
                value[strcspn(value, "\n")] = 0;
                strncpy(config.service_log, value, sizeof(config.service_log) - 1);
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