/* config.h - v0.9.0 (Multi-Channel Logging) */
#ifndef CONFIG_H
#define CONFIG_H

#define DEFAULT_WINDOW_SEC 5
#define DEFAULT_RISK_THRESHOLD 100

// Puanlama Varsayilanlari
#define DEFAULT_SCORE_WRITE 2
#define DEFAULT_SCORE_RENAME 20
#define DEFAULT_SCORE_UNLINK 50
#define DEFAULT_SCORE_HONEYPOT 1000
#define DEFAULT_SCORE_EXT_PENALTY 50

// [YENI] Varsayilan Log Dosyalari
#define DEFAULT_SERVICE_LOG "./service.log"
#define DEFAULT_ALERT_LOG   "./alerts.json"
#define DEFAULT_AUDIT_LOG   "./audit.json"

#define MAX_WHITELIST_LENGTH 2048

struct app_config {
    int window_sec;
    int write_threshold;
    int rename_threshold;

    // Puanlama
    int score_write;
    int score_rename;
    int score_unlink;
    int score_honeypot;
    int score_ext_penalty;
    int risk_threshold;
    int active_blocking;


    // [YENI] Log Dosyasi Yollari (Eski 'log_file' kaldirildi)
    char service_log[256];
    char alert_log[256];
    char audit_log[256];

    int verbose_mode;
    char whitelist_str[MAX_WHITELIST_LENGTH];
    char honeypot_file[256];
    char config_path[256];
};

extern struct app_config config;

void init_config_defaults();
void load_config_file(const char *filename);

#endif // CONFIG_H