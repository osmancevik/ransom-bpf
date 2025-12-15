#ifndef CONFIG_H
#define CONFIG_H

// Varsayılan Değerler
#define DEFAULT_WINDOW_SEC 5
#define DEFAULT_WRITE_THRESHOLD 15
#define DEFAULT_RENAME_THRESHOLD 5
#define DEFAULT_LOG_FILE "/var/log/ransom-bpf.log"
#define MAX_WHITELIST_LENGTH 512

struct app_config {
    int window_sec;
    int write_threshold;
    int rename_threshold;
    char log_file[256];
    int verbose_mode;
    char whitelist_str[MAX_WHITELIST_LENGTH];
};

extern struct app_config config;

// Fonksiyonlar ayrıştırıldı
void init_config_defaults();
void load_config_file(const char *filename);

#endif // CONFIG_H