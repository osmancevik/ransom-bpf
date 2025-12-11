#ifndef CONFIG_H
#define CONFIG_H

// Varsayılan Değerler (Dosya bulunamazsa bunlar kullanılır)
#define DEFAULT_WINDOW_SEC 2
#define DEFAULT_WRITE_THRESHOLD 15
#define DEFAULT_RENAME_THRESHOLD 5
#define DEFAULT_LOG_FILE "/var/log/ransom-bpf.log"

struct app_config {
    int window_sec;          // Analiz penceresi süresi (sn)
    int write_threshold;     // Yazma limiti
    int rename_threshold;    // Yeniden adlandırma limiti
    char log_file[256];      // Log dosyası yolu
    int verbose_mode;        // Detaylı çıktı modu
};

// Global konfigürasyon nesnesi (Her yerden erişilebilir)
extern struct app_config config;

// Fonksiyon prototipi
void load_config(const char *filename);

#endif // CONFIG_H