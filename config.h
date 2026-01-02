/* config.h */
#ifndef CONFIG_H
#define CONFIG_H

// Varsayılan Eşik Değerleri (Eski - Geri uyumluluk için tutulabilir veya yeni mantıkla değiştirilebilir)
#define DEFAULT_WINDOW_SEC 5
#define DEFAULT_WRITE_THRESHOLD 15
#define DEFAULT_RENAME_THRESHOLD 5

// --- YENİ: Varsayılan Puanlar ve Risk Limiti ---
// Mantık: Risk > THRESHOLD ise ALARM ver.
#define DEFAULT_SCORE_WRITE 2       // Her yazma işlemi için düşük puan
#define DEFAULT_SCORE_RENAME 20     // İsim değiştirme daha şüpheli
#define DEFAULT_SCORE_UNLINK 50     // Dosya silme oldukça şüpheli
#define DEFAULT_SCORE_HONEYPOT 1000 // Honeypot'a dokunmak kesin suçtur (Anında Alarm)
#define DEFAULT_RISK_THRESHOLD 100  // Alarm üretmek için gereken toplam puan

#define DEFAULT_LOG_FILE "/var/log/ransom-bpf.log"
#define MAX_WHITELIST_LENGTH 512

struct app_config {
    // Zaman Penceresi
    int window_sec;

    // Eski Eşikler (Hala kullanılabilir veya loglama için referans olabilir)
    int write_threshold;
    int rename_threshold;

    // --- YENİ: Dinamik Puanlama Parametreleri ---
    int score_write;
    int score_rename;
    int score_unlink;
    int score_honeypot;
    int risk_threshold;

    // Yollar ve Ayarlar
    char log_file[256];
    int verbose_mode;
    char whitelist_str[MAX_WHITELIST_LENGTH];
    char honeypot_file[256];
    char config_path[256];
};

extern struct app_config config;

void init_config_defaults();
void load_config_file(const char *filename);

#endif // CONFIG_H