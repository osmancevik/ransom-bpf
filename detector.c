#include <stdio.h>
#include <string.h>
#include <time.h>
#include "detector.h"
#include "logger.h"
#include "config.h"

// Varsayılan Honeypot dosya adı (Config'den gelmezse yedek)
#define DEFAULT_HONEYPOT "secret_passwords.txt"

// Yardımcı fonksiyon: Pencere kontrolü (Zaman aşımı varsa sayacı sıfırlar)
static void check_window(struct process_stats *s) {
    time_t now = time(NULL);
    // Config'den gelen pencere süresini kullan
    if (difftime(now, s->window_start_time) >= config.window_sec) {
        s->window_start_time = now;
        s->write_burst = 0;
        s->rename_burst = 0;
    }
}

// GÖREV 1.2: Honeypot Kontrol Fonksiyonu
int is_honeypot_access(const char *filename) {
    if (!filename) return 0;

    // Config'de tanımlı tuzak dosya adını al, yoksa varsayılanı kullan
    const char *trap_file = (strlen(config.honeypot_file) > 0) ? config.honeypot_file : DEFAULT_HONEYPOT;

    // Dosya adının içinde tuzak dosya ismi geçiyor mu?
    if (strstr(filename, trap_file) != NULL) {
        return 1;
    }
    return 0;
}

void analyze_event(struct process_stats *s, const struct event *e) {
    check_window(s);

    // 1. Önce Honeypot kontrolü (En kritik)
    if (e->type == EVENT_OPEN || e->type == EVENT_WRITE || e->type == EVENT_RENAME) {
        if (is_honeypot_access(e->filename)) {
            LOG_ALARM("KRITIK: TUZAK DOSYAYA ERISIM (HONEYPOT)! PID: %d (%s) -> Dosya: %s",
                      s->pid, s->comm, e->filename);
            // Burada return diyerek diğer kontrollere girmeyebiliriz veya devam edebiliriz.
            // Şimdilik analiz devam etsin.
        }
    }

    switch (e->type) {
        case EVENT_EXEC:
            s->total_exec_count++;
            LOG_INFO("[EXEC] PID: %-6d | COMM: %s | FILE: %s", s->pid, s->comm, e->filename);
            break;

        case EVENT_WRITE:
            s->total_write_count++;
            s->write_burst++;

            // Config'den gelen eşik değerini kullan (Test 1'i düzelten kısım burası)
            if (s->write_burst > config.write_threshold) {
                LOG_ALARM("FIDYE YAZILIMI SUPHESI (WRITE BURST)! PID: %d (%s) -> %u dosya (Limit: %d)",
                          s->pid, s->comm, s->write_burst, config.write_threshold);
                s->write_burst = 0; // Alarm sonrası sayacı sıfırla
            }
            break;

        case EVENT_RENAME:
            s->rename_burst++;

            if (s->rename_burst > config.rename_threshold) {
                LOG_ALARM("FIDYE YAZILIMI SUPHESI (RENAME BURST)! PID: %d (%s) -> %u dosya (Limit: %d)",
                          s->pid, s->comm, s->rename_burst, config.rename_threshold);
                s->rename_burst = 0;
            } else {
                LOG_INFO("[RENAME] PID: %-6d | File: %s", s->pid, e->filename);
            }
            break;

        // GÖREV 1.3: Silme Analizi
        // Not: common.h dosyasında EVENT_DELETE tanımlı olmalı veya 6 olarak varsayıyoruz
        case 6: // EVENT_DELETE
             LOG_INFO("[DELETE] Dosya silindi. PID: %d | Dosya: %s", s->pid, e->filename);
             break;

        default:
            break;
    }
}