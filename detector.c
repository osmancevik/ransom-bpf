/* detector.c */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "detector.h"
#include "logger.h"
#include "config.h"
#include "whitelist.h"

// Yardımcı Fonksiyon: Zaman penceresi kontrolü ve sıfırlama
static void check_window(struct process_stats *s) {
    time_t now = time(NULL);
    double diff = difftime(now, s->window_start_time);

    // Eğer zaman penceresi (örn: 10 sn) dolduysa istatistikleri sıfırla
    if (diff > config.window_sec) {
        s->window_start_time = now;
        s->write_burst = 0;
        s->rename_burst = 0;

        // Pencere dolduğunda süreç "aklanmış" sayılır, risk puanı sıfırlanır.
        s->current_score = 0;
    }
}

// --- YENİ: Şüpheli Uzantı Kontrolü (Task 2.5) ---
static int has_suspicious_extension(const char *filename) {
    if (!filename) return 0;

    // Bilinen fidye yazılımı uzantıları
    const char *suspicious_exts[] = {
        ".locked",
        ".enc",
        ".cry",
        ".crypto",
        ".crypted",
        ".wanna",
        ".dark",
        ".micro",
        ".fun",
        NULL // Liste sonu belirteci
    };

    size_t len = strlen(filename);
    for (int i = 0; suspicious_exts[i] != NULL; i++) {
        const char *ext = suspicious_exts[i];
        size_t ext_len = strlen(ext);

        if (len > ext_len) {
            // Dosya adının sonu (suffix) kontrolü
            if (strcmp(filename + len - ext_len, ext) == 0) {
                return 1; // Şüpheli uzantı bulundu
            }
        }
    }
    return 0;
}

int is_honeypot_access(const char *filename) {
    if (!filename || strlen(config.honeypot_file) == 0) return 0;

    // Dosya yolu içinde tuzak dosya ismi geçiyor mu?
    if (strstr(filename, config.honeypot_file) != NULL) {
        return 1;
    }
    return 0;
}

void analyze_event(struct process_stats *s, const struct event *e) {

    // 1. Whitelist Kontrolü (Gürültü Azaltma)
    if (is_whitelisted(s->comm)) {
        return; // Güvenli süreç, analiz etme.
    }

    // 2. Zaman Penceresi Kontrolü
    check_window(s);

    int score_gained = 0;
    int is_alarm = 0;
    char risk_reason[64] = {0};

    // 3. Olay Türüne Göre Puanlama ve Analiz
    switch (e->type) {
        case EVENT_WRITE:
            s->write_burst++;
            s->total_write_count++;
            score_gained = config.score_write;

            // Honeypot Kontrolü
            if (is_honeypot_access(e->filename)) {
                score_gained += config.score_honeypot;
                snprintf(risk_reason, sizeof(risk_reason), "HONEYPOT WRITE");
            }
            break;

        case EVENT_RENAME:
            s->rename_burst++;
            score_gained = config.score_rename;

            // Honeypot Kontrolü
            if (is_honeypot_access(e->filename)) {
                score_gained += config.score_honeypot;
                snprintf(risk_reason, sizeof(risk_reason), "HONEYPOT RENAME");
            }
            break;

        case EVENT_UNLINK: // Dosya Silme
            score_gained = config.score_unlink;
            break;

        case EVENT_OPEN:
             // Honeypot Kontrolü (Okuma teşebbüsü)
            if (is_honeypot_access(e->filename)) {
                score_gained += config.score_honeypot;
                snprintf(risk_reason, sizeof(risk_reason), "HONEYPOT ACCESS");
            }
            break;
    }

    // --- YENİ: Uzantı Duyarlı Ceza Puanı (Task 2.5) ---
    // Eğer dosya adı şüpheli bir uzantı içeriyorsa ekstra puan ekle
    if ((e->type == EVENT_RENAME || e->type == EVENT_WRITE) && has_suspicious_extension(e->filename)) {
        score_gained += config.score_ext_penalty;

        // Eğer henüz bir sebep atanmamışsa sebebi güncelle
        if (strlen(risk_reason) == 0) {
            snprintf(risk_reason, sizeof(risk_reason), "SUSPICIOUS EXTENSION");
        }
    }

    // 4. Puanı Ekle
    s->current_score += score_gained;

    // 5. Risk Değerlendirmesi (Threshold Check)
    if (strlen(risk_reason) == 0) {
        if (s->current_score >= config.risk_threshold) {
            is_alarm = 1;
            snprintf(risk_reason, sizeof(risk_reason), "RISK THRESHOLD EXCEEDED");
        }
    } else {
        // Honeypot veya Uzantı nedenleriyle zaten şüpheli durum oluşmuşsa
        if (s->current_score >= config.risk_threshold) {
            is_alarm = 1;
        }
        // Not: Honeypot durumunda puan zaten çok yüksek (1000) olduğu için threshold'u her türlü geçer.
    }

    // 6. Alarm Üretimi
    if (is_alarm) {
        LOG_ALARM("FIDYE YAZILIMI SUPHESI [%s]! PID: %d (%s) | File: %s | Score: %d/%d",
                  risk_reason,
                  s->pid,
                  s->comm,
                  e->filename,
                  s->current_score,
                  config.risk_threshold);

        // Alarm sonrası reset
        s->window_start_time = time(NULL);
        s->current_score = 0;
        s->write_burst = 0;
        s->rename_burst = 0;
    }
}