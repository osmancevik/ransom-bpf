/* detector.c */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h> // Matematiksel işlemler gerekirse
#include "detector.h"
#include "logger.h"
#include "config.h"
#include "whitelist.h"

// --- YENİ: Sönümleme (Decay) Algoritması ---
// Görev 2.7: Riski zamanla yavaş yavaş azalt
static void apply_decay(struct process_stats *s) {
    time_t now = time(NULL);
    double diff = difftime(now, s->last_decay_time);

    // En az 1 saniye geçmişse sönümleme uygula
    if (diff >= 1.0) {
        // Algoritma: Her saniye için mevcut skorun %10'u kadar azalt.
        // Örn: 5 saniye boşluk varsa -> 0.1 * 5 = 0.5 (%50 azalma)
        // Bu, uzun süre pasif kalan saldırganın "soğumasını" sağlar.

        int decay_amount = (int)(s->current_score * 0.10 * diff);

        // Eğer skor pozitifse ama decay 0 çıkıyorsa (örn skor=5 ise %10'u 0 yapar),
        // en az 1 puan düşürerek erimeyi garanti et.
        if (s->current_score > 0 && decay_amount == 0) {
            decay_amount = 1;
        }

        s->current_score -= decay_amount;

        // Negatif kontrolü
        if (s->current_score < 0) {
            s->current_score = 0;
        }

        // Eğer skor sıfırlandıysa burst sayaçlarını da temizle (isteğe bağlı ama önerilir)
        if (s->current_score == 0) {
            s->write_burst = 0;
            s->rename_burst = 0;
        }

        // Zamanı güncelle
        s->last_decay_time = now;
    }
}

static int has_suspicious_extension(const char *filename) {
    if (!filename) return 0;
    const char *suspicious_exts[] = {
        ".locked", ".enc", ".cry", ".crypto", ".crypted",
        ".wanna", ".dark", NULL
    };
    size_t len = strlen(filename);
    for (int i = 0; suspicious_exts[i] != NULL; i++) {
        const char *ext = suspicious_exts[i];
        size_t ext_len = strlen(ext);
        if (len > ext_len) {
            if (strcmp(filename + len - ext_len, ext) == 0) return 1;
        }
    }
    return 0;
}

int is_honeypot_access(const char *filename) {
    if (!filename || strlen(config.honeypot_file) == 0) return 0;
    if (strstr(filename, config.honeypot_file) != NULL) return 1;
    return 0;
}

void analyze_event(struct process_stats *s, const struct event *e) {

    // 1. Whitelist
    if (is_whitelisted(s->comm)) return;

    // 2. --- YENİ: Sönümleme Uygula ---
    // (Eski check_window yerine artık bu var)
    apply_decay(s);

    int score_gained = 0;
    int is_alarm = 0;
    char risk_reason[64] = {0};

    // 3. Olay Türüne Göre Puanlama
    switch (e->type) {
        case EVENT_WRITE:
            s->write_burst++;
            s->total_write_count++;
            score_gained = config.score_write;
            if (is_honeypot_access(e->filename)) {
                score_gained += config.score_honeypot;
                snprintf(risk_reason, sizeof(risk_reason), "HONEYPOT WRITE");
            }
            break;

        case EVENT_RENAME:
            s->rename_burst++;
            score_gained = config.score_rename;
            if (is_honeypot_access(e->filename)) {
                score_gained += config.score_honeypot;
                snprintf(risk_reason, sizeof(risk_reason), "HONEYPOT RENAME");
            }
            break;

        case EVENT_UNLINK:
            score_gained = config.score_unlink;
            break;

        case EVENT_OPEN:
            if (is_honeypot_access(e->filename)) {
                score_gained += config.score_honeypot;
                snprintf(risk_reason, sizeof(risk_reason), "HONEYPOT ACCESS");
            }
            break;
    }

    // Dizin Hassasiyeti (Task 2.6)
    double multiplier = 1.0;
    if (e->filename) {
        if (strncmp(e->filename, "/home", 5) == 0) multiplier = 2.0;
        else if (strncmp(e->filename, "/etc", 4) == 0) multiplier = 5.0;
        else if (strncmp(e->filename, "/var/www", 8) == 0) multiplier = 2.0;
        else if (strncmp(e->filename, "/tmp", 4) == 0) multiplier = 0.5;
    }
    score_gained = (int)(score_gained * multiplier);

    // Uzantı Cezası (Task 2.5)
    if ((e->type == EVENT_RENAME || e->type == EVENT_WRITE) && has_suspicious_extension(e->filename)) {
        score_gained += config.score_ext_penalty;
        if (strlen(risk_reason) == 0) snprintf(risk_reason, sizeof(risk_reason), "SUSPICIOUS EXTENSION");
    }

    // 4. Puanı Ekle
    s->current_score += score_gained;

    // 5. Alarm Kontrolü
    if (strlen(risk_reason) == 0) {
        if (s->current_score >= config.risk_threshold) {
            is_alarm = 1;
            snprintf(risk_reason, sizeof(risk_reason), "RISK THRESHOLD EXCEEDED");
        }
    } else {
        if (s->current_score >= config.risk_threshold) is_alarm = 1;
    }

    // 6. Alarm
    if (is_alarm) {
        LOG_ALARM("FIDYE YAZILIMI SUPHESI [%s]! PID: %d (%s) | File: %s | Score: %d/%d",
                  risk_reason, s->pid, s->comm, e->filename, s->current_score, config.risk_threshold);

        // Alarm sonrası reset
        s->current_score = 0;
        s->write_burst = 0;
        s->rename_burst = 0;
        // Decay zamanını da sıfırla ki hemen tekrar decay yapmasın
        s->last_decay_time = time(NULL);
    }
}