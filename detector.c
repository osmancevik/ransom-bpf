/* detector.c - v0.9.0 (Routing Logs) */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "detector.h"
#include "logger.h"
#include "config.h"
#include "whitelist.h"

// ... (apply_decay, has_suspicious_extension, is_honeypot_access fonksiyonları AYNI KALACAK) ...
// (Lütfen önceki tam detector.c dosyasındaki yardımcı fonksiyonları buraya ekleyin)

// --- YARDIMCI FONKSIYONLAR ---
static void apply_decay(struct process_stats *s) {
    time_t now = time(NULL);
    double diff = difftime(now, s->last_decay_time);
    if (diff >= 1.0) {
        int decay_amount = (int)(s->current_score * 0.10 * diff);
        if (s->current_score > 0 && decay_amount == 0) decay_amount = 1;
        s->current_score -= decay_amount;
        if (s->current_score < 0) s->current_score = 0;
        if (s->current_score == 0) { s->write_burst = 0; s->rename_burst = 0; }
        s->last_decay_time = now;
    }
}

static int has_suspicious_extension(const char *filename) {
    if (!filename) return 0;
    const char *suspicious_exts[] = { ".locked", ".enc", ".cry", ".crypto", ".crypted", ".wanna", ".dark", NULL };
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

// --- ANA ANALIZ ---

void analyze_event(struct process_stats *s, const struct event *e) {

    // 1. Whitelist Filtresi (Gürültüyü burada kesiyoruz)
    if (is_whitelisted(s->comm)) return;

    // 2. [YENI] Audit Loglama (Whitelist'i gecen HAM olaylari kaydet)
    const char *event_name = "UNKNOWN";
    switch(e->type) {
        case EVENT_WRITE: event_name = "WRITE"; break;
        case EVENT_RENAME: event_name = "RENAME"; break;
        case EVENT_OPEN: event_name = "OPEN"; break;
        case EVENT_UNLINK: event_name = "UNLINK"; break;
    }

    // Ham veriyi 'audit.json'a yaz
    log_audit_json(event_name, s->pid, e->ppid, e->uid, s->comm, e->filename);

    // 3. Analiz ve Puanlama
    apply_decay(s);

    int score_gained = 0;
    int is_alarm = 0;
    char risk_reason[64] = {0};

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

    double multiplier = 1.0;
    if (e->filename) {
        if (strncmp(e->filename, "/home", 5) == 0) multiplier = 2.0;
        else if (strncmp(e->filename, "/etc", 4) == 0) multiplier = 5.0;
        else if (strncmp(e->filename, "/var/www", 8) == 0) multiplier = 2.0;
        else if (strncmp(e->filename, "/tmp", 4) == 0) multiplier = 0.5;
    }
    score_gained = (int)(score_gained * multiplier);

    if ((e->type == EVENT_RENAME || e->type == EVENT_WRITE) && has_suspicious_extension(e->filename)) {
        score_gained += config.score_ext_penalty;
        if (strlen(risk_reason) == 0) snprintf(risk_reason, sizeof(risk_reason), "SUSPICIOUS EXTENSION");
    }

    s->current_score += score_gained;

    if (strlen(risk_reason) == 0) {
        if (s->current_score >= config.risk_threshold) {
            is_alarm = 1;
            snprintf(risk_reason, sizeof(risk_reason), "RISK THRESHOLD EXCEEDED");
        }
    } else {
        if (s->current_score >= config.risk_threshold) is_alarm = 1;
    }

    // 4. Alarm Loglama (Sadece Kritik Olaylar)
    if (is_alarm) {
        // Konsola (Renkli)
        LOG_ALARM("FIDYE YAZILIMI SUPHESI [%s]! PID:%d UID:%d | File:%s | Score:%d",
                  risk_reason, s->pid, e->uid, e->filename, s->current_score);

        // Alerts Dosyasina (alerts.json)
        log_alert_json(
            "RANSOMWARE_DETECTED",
            s->pid,
            e->ppid,
            e->uid,
            s->comm,
            e->filename,
            risk_reason,
            s->current_score
        );

        s->current_score = 0;
        s->write_burst = 0;
        s->rename_burst = 0;
        s->last_decay_time = time(NULL);
    }
}