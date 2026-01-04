/* detector.c - v0.9.7 (Safety Filters & Collateral Damage Prevention) */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h> // kill() ve SIGKILL icin
#include <errno.h>  // Hata kodlari icin
#include "detector.h"
#include "logger.h"
#include "config.h"
#include "whitelist.h"

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

// [GUNCEL] Surec Sonlandirma Yardimcisi (Guvenlik Filtreli)
static void kill_process(struct process_stats *s, const struct event *e, const char *original_reason) {

    // --- GUVENLIK FILTRESI (Safety Checks) ---

    // 1. Kritik Sistem Sureci Korumasi (PID 0, 1)
    // PID 1 (init/systemd) oldurulurse sistem kernel panic verir ve coker.
    if (s->pid <= 1) {
        LOG_ERR("⚠️ KRITIK GUVENLIK: PID %d (init/systemd) oldurulmeye calisildi! Engellendi.", s->pid);
        log_alert_json(
            "KILL_PREVENTED",
            s->pid, e->ppid, e->uid, s->comm, e->filename,
            "Critical System Process Protection",
            s->current_score
        );
        return;
    }

    // 2. Beyaz Liste Korumasi (Last Resort Check)
    // Analiz motorunun basinda kontrol ediliyor ama burasi "son durak".
    // Yazilimdaki bir bug veya race condition nedeniyle buraya ulasirsa engelle.
    if (is_whitelisted(s->comm)) {
        LOG_WARN("⚠️ GUVENLIK: Whitelist'teki surec (%s) oldurulmeye calisildi! Engellendi.", s->comm);
        log_alert_json(
            "KILL_PREVENTED",
            s->pid, e->ppid, e->uid, s->comm, e->filename,
            "Whitelisted Process Protection",
            s->current_score
        );
        return;
    }

    // --- MUDAHALE (Action) ---

    // 9 = SIGKILL (Kesin ve yakalanamaz sonlandirma)
    int ret = kill(s->pid, SIGKILL);

    if (ret == 0) {
        // BASARILI: Terminale Logla
        LOG_ALARM("⛔ AKTIF MUDAHALE: Surec Olduruldu! PID: %d (%s)", s->pid, s->comm);

        // BASARILI: Alerts JSON'a 'PROCESS_KILLED' olarak kaydet
        log_alert_json(
            "PROCESS_KILLED",
            s->pid,
            e->ppid,
            e->uid,
            s->comm,
            e->filename,
            "Active Blocking Triggered",
            s->current_score
        );
    } else {
        // HATA: Yetki yok, surec zaten olmus veya zombie
        LOG_ERR("❌ MUDAHALE BASARISIZ: Surec oldurulemedi (PID: %d). Hata: %s", s->pid, strerror(errno));

        log_alert_json(
            "KILL_FAILED",
            s->pid, e->ppid, e->uid, s->comm, e->filename, strerror(errno), s->current_score
        );
    }
}

// --- ANA ANALIZ ---

void analyze_event(struct process_stats *s, const struct event *e) {

    // 1. Whitelist Filtresi (Gürültüyü burada kesiyoruz)
    if (is_whitelisted(s->comm)) return;

    // 2. Audit Loglama (Whitelist'i gecen HAM olaylari kaydet)
    const char *event_name = "UNKNOWN";
    switch(e->type) {
        case EVENT_WRITE: event_name = "WRITE"; break;
        case EVENT_RENAME: event_name = "RENAME"; break;
        case EVENT_OPEN: event_name = "OPEN"; break;
        case EVENT_UNLINK: event_name = "UNLINK"; break;
    }

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

    // 4. Alarm ve Müdahale (Active Intervention)
    if (is_alarm) {
        // A. Tespit Logu (Once tespit ettim de)
        LOG_ALARM("FIDYE YAZILIMI SUPHESI [%s]! PID:%d UID:%d | File:%s | Score:%d",
                  risk_reason, s->pid, e->uid, e->filename, s->current_score);

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

        // B. Aktif Engelleme (Active Blocking) - Guvenli Filtreli
        if (config.active_blocking) {
            kill_process(s, e, risk_reason);
        }

        // C. Skor Sifirlama
        s->current_score = 0;
        s->write_burst = 0;
        s->rename_burst = 0;
        s->last_decay_time = time(NULL);
    }
}