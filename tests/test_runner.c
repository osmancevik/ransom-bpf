/* tests/test_runner.c - v0.9.1 (Multi-Channel Log Support) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdarg.h>

#include "../detector.h"
#include "../config.h"
#include "../logger.h"
#include "../common.h"
#include "../state_manager.h"

// Headerlarda guncellenmemis olma ihtimaline karsi manuel bildirimler
extern int is_honeypot_access(const char *filename);

#ifndef EVENT_UNLINK
#define EVENT_UNLINK 6
#endif

// --- MOCK (SAHTE) ALTYAPI ---

LogLevel last_log_level = -1;
char last_log_msg[256];
int alarm_triggered = 0;

// 1. Mock Standart Logger
void log_message(LogLevel level, const char *file, int line, const char *format, ...) {
    last_log_level = level;

    if (level == LOG_LEVEL_ALARM) {
        alarm_triggered = 1;
    }

    va_list args;
    va_start(args, format);
    vsnprintf(last_log_msg, sizeof(last_log_msg), format, args);
    va_end(args);
}

// 2. [DUZELTME] Mock Audit Log (Ham Veri - 6 Parametre)
// logger.h ile uyumlu hale getirildi.
void log_audit_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename)
{
    // Test sirasinda JSON uretmiyoruz, bos govde yeterli.
}

// 3. [YENI] Mock Alert Log (Alarmlar - 8 Parametre)
// detector.c artik bunu cagirdigi icin Mock'lanmasi sart.
void log_alert_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename,
                    const char *risk_reason,
                    int score)
{
    // Alarm durumunu log_message (LOG_ALARM) zaten yakaliyor.
    // Burasi sadece link hatasini onlemek icin var.
}

// 4. Mock Libbpf
int logger_libbpf_print(enum libbpf_print_level level, const char *format, va_list args) {
    return 0;
}


// --- YARDIMCI FONKSIYONLAR ---

void setup() {
    alarm_triggered = 0;
    last_log_level = -1;
    memset(last_log_msg, 0, sizeof(last_log_msg));

    // Config'i sifirla
    memset(&config, 0, sizeof(struct app_config));

    // Faz 2 Puanlama Ayarlari
    config.window_sec = 5;
    config.risk_threshold = 100;

    config.score_write = 10;
    config.score_rename = 20;
    config.score_unlink = 50;
    config.score_honeypot = 1000;
    config.score_ext_penalty = 50;

    config.write_threshold = 10;
    config.rename_threshold = 5;

    config.verbose_mode = 0;

    // [DUZELTME] Eski 'log_file' yerine yeni alanlar
    strcpy(config.service_log, "");
    strcpy(config.alert_log, "");
    strcpy(config.audit_log, "");

    strcpy(config.honeypot_file, "secret_passwords.txt");
}

#define PASS() printf("\033[0;32m[PASS]\033[0m\n")
#define FAIL() printf("\033[0;31m[FAIL]\033[0m\n")

// --- TEST SENARYOLARI (Aynen Korunuyor) ---

void test_write_burst_detection() {
    printf("Test 1: Write Burst (Risk Puani ile Tespiti)... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 1001;
    strcpy(p.comm, "ransom.exe");
    p.window_start_time = time(NULL);

    struct event e;
    e.type = EVENT_WRITE;
    e.pid = 1001;
    e.uid = 1000; e.ppid = 900; // Mock veri

    for (int i = 0; i < 11; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 1) PASS();
    else {
        FAIL();
        printf("   -> Beklenen: Alarm tetiklenmeliydi. (Score: %d)\n", p.current_score);
        exit(1);
    }
}

void test_normal_user_behavior() {
    printf("Test 2: Normal Kullanici (False Positive Kontrolu)... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 2002;
    p.window_start_time = time(NULL);

    struct event e;
    e.type = EVENT_WRITE;
    e.uid = 1000;

    for (int i = 0; i < 5; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 0) PASS();
    else {
        FAIL();
        printf("   -> Hata: Alarm caldi. (Score: %d)\n", p.current_score);
        exit(1);
    }
}

void test_window_reset_logic() {
    printf("Test 3: Zaman Penceresi Sifirlama (Score Reset)... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 3003;
    p.current_score = 90;
    p.window_start_time = time(NULL) - 10;

    struct event e;
    e.type = EVENT_WRITE;
    e.uid = 1000;

    analyze_event(&p, &e);

    if (alarm_triggered == 0 && p.current_score == 10) PASS();
    else {
        FAIL();
        printf("   -> Hata: Zaman penceresi skoru sifirlamadi. (Score: %d)\n", p.current_score);
        exit(1);
    }
}

void test_rename_burst_detection() {
    printf("Test 4: Rename Burst (Toplu Isim Degistirme)... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 4004;
    p.window_start_time = time(NULL);

    struct event e;
    e.type = EVENT_RENAME;
    e.uid = 1000;
    strcpy(e.filename, "veri.txt.locked");

    for (int i = 0; i < 6; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 1) PASS();
    else {
        FAIL();
        printf("   -> Hata: Rename limiti asilmasina ragmen alarm calmad.\n");
        exit(1);
    }
}

void test_honeypot_access() {
    printf("Test 5: Honeypot (Tuzak Dosya) Tespiti... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 5005;
    strcpy(p.comm, "hacker");

    struct event e;
    e.type = EVENT_OPEN;
    e.uid = 1000;
    strcpy(e.filename, "/var/www/secret_passwords.txt");

    analyze_event(&p, &e);

    if (alarm_triggered == 1) PASS();
    else {
        FAIL();
        printf("   -> Hata: Honeypot dosyasina erisim alarm uretmedi!\n");
        exit(1);
    }
}

void test_deletion_event() {
    printf("Test 6: Dosya Silme (Deletion) Puani... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 6006;

    struct event e;
    e.type = EVENT_UNLINK;
    e.uid = 1000;
    strcpy(e.filename, "onemli.pdf");

    analyze_event(&p, &e);
    assert(alarm_triggered == 0);

    analyze_event(&p, &e);

    if (alarm_triggered == 1) PASS();
    else {
        FAIL();
        printf("   -> Hata: 2. dosya silme isleminde alarm calmad.\n");
        exit(1);
    }
}

int main() {
    printf("==========================================\n");
    printf("   RANSOM-BPF: UNIT TESTS (PHASE 2)       \n");
    printf("==========================================\n");

    test_write_burst_detection();
    test_normal_user_behavior();
    test_window_reset_logic();
    test_rename_burst_detection();
    test_honeypot_access();
    test_deletion_event();

    printf("==========================================\n");
    printf("   TUM TESTLER BASARIYLA TAMAMLANDI.      \n");
    printf("==========================================\n");
    
    return 0;
}