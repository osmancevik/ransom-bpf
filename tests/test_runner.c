/* tests/test_runner.c */
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

// detector.h güncellenmemişse diye manuel bildirim
extern int is_honeypot_access(const char *filename);

#ifndef EVENT_DELETE
#define EVENT_DELETE 6
#endif

// --- MOCK (SAHTE) ALTYAPI ---

// DÜZELTME 1: 'struct app_config config;' SILINDI.
// Artık config.c içindeki gerçek tanımı kullanıyoruz (extern).

// Logger Değişkenleri
LogLevel last_log_level = -1;
char last_log_msg[256];
int alarm_triggered = 0;

// Mock Logger Fonksiyonu
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

// --- YARDIMCI FONKSİYONLAR ---

void setup() {
    alarm_triggered = 0;
    last_log_level = -1;
    memset(last_log_msg, 0, sizeof(last_log_msg));

    // Config'i sıfırla
    memset(&config, 0, sizeof(struct app_config));

    // DÜZELTME 2: Faz 2 Puanlama Ayarları Eklendi
    // Testlerin başarılı geçmesi için bu değerler kritik.
    config.window_sec = 5;

    // Risk Threshold: 100 puan
    config.risk_threshold = 100;

    // Puanlar (Senaryoya göre ayarlandı)
    config.score_write = 10;      // 10 yazma = 100 puan (Alarm)
    config.score_rename = 20;     // 5 rename = 100 puan (Alarm)
    config.score_unlink = 50;     // 2 silme = 100 puan (Alarm)
    config.score_honeypot = 1000; // 1 honeypot = 1000 puan (Alarm)

    // Eski eşikler (Geri uyumluluk için)
    config.write_threshold = 10;
    config.rename_threshold = 5;

    config.verbose_mode = 0;
    strcpy(config.log_file, "");

    // Honeypot dosya adı
    strcpy(config.honeypot_file, "secret_passwords.txt");
}

#define PASS() printf("\033[0;32m[PASS]\033[0m\n")
#define FAIL() printf("\033[0;31m[FAIL]\033[0m\n")

// --- TEST SENARYOLARI ---

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

    // Config: score_write = 10, Threshold = 100.
    // 11 adet yazma olayı gönderiyoruz.
    // 10. yazmada (10*10=100) alarm çalmalı.
    for (int i = 0; i < 11; i++) {
        analyze_event(&p, &e);
    }

    // Yeni mantıkta alarm çalınca burst sıfırlanıyor (p.write_burst == 0 kontrolü bu yüzden geçerli)
    if (alarm_triggered == 1) {
        PASS();
    } else {
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

    // 5 yazma * 10 puan = 50 puan. Threshold(100) altında kalmalı.
    for (int i = 0; i < 5; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 0) {
        PASS();
    } else {
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
    p.current_score = 90; // Alarm sınırına yakın
    p.window_start_time = time(NULL) - 10; // 10 saniye önce (Süre dolmuş)

    struct event e;
    e.type = EVENT_WRITE; // +10 puan gelecek

    // analyze_event önce pencere kontrolü yapıp skoru 0'a çekecek.
    // Sonra +10 ekleyecek. Sonuç: 10 puan olmalı (Alarm yok).
    analyze_event(&p, &e);

    if (alarm_triggered == 0 && p.current_score == 10) {
        PASS();
    } else {
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
    strcpy(e.filename, "veri.txt.locked");

    // Config: score_rename = 20. Threshold = 100.
    // 6 * 20 = 120 Puan -> Alarm.
    for (int i = 0; i < 6; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 1) {
        PASS();
    } else {
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
    // Setup'da "secret_passwords.txt" tanımladık
    strcpy(e.filename, "/var/www/secret_passwords.txt");

    // Config: score_honeypot = 1000. Anında alarm.
    analyze_event(&p, &e);

    if (alarm_triggered == 1) {
        PASS();
    } else {
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
    e.type = EVENT_DELETE;
    strcpy(e.filename, "onemli.pdf");

    // Config: score_unlink = 50. Threshold = 100.
    // 1. Silme -> 50 puan (Alarm Yok)
    analyze_event(&p, &e);
    assert(alarm_triggered == 0);

    // 2. Silme -> 100 puan (Alarm Var)
    analyze_event(&p, &e);

    if (alarm_triggered == 1) {
        PASS();
    } else {
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