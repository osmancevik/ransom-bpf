/* tests/test_runner.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdarg.h> // va_list icin gerekli

#include "../detector.h"
#include "../config.h"
#include "../logger.h" // LogLevel ve prototipler buradan gelir
#include "../common.h"
#include "../state_manager.h"

// Eksik olan veya detector.c'de tanımlanacak fonksiyon prototiplerini bildiriyoruz
// (detector.h güncellenmemişse derleme hatası almamak için)
extern int is_honeypot_access(const char *filename);

// Yeni eklenecek EVENT türü (common.h güncellenmediyse manuel tanımla)
#ifndef EVENT_DELETE
#define EVENT_DELETE 6
#endif

// --- MOCK (SAHTE) ALTYAPI ---

// 1. Config: Global config değişkenini test için manuel tanımlıyoruz
struct app_config config;

// 2. Logger Durumu: Test sırasında logları takip etmek için değişkenler
LogLevel last_log_level = -1;
char last_log_msg[256];
int alarm_triggered = 0;

// 3. Mock Logger Fonksiyonu
void log_message(LogLevel level, const char *file, int line, const char *format, ...) {
    last_log_level = level;

    if (level == LOG_LEVEL_ALARM) {
        alarm_triggered = 1;
    }

    // Mesaji sakla
    va_list args;
    va_start(args, format);
    vsnprintf(last_log_msg, sizeof(last_log_msg), format, args);
    va_end(args);
}

// --- YARDIMCI FONKSİYONLAR ---

// Her testten önce ortamı sıfırlar
void setup() {
    alarm_triggered = 0;
    last_log_level = -1;
    memset(last_log_msg, 0, sizeof(last_log_msg));

    memset(&config, 0, sizeof(struct app_config)); // Temizle

    // Teste Ozel Ayarlar
    config.window_sec = 5;
    config.write_threshold = 10;
    config.rename_threshold = 5;
    config.verbose_mode = 0;

    // Varsayılan Honeypot Dosyası (detector.c içinde global olabilir ama buraya not düştük)
    // Not: detector.c'deki HONEYPOT_FILENAME değişkenini değiştirmek için
    // extern char HONEYPOT_FILENAME[]; yapmak gerekebilir ama şimdilik varsayılanı test edeceğiz.

    strcpy(config.log_file, "");
}

#define PASS() printf("\033[0;32m[PASS]\033[0m\n")
#define FAIL() printf("\033[0;31m[FAIL]\033[0m\n")

// --- TEST SENARYOLARI ---

void test_write_burst_detection() {
    printf("Test 1: Write Burst (Fidye Yazilimi Yazma Tespiti)... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 1001;
    strcpy(p.comm, "ransom.exe");
    p.window_start_time = time(NULL);

    struct event e;
    e.type = EVENT_WRITE;
    e.pid = 1001;

    for (int i = 0; i < 11; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 1 && p.write_burst == 0) {
        PASS();
    } else {
        FAIL();
        printf("   -> Beklenen: Alarm tetiklenmeliydi. (Triggered: %d)\n", alarm_triggered);
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

    for (int i = 0; i < 5; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 0 && p.write_burst == 5) {
        PASS();
    } else {
        FAIL();
        printf("   -> Hata: Alarm caldi veya sayac yanlis.\n");
        exit(1);
    }
}

void test_window_reset_logic() {
    printf("Test 3: Zaman Penceresi Sifirlama (Window Reset)... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 3003;
    p.write_burst = 9;
    p.window_start_time = time(NULL) - 10; // 10 saniye önce

    struct event e;
    e.type = EVENT_WRITE;

    analyze_event(&p, &e);

    if (alarm_triggered == 0 && p.write_burst == 1) {
        PASS();
    } else {
        FAIL();
        printf("   -> Hata: Zaman penceresi sifirlanmadi.\n");
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

// --- YENI TESTLER (GOREV 1.2 & 1.3) ---

void test_honeypot_access() {
    printf("Test 5: Honeypot (Tuzak Dosya) Tespiti... ");
    setup();

    // 1. is_honeypot_access mantık testi
    int res1 = is_honeypot_access("secret_passwords.txt");
    int res2 = is_honeypot_access("/home/user/secret_passwords.txt");
    int res3 = is_honeypot_access("odev.docx");

    assert(res1 == 1);
    assert(res2 == 1);
    assert(res3 == 0);

    // 2. Entegrasyon testi (analyze_event üzerinden)
    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 5005;
    strcpy(p.comm, "hacker");

    struct event e;
    e.type = EVENT_OPEN; // Veya READ
    strcpy(e.filename, "/var/www/secret_passwords.txt");

    analyze_event(&p, &e);

    // Honeypot erişimi ALARM (LOG_LEVEL_ALARM) üretmeli
    if (alarm_triggered == 1) {
        PASS();
    } else {
        FAIL();
        printf("   -> Hata: Honeypot dosyasina erisim alarm uretmedi!\n");
        exit(1);
    }
}

void test_deletion_event() {
    printf("Test 6: Dosya Silme (Deletion) Loglama... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 6006;
    strcpy(p.comm, "rm");

    struct event e;
    e.type = EVENT_DELETE; // Veya UNLINK
    strcpy(e.filename, "onemli_belge.pdf");

    analyze_event(&p, &e);

    // Silme işlemi şu an sadece INFO seviyesinde loglanıyor (Alarm değil)
    // Bu yüzden alarm_triggered == 0 olmalı ama last_log_msg içinde "silme" veya "DELETE" geçmeli

    if (alarm_triggered == 0 && last_log_level == LOG_LEVEL_INFO) {
        PASS();
    } else {
        FAIL();
        printf("   -> Hata: Silme islemi INFO logu uretmedi veya yanlislikla ALARM ureti.\n");
        printf("      Last Level: %d (Beklenen: %d)\n", last_log_level, LOG_LEVEL_INFO);
        exit(1);
    }
}

// --- MAIN RUNNER ---

int main() {
    printf("==========================================\n");
    printf("   eBPF RANSOMWARE DETECTION - UNIT TESTS \n");
    printf("==========================================\n");

    test_write_burst_detection();
    test_normal_user_behavior();
    test_window_reset_logic();
    test_rename_burst_detection();

    // Yeni eklenen testleri çalıştır
    test_honeypot_access();
    test_deletion_event();

    printf("==========================================\n");
    printf("   TUM TESTLER BASARIYLA TAMAMLANDI.      \n");
    printf("==========================================\n");
    
    return 0;
}