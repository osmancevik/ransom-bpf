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

// --- MOCK (SAHTE) ALTYAPI ---

// 1. Config: Global config değişkenini test için manuel tanımlıyoruz
// config.c baglanmadigi icin bu degiskeni bizim yaratmamiz sart.
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

    // DUZELTME: init_config_defaults() cagrisi KALDIRILDI.
    // Cunku config.c bagli degil. Degerleri manuel atiyoruz:

    memset(&config, 0, sizeof(struct app_config)); // Temizle

    // Teste Ozel Ayarlar
    config.window_sec = 5;
    config.write_threshold = 10;
    config.rename_threshold = 5;
    config.verbose_mode = 0;

    // Testte log dosyasina yazilmasini istemiyoruz
    strcpy(config.log_file, "");
}

// Renkli çıktı için basit makrolar
#define PASS() printf("\033[0;32m[PASS]\033[0m\n")
#define FAIL() printf("\033[0;31m[FAIL]\033[0m\n")

// --- TEST SENARYOLARI ---

void test_write_burst_detection() {
    printf("Test 1: Write Burst (Fidye Yazilimi Yazma Tespiti)... ");
    setup();

    // Süreç Hazırlığı
    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 1001;
    strcpy(p.comm, "ransom.exe");
    p.window_start_time = time(NULL);

    // Olay Hazırlığı
    struct event e;
    e.type = EVENT_WRITE;
    e.pid = 1001;

    // Eşik 10 iken, 11 tane olay gönderiyoruz
    for (int i = 0; i < 11; i++) {
        analyze_event(&p, &e);
    }

    // Kontrol
    if (alarm_triggered == 1 && p.write_burst == 0) {
        PASS();
    } else {
        FAIL();
        printf("   -> Beklenen: Alarm tetiklenmeliydi. (Triggered: %d, Burst: %lu)\n", alarm_triggered, p.write_burst);
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

    // Eşik 10 iken, sadece 5 olay gönderiyoruz
    for (int i = 0; i < 5; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 0 && p.write_burst == 5) {
        PASS();
    } else {
        FAIL();
        printf("   -> Hata: Alarm caldi veya sayac yanlis. (Burst: %lu)\n", p.write_burst);
        exit(1);
    }
}

void test_window_reset_logic() {
    printf("Test 3: Zaman Penceresi Sifirlama (Window Reset)... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 3003;
    p.write_burst = 9; // Limite çok yakın (Limit: 10)

    // HİLE: Sürecin başlangıç zamanını 10 saniye geriye alıyoruz
    p.window_start_time = time(NULL) - 10;

    struct event e;
    e.type = EVENT_WRITE;

    // Yeni bir olay geldiğinde, süre dolduğu için eski sayaç silinmeli
    analyze_event(&p, &e);

    if (alarm_triggered == 0 && p.write_burst == 1) {
        PASS();
    } else {
        FAIL();
        printf("   -> Hata: Zaman penceresi sifirlanmadi. (Burst: %lu)\n", p.write_burst);
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

    // Rename limiti 5. Biz 6 tane gönderiyoruz.
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

// --- MAIN RUNNER ---

int main() {
    printf("==========================================\n");
    printf("   eBPF RANSOMWARE DETECTION - UNIT TESTS \n");
    printf("==========================================\n");

    test_write_burst_detection();
    test_normal_user_behavior();
    test_window_reset_logic();
    test_rename_burst_detection();

    printf("==========================================\n");
    printf("   TUM TESTLER BASARIYLA TAMAMLANDI.      \n");
    printf("==========================================\n");
    
    return 0;
}