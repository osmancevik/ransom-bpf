#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>


#include "../detector.h"
#include "../config.h"
#include "../logger.h"
#include "../common.h"
#include "../state_manager.h" 

// --- MOCK (SAHTE) ALTYAPI ---

// 1. Config: Global config değişkenini test için manuel tanımlıyoruz
struct app_config config;

// 2. Logger Durumu: Test sırasında logları takip etmek için değişkenler
int last_log_level = -1;
char last_log_msg[256];
int alarm_triggered = 0;

// 3. Mock Logger Fonksiyonu: Ekrana basmak yerine değişkenleri günceller
void log_message(enum log_level level, const char *format, ...) {
    last_log_level = level;
    if (level == LEVEL_ALARM) {
        alarm_triggered = 1;
    }
}

// --- YARDIMCI FONKSİYONLAR ---

// Her testten önce ortamı sıfırlar
void setup() {
    alarm_triggered = 0;
    last_log_level = -1;
    memset(last_log_msg, 0, sizeof(last_log_msg));

    // Varsayılan test ayarları
    config.window_sec = 5;       // 5 saniyelik pencere
    config.write_threshold = 10; // 10 dosya limiti
    config.rename_threshold = 5; // 5 isim değiştirme limiti
}

// Renkli çıktı için basit makrolar (Terminalde şık görünür)
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

    // Kontrol: Alarm çaldı mı? Burst sayacı sıfırlandı mı?
    if (alarm_triggered == 1 && p.write_burst == 0) {
        PASS();
    } else {
        FAIL();
        printf("   -> Beklenen: Alarm tetiklenmeliydi.\n");
        exit(1); // Test başarısızsa durdur
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
        printf("   -> Hata: Alarm caldi veya sayac yanlis. (Burst: %d)\n", p.write_burst);
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
    // Böylece 5 saniyelik pencere dolmuş oluyor.
    p.window_start_time = time(NULL) - 10; 

    struct event e;
    e.type = EVENT_WRITE;

    // Yeni bir olay geldiğinde, süre dolduğu için eski sayaç (9) silinmeli
    // ve sayaç 1'den başlamalıdır. Alarm çalmamalıdır.
    analyze_event(&p, &e);

    if (alarm_triggered == 0 && p.write_burst == 1) {
        PASS();
    } else {
        FAIL();
        printf("   -> Hata: Zaman penceresi sifirlanmadi. (Burst: %d)\n", p.write_burst);
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

    // Gelecekte H2 (İmza) testleri buraya eklenecek:
    // test_signature_detection();

    printf("==========================================\n");
    printf("   TUM TESTLER BASARIYLA TAMAMLANDI.      \n");
    printf("==========================================\n");
    
    return 0;
}