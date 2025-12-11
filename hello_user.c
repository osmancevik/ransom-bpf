// hello_user.c: Eşik Bazlı Tespit (H1) Eklenmiş Versiyon

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>       // <--- EKLENDİ: Zaman fonksiyonları için
#include <bpf/libbpf.h>
#include <errno.h>

#include "hello_kern.skel.h"
#include "common.h"
#include "uthash.h"

// --- AYARLAR VE EŞİK DEĞERLERİ (THRESHOLDS) ---
// Rapor-1'deki "5 saniyede 10 dosya" örneğine benzer ayarlar.
// Test etmek kolay olsun diye şimdilik düşük tutuyoruz.
#define RATE_WINDOW_SEC 2       // Hız ölçüm penceresi (saniye)
#define THRESHOLD_WRITE 15      // Pencere içindeki maksimum yazma sayısı
#define THRESHOLD_RENAME 5      // Pencere içindeki maksimum yeniden adlandırma sayısı

// --- DURUM YÖNETİMİ VERİ YAPILARI ---

struct process_stats {
    int pid;                   // KEY
    char comm[TASK_COMM_LEN];  // Process Name

    // --- KÜMÜLATİF İSTATİSTİKLER (Raporlama için) ---
    unsigned long total_exec_count;
    unsigned long total_write_count;

    // --- HIZ ANALİZİ İÇİN (Eşik Bazlı Kural - H1) ---
    time_t window_start_time;  // Mevcut pencerenin başladığı zaman
    unsigned int write_burst;  // Pencere içindeki yazma sayısı
    unsigned int rename_burst; // Pencere içindeki rename sayısı

    UT_hash_handle hh;         // uthash handle
};

struct process_stats *processes = NULL; // Hash table head

// Ajanın kendi PID'si
static int own_pid = 0;
static volatile bool exiting = false;

static void handle_exit(int sig) { exiting = true; }

int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

/*
 * check_thresholds: Belirli bir süreç için eşik aşımı olup olmadığını kontrol eder.
 */
void check_thresholds(struct process_stats *s) {
    time_t now = time(NULL);

    // 1. Pencere Kontrolü: Süre dolduysa pencereyi sıfırla
    if (difftime(now, s->window_start_time) >= RATE_WINDOW_SEC) {
        // Eski pencereyi kapat, yenisini aç
        s->window_start_time = now;
        s->write_burst = 0;
        s->rename_burst = 0;
        // Not: Burası debug için açılabilir ama çok log üretir
        // printf("DEBUG: PID %d icin pencere sifirlandi.\n", s->pid);
    }
}

int handle_event(void *ctx, void *data, size_t size) {
    const struct event *e = data;
    struct process_stats *s;

    if (size < sizeof(*e)) return 1;

    // --- 1. FİLTRELEME ---
    if ((int)e->pid == own_pid) return 0;

    // Gürültü filtreleri
    if (strcmp(e->comm, "sshd-session") == 0 ||
        strcmp(e->comm, "sudo") == 0 ||
        strcmp(e->comm, "sshd") == 0) {
        return 0;
    }

    // --- 2. DURUM YÖNETİMİ (BUL VEYA OLUŞTUR) ---
    int key_pid = (int)e->pid;
    HASH_FIND_INT(processes, &key_pid, s);

    if (!s) {
        s = (struct process_stats *)malloc(sizeof(struct process_stats));
        if (!s) return 0; // Out of memory check
        s->pid = key_pid;
        strncpy(s->comm, e->comm, TASK_COMM_LEN);
        s->comm[TASK_COMM_LEN - 1] = '\0';

        // İlk değer atamaları
        s->total_exec_count = 0;
        s->total_write_count = 0;
        s->window_start_time = time(NULL);
        s->write_burst = 0;
        s->rename_burst = 0;

        HASH_ADD_INT(processes, pid, s);
    }

    // Her olaydan önce zaman penceresini kontrol et
    check_thresholds(s);

    // --- 3. OLAY İŞLEME VE ALARM MANTIĞI ---
    switch (e->type) {
        case EVENT_EXEC:
            s->total_exec_count++;
            printf("[EXEC]   PID: %-6d | COMM: %-16s | FILE: %s\n",
                   s->pid, s->comm, e->filename);
            break;

        case EVENT_WRITE:
            s->total_write_count++; // Toplamı artır
            s->write_burst++;       // Pencereyi artır

            // --- H1 KURALI: HIZLI YAZMA TESPİTİ ---
            if (s->write_burst > THRESHOLD_WRITE) {
                printf("\033[1;31m"); // KIRMIZI RENK BAŞLA
                printf("[ALARM]  FIDYE YAZILIMI SUPHESI (WRITE BURST)!\n");
                printf("         PID: %d (%s) -> %d saniyede %u dosya yazdi!\n",
                        s->pid, s->comm, RATE_WINDOW_SEC, s->write_burst);
                printf("\033[0m");    // RENK SIFIRLA

                // Alarmı spamlamamak için pencereyi sıfırlayabiliriz veya
                // süreci kill listesine alabiliriz (Gelecek hafta görevi)
                s->write_burst = 0; // Geçici çözüm: Sayacı sıfırla ki logu boğmasın
            } else {
                // Sadece bilgi amaçlı (debug için opsiyonel)
                 printf("[WRITE]  PID: %-6d | Rate: %u/%ds | Total: %lu\n",
                       s->pid, s->comm, s->write_burst, RATE_WINDOW_SEC, s->total_write_count);
            }
            break;

        case EVENT_RENAME:
            s->rename_burst++;

            // --- H1 KURALI: HIZLI UZANTI DEĞİŞTİRME ---
            if (s->rename_burst > THRESHOLD_RENAME) {
                printf("\033[1;31m"); // KIRMIZI RENK
                printf("[ALARM]  FIDYE YAZILIMI SUPHESI (RENAME BURST)!\n");
                printf("         PID: %d (%s) -> %d saniyede %u dosya adi degistirdi!\n",
                        s->pid, s->comm, RATE_WINDOW_SEC, s->rename_burst);
                printf("\033[0m"); // RENK SIFIRLA
                s->rename_burst = 0;
            } else {
                 printf("[RENAME] PID: %-6d | Rate: %u/%ds | File: %s\n",
                       s->pid, s->comm, s->rename_burst, RATE_WINDOW_SEC, e->filename);
            }
            break;

        case EVENT_OPEN:
            // Open olayları çok sıktır, analiz etmiyoruz ama debug için görebiliriz
            break;

        default:
            break;
    }

    return 0;
}

int main(int argc, char **argv) {
    // ... Main fonksiyonu önceki kodun aynısı ...
    // ... Sadece struct başlatmalarını yukarıdaki koda uydurduğumuzdan emin ol yeter ...

    struct hello_kern* skel;
    struct ring_buffer *rb_manager = NULL;
    int err;

    own_pid = getpid();
    libbpf_set_print(print_libbpf_log);
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    skel = hello_kern__open();
    if (!skel) return 1;

    err = hello_kern__load(skel);
    if (err) goto cleanup;

    err = hello_kern__attach(skel);
    if (err) goto cleanup;

    rb_manager = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb_manager) {
        err = -1;
        goto cleanup;
    }

    printf("Hafizali ve Esik Kontrollu eBPF Ajan (PID: %d) baslatildi.\n", own_pid);
    printf("Kurallar: %d saniyede >%d WRITE veya >%d RENAME ALARM uretir.\n",
            RATE_WINDOW_SEC, THRESHOLD_WRITE, THRESHOLD_RENAME);
    printf("-------------------------------------------------------\n");

    while (!exiting) {
        err = ring_buffer__poll(rb_manager, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

cleanup:
    // ... Cleanup kodu aynı ...
    struct process_stats *current_user, *tmp;
    HASH_ITER(hh, processes, current_user, tmp) {
        HASH_DEL(processes, current_user);
        free(current_user);
    }
    ring_buffer__free(rb_manager);
    hello_kern__destroy(skel);
    return -err;
}