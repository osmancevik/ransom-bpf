#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hello_kern.skel.h"
#include "common.h"
#include "logger.h"
#include "state_manager.h"
#include "detector.h"
#include "config.h"
#include "whitelist.h" // YENİ: Whitelist modülü eklendi

static int own_pid = 0;
static volatile bool exiting = false;

static void handle_exit(int sig) { exiting = true; }

static int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    // libbpf loglarını sadece hata varsa basalım
    if (level == LIBBPF_WARN || level == LIBBPF_INFO) return 0;
    return vfprintf(stderr, format, args);
}

// Ring Buffer'dan gelen olayların işlendiği callback fonksiyonu
int handle_event(void *ctx, void *data, size_t size) {
    const struct event *e = data;

    // 1. Kendi aktivitelerimizi filtrele (Sonsuz döngüyü önler)
    if ((int)e->pid == own_pid) return 0;

    // 2. Özel Durum: EXIT (Süreç Sonlanması)
    // Süreç bittiği için temizlik yapıyoruz, whitelist kontrolüne gerek yok.
    if (e->type == EVENT_EXIT) {
        remove_process(e->pid);
        return 0;
    }

    // 3. İstatistikleri Al veya Oluştur
    // Not: Normalde whitelist kontrolünü bu adımdan önce yaparak bellek tasarrufu
    // sağlanabilir, ancak "Rapor 7" mimarisine sadık kalarak state yönetimini koruyoruz.
    struct process_stats *s = get_or_create_process(e->pid, e->comm);
    if (!s) {
        // Bellek hatası veya beklenmedik durum
        return 0;
    }

    // --- YENİ: BEYAZ LİSTE (WHITELIST) KONTROLÜ ---
    // Eğer süreç güvenilir listedeyse, analiz motoruna göndermeden döngüden çık.
    // Bu sayede "False Positive" (Hatalı Alarm) önlenir.
    if (is_whitelisted(s->comm)) {
        // İsteğe bağlı: Whitelist'e takılanları debug modunda loglayabiliriz
        // LOG_DEBUG("Whitelist surec atlandi: %s", s->comm);
        return 0;
    }

    // 4. Analiz Motorunu Çalıştır
    // Süreç beyaz listede değilse, fidye yazılımı davranışları için analiz et.
    analyze_event(s, e);

    return 0;
}

int main(int argc, char **argv) {
    struct hello_kern* skel;
    struct ring_buffer *rb = NULL;
    int err;

    own_pid = getpid();

    // 1. Konfigürasyonu Yükle
    // Varsayılan olarak "ransom.conf" dosyasını arar.
    load_config("ransom.conf");

    // 2. Log Sistemini Başlat
    init_logger();

    // 3. Whitelist'i Başlat (YENİ)
    // Config dosyasından okunan "apt,git,make" gibi listeyi parçalar ve hazırlar.
    init_whitelist(config.whitelist_str);

    libbpf_set_print(print_libbpf_log);
    LOG_INFO("eBPF Ajan Baslatildi (PID: %d).", own_pid);

    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    // 4. eBPF İskeletini Aç (Open)
    skel = hello_kern__open();
    if (!skel) {
        LOG_ERR("eBPF iskeleti acilamadi.");
        return 1;
    }

    // 5. eBPF Programını Yükle (Load)
    err = hello_kern__load(skel);
    if (err) {
        LOG_ERR("eBPF programi yuklenemedi.");
        goto cleanup;
    }

    // 6. Kancaları Bağla (Attach)
    err = hello_kern__attach(skel);
    if (err) {
        LOG_ERR("eBPF programi baglanamadi.");
        goto cleanup;
    }

    // 7. Ring Buffer Kurulumu
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        LOG_ERR("Ring buffer olusturulamadi.");
        goto cleanup;
    }

    LOG_INFO("Izleme basladi. Cikis icin Ctrl+C kullanin.");

    // Mevcut Whitelist durumunu bilgi olarak bas
    LOG_INFO("Aktif Whitelist: [%s]", config.whitelist_str);

    // Ana Döngü
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

    // Temizlik İşlemleri
    cleanup:
    cleanup_all_processes(); // Bellekte kalan süreç istatistiklerini temizle
    ring_buffer__free(rb);
    hello_kern__destroy(skel);
    finalize_logger();

    return -err;
}