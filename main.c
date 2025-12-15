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
#include "whitelist.h"
#include "cli.h"  // <--- YENİ: CLI Header

static int own_pid = 0;
static volatile bool exiting = false;

static void handle_exit(int sig) { exiting = true; }

static int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    // Verbose mod kapalıysa libbpf detaylarını gizle
    if (!config.verbose_mode && (level == LIBBPF_DEBUG || level == LIBBPF_INFO)) return 0;
    return vfprintf(stderr, format, args);
}

int handle_event(void *ctx, void *data, size_t size) {
    // ... (Bu kısım aynı kalacak, değişiklik yok) ...
    // KOD TEKRARINI ÖNLEMEK İÇİN BURAYI KISALTTIM
    // handle_event içeriği mevcut v0.5.0 kodundaki ile aynı.

    const struct event *e = data;
    if ((int)e->pid == own_pid) return 0;

    if (e->type == EVENT_EXIT) {
        remove_process(e->pid);
        return 0;
    }

    struct process_stats *s = get_or_create_process(e->pid, e->comm);
    if (!s) return 0;

    if (is_whitelisted(s->comm)) return 0;

    analyze_event(s, e);
    return 0;
}

int main(int argc, char **argv) {
    struct hello_kern* skel;
    struct ring_buffer *rb = NULL;
    int err;

    own_pid = getpid();

    // --- 1. Konfigürasyon ve CLI Yükleme ---

    // A. Önce güvenli varsayılanları yükle
    init_config_defaults();

    // B. Varsayılan config dosyasını dene (Varsa yükler, yoksa sessizce geçer)
    //    Not: Kullanıcı -c ile başka dosya verirse parse_arguments bunu ezecektir.
    FILE *f = fopen("ransom.conf", "r");
    if (f) {
        fclose(f);
        load_config_file("ransom.conf");
    }

    // C. CLI Argümanlarını işle (Config yükleme ve Override işlemleri burada)
    parse_arguments(argc, argv);

    // --- 2. Başlatma ---

    init_logger();
    init_whitelist(config.whitelist_str);
    libbpf_set_print(print_libbpf_log);

    // D. Kullanıcıya Özet Tabloyu Göster
    print_startup_summary();

    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    // --- 3. eBPF Yükleme (Skeleton) ---
    // (Burası aynı kalıyor)
    skel = hello_kern__open();
    if (!skel) {
        LOG_ERR("eBPF iskeleti acilamadi.");
        return 1;
    }

    err = hello_kern__load(skel);
    if (err) {
        LOG_ERR("eBPF programi yuklenemedi.");
        goto cleanup;
    }

    err = hello_kern__attach(skel);
    if (err) {
        LOG_ERR("eBPF programi baglanamadi.");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        LOG_ERR("Ring buffer olusturulamadi.");
        goto cleanup;
    }

    LOG_INFO("Sistem izleniyor...");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

    cleanup:
    LOG_INFO("Kapatiliyor...");
    cleanup_all_processes();
    ring_buffer__free(rb);
    hello_kern__destroy(skel);
    finalize_logger();

    return -err;
}