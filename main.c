/* main.c - v0.7.0 (Graceful Exit & Fixed Summary) */
#include <stdio.h>
#include <stdlib.h>
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
#include "cli.h"

extern void cleanup_whitelist();

static int own_pid = 0;
static volatile bool exiting = false;
static char config_source[256] = "Varsayilan (Gomulu)";

static void handle_exit(int sig) { exiting = true; }

static void handle_crash(int sig) {
    fprintf(stderr, "KRITIK HATA: Program coktu! Sinyal: %d\n", sig);
    finalize_logger();
    exit(1);
}

static int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    if (!config.verbose_mode && (level == LIBBPF_DEBUG || level == LIBBPF_INFO)) return 0;
    return vfprintf(stderr, format, args);
}

int handle_event(void *ctx, void *data, size_t size) {
    if (!data) return 0;
    const struct event *e = data;

    // Kendimizi filtrele (Sonsuz döngü koruması)
    if ((int)e->pid == own_pid) return 0;

    // Süreç çıkış olayı
    if (e->type == EVENT_EXIT) {
        remove_process(e->pid);
        return 0;
    }

    // Durum takibi ve Beyaz liste kontrolü
    struct process_stats *s = get_process_stats(e->pid, e->comm);
    if (!s) return 0;

    if (is_whitelisted(s->comm)) return 0;

    // Analiz Motoru
    analyze_event(s, e);

    return 0;
}

int main(int argc, char **argv) {
    struct hello_kern* skel;
    struct ring_buffer *rb = NULL;
    int err;

    own_pid = getpid();

    // --- 1. HAZIRLIK ---
    init_config_defaults();

    // --- 2. CLI ARGÜMAN KONTROLÜ (ÖNCELİKLİ - GRACEFUL EXIT FIX) ---
    // Eğer --help veya --version çağrıldıysa, parse_arguments 1 döner.
    // Bu durumda dosya işlemleri yapmadan, eBPF yüklemeden temizce çıkarız.
    // Bu sayede 'htop' üzerinde zombi süreçler kalmaz.
    if (parse_arguments(argc, argv) == 1) {
        return 0;
    }

    // --- 3. KONFİGÜRASYON YÜKLEME ---
    // Eğer CLI ile özel bir config (-c) verilmişse onu yükle
    if (strlen(config.config_path) > 0) {
        if (access(config.config_path, F_OK) == 0) {
            load_config_file(config.config_path);
            snprintf(config_source, sizeof(config_source), "%s", config.config_path);
        } else {
            fprintf(stderr, "HATA: Belirtilen config dosyasi bulunamadi: %s\n", config.config_path);
            return 1;
        }
    }
    // Özel config yoksa varsayılan yerlere bak
    else {
        if (access("ransom.conf", F_OK) == 0) {
            load_config_file("ransom.conf");
            snprintf(config_source, sizeof(config_source), "./ransom.conf");
        }
        else if (access("/etc/ransom-bpf/ransom.conf", F_OK) == 0) {
            load_config_file("/etc/ransom-bpf/ransom.conf");
            snprintf(config_source, sizeof(config_source), "/etc/ransom-bpf/ransom.conf");
        }
    }

    // --- 4. SISTEM BASLATMA ---
    // Loglama ve Whitelist, config yüklendikten sonra başlatılır
    init_logger();
    init_whitelist(config.whitelist_str);
    libbpf_set_print(print_libbpf_log);

    // Başlangıç Logunu Bas
    LOG_INFO("Baslatiliyor... (Config Kaynagi: %s)", config_source);

    // [DÜZELTME] Özet tabloyu ARTIK HER ZAMAN GÖSTERİYORUZ (if bloğu kaldırıldı)
    print_startup_summary();

    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);
    signal(SIGSEGV, handle_crash);
    signal(SIGABRT, handle_crash);

    // --- 5. eBPF Yükleme ---
    skel = hello_kern__open();
    if (!skel) { LOG_ERR("eBPF iskeleti acilamadi."); return 1; }

    err = hello_kern__load(skel);
    if (err) { LOG_ERR("eBPF programi yuklenemedi."); goto cleanup; }

    err = hello_kern__attach(skel);
    if (err) { LOG_ERR("eBPF programi baglanamadi."); goto cleanup; }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) { LOG_ERR("Ring buffer olusturulamadi."); goto cleanup; }

    LOG_INFO("Sistem izleniyor... (Cikis icin Ctrl+C)");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

    cleanup:
    LOG_INFO("Kapatiliyor...");
    cleanup_whitelist();
    cleanup_all_processes();
    ring_buffer__free(rb);
    hello_kern__destroy(skel);
    finalize_logger();

    return -err;
}