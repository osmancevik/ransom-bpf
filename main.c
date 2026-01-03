/* main.c - v0.7.5 (Self-Monitoring & Silent Startup) */
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

// Olay Isleyicisi (Callback)
int handle_event(void *ctx, void *data, size_t size) {
    if (!data) return 0;
    const struct event *e = data;

    // [KRITIK] Kendimizi filtrele (Sonsuz dongu ve Feedback Loop korumasi)
    // Ajanin kendi yazdigi loglari analiz etmesini engeller.
    if ((int)e->pid == own_pid) return 0;

    // Surec cikis olayi
    if (e->type == EVENT_EXIT) {
        remove_process(e->pid);
        return 0;
    }

    // Durum takibi ve Beyaz liste kontrolu
    struct process_stats *s = get_process_stats(e->pid, e->comm);
    if (!s) return 0;

    // Dinamik Whitelist kontrolu (O(1) Hash Tablosu)
    if (is_whitelisted(s->comm)) return 0;

    // Analiz Motoru
    analyze_event(s, e);

    return 0;
}

int main(int argc, char **argv) {
    struct hello_kern* skel;
    struct ring_buffer *rb = NULL;
    int err;

    own_pid = getpid(); // Ajanin PID'sini al

    // --- 1. HAZIRLIK ---
    init_config_defaults();

    // --- 2. CLI ARGUMAN KONTROLU (ONCELIKLI - GRACEFUL EXIT) ---
    // Eger --help veya --version cagrilmissa temizce cik.
    if (parse_arguments(argc, argv) == 1) {
        return 0;
    }

    // --- 3. KONFIGURASYON YUKLEME ---
    // Eger CLI ile ozel bir config (-c) verilmisse onu yukle
    if (strlen(config.config_path) > 0) {
        if (access(config.config_path, F_OK) == 0) {
            load_config_file(config.config_path);
            snprintf(config_source, sizeof(config_source), "%s", config.config_path);
        } else {
            fprintf(stderr, "HATA: Belirtilen config dosyasi bulunamadi: %s\n", config.config_path);
            return 1;
        }
    }
    // Ozel config yoksa varsayilan yerlere bak
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
    // Loglama ve Whitelist, config yuklendikten sonra baslatilir
    init_logger();
    init_whitelist(config.whitelist_str);

    // [YENI] Libbpf gurultusunu filtrele (Sessiz Baslatma)
    // logger.c icindeki gelismis fonksiyonu kullaniyoruz.
    libbpf_set_print(logger_libbpf_print);

    // Baslangic Logunu Bas
    LOG_INFO("Baslatiliyor... (Config Kaynagi: %s)", config_source);

    // Ozet tabloyu goster
    print_startup_summary();

    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);
    signal(SIGSEGV, handle_crash);
    signal(SIGABRT, handle_crash);

    // --- 5. eBPF Yukleme ---
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