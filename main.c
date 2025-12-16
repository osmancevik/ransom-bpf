/* main.c - v0.6.4 (Truly Silent CLI) */
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
    // Crash anında logger başlatılmamış olabilir, kontrolsüz yazdırmayalım.
    // Ancak systemd loglarına düşmesi için stderr'e yazmak güvenlidir.
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

    // --- 1. KONFIGURASYON (Sessiz) ---
    // Henüz Logger başlatmıyoruz! --version derse log dosyası oluşmasın/kirlenmesin.

    init_config_defaults();

    // Dosyayı sessizce yükle
    if (access("ransom.conf", F_OK) == 0) {
        load_config_file("ransom.conf");
        snprintf(config_source, sizeof(config_source), "./ransom.conf");
    }
    else if (access("/etc/ransom-bpf/ransom.conf", F_OK) == 0) {
        load_config_file("/etc/ransom-bpf/ransom.conf");
        snprintf(config_source, sizeof(config_source), "/etc/ransom-bpf/ransom.conf");
    }

    // CLI Argümanlarını işle
    // EĞER --version veya --help ise, fonksiyon burada exit(0) çağırır.
    // Dolayısıyla aşağıya hiç inmez ve log basmaz.
    parse_arguments(argc, argv);

    // --- 2. SISTEM BASLATMA (Gürültülü Mod) ---
    // Buraya geldiysek gerçek bir çalıştırma isteğidir (daemon veya izleme modu).

    init_logger(); // Log dosyasını şimdi aç
    init_whitelist(config.whitelist_str);
    libbpf_set_print(print_libbpf_log);

    // Başlangıç Logunu Bas
    LOG_INFO("Baslatiliyor... (Config Kaynagi: %s)", config_source);

    // Özet tabloyu göster (Sadece manuel başlatıldıysa mantıklı olabilir ama logda da dursun)
    if (config.verbose_mode) {
        print_startup_summary();
    }

    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);
    signal(SIGSEGV, handle_crash);
    signal(SIGABRT, handle_crash);

    // --- 3. eBPF Yükleme ---
    skel = hello_kern__open();
    if (!skel) { LOG_ERR("eBPF iskeleti acilamadi."); return 1; }

    err = hello_kern__load(skel);
    if (err) { LOG_ERR("eBPF programi yuklenemedi."); goto cleanup; }

    err = hello_kern__attach(skel);
    if (err) { LOG_ERR("eBPF programi baglanamadi."); goto cleanup; }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) { LOG_ERR("Ring buffer olusturulamadi."); goto cleanup; }

    LOG_INFO("Sistem izleniyor...");

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