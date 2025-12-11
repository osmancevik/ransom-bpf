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

static int own_pid = 0;
static volatile bool exiting = false;

static void handle_exit(int sig) { exiting = true; }

static int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    // libbpf loglarını sadece hata varsa basalım
    if (level == LIBBPF_WARN || level == LIBBPF_INFO) return 0;
    return vfprintf(stderr, format, args);
}

int handle_event(void *ctx, void *data, size_t size) {
    const struct event *e = data;

    // Filtreleme
    if ((int)e->pid == own_pid) return 0;

    // Gürültü filtreleme (Basit)
    if (strcmp(e->comm, "sshd") == 0 || strcmp(e->comm, "sudo") == 0) return 0;

    // Özel Durum: EXIT
    if (e->type == EVENT_EXIT) {
        // Eski yöntem (HASH_DEL) yerine modüler fonksiyonu kullanıyoruz:
        remove_process(e->pid);
        return 0;
    }

    // Normal Akış (EXEC, WRITE, RENAME)
    // Eski yöntem (HASH_FIND) yerine modüler fonksiyonu kullanıyoruz:
    struct process_stats *s = get_or_create_process(e->pid, e->comm);
    if (s) {
        analyze_event(s, e);
    }

    return 0;
}

int main(int argc, char **argv) {
    struct hello_kern* skel;
    struct ring_buffer *rb = NULL;
    int err;

    own_pid = getpid();
    libbpf_set_print(print_libbpf_log);
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    // 1. Yükle
    skel = hello_kern__open();
    if (!skel) {
        LOG_ERR("eBPF iskeleti acilamadi.");
        return 1;
    }

    // 2. Load
    err = hello_kern__load(skel);
    if (err) {
        LOG_ERR("eBPF programi yuklenemedi.");
        goto cleanup;
    }

    // 3. Attach
    err = hello_kern__attach(skel);
    if (err) {
        LOG_ERR("eBPF programi baglanamadi.");
        goto cleanup;
    }

    // 4. Ring Buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        LOG_ERR("Ring buffer olusturulamadi.");
        goto cleanup;
    }

    LOG_INFO("eBPF Ajan Baslatildi (PID: %d). Ctrl+C ile cikabilirsiniz.", own_pid);

    // Ana Döngü
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

cleanup:
    // Eski yöntem (HASH_ITER) yerine modüler fonksiyonu kullanıyoruz:
    cleanup_all_processes();

    ring_buffer__free(rb);
    hello_kern__destroy(skel);
    return -err;
}