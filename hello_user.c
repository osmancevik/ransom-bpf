// SPDX-License-Identifier: GPL-2.0
/*
 * hello_user.c: User-space agent to load eBPF program
 * and read events from a Ring Buffer.
 * Supports: execve and write events with per-PID statistics.
 * Fix: Ignores own PID to prevent feedback loops.
 */

#include <stdio.h>
#include <stdlib.h>     // malloc, free
#include <unistd.h>     // sleep, getpid
#include <signal.h>     // signal handling
#include <string.h>     // strcmp
#include <bpf/libbpf.h> // libbpf functions
#include <errno.h>

#include "hello_kern.skel.h"
#include "common.h"
#include "uthash.h"     // State Management

// --- DURUM YÖNETİMİ VERİ YAPILARI ---

struct process_stats {
    int pid;                   // KEY
    char comm[TASK_COMM_LEN];  // Process Name
    unsigned long exec_count;  // Counter for execve
    unsigned long write_count; // Counter for write
    UT_hash_handle hh;         // uthash handle
};

struct process_stats *processes = NULL; // Hash table head

// Ajanın kendi PID'si (Feedback loop'u engellemek için)
static int own_pid = 0;

// Flag to control the main loop
static volatile bool exiting = false;

static void handle_exit(int sig)
{
    exiting = true;
}

int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/*
 * handle_event: Processes events from the Ring Buffer.
 * Updates stats based on event type (EXEC or WRITE).
 */
int handle_event(void *ctx, void *data, size_t size)
{
    const struct event *e = data;
    struct process_stats *s;

    if (size < sizeof(*e)) {
        return 1;
    }

    // --- 1. FİLTRELEME (Gürültü Önleme) ---

    // A: Kendi kendini yoksay
    if ((int)e->pid == own_pid) {
        return 0;
    }

    // B: Geliştirme ortamı gürültülerini yoksay (GEÇİCİ LİSTE)
    // sshd-session: SSH bağlantısı logları
    // sudo: Yetki işlemleri logları
    // tty: Terminal çıktıları
    if (strcmp(e->comm, "sshd-session") == 0 ||
        strcmp(e->comm, "sudo") == 0 ||
        strcmp(e->comm, "bash") == 0 ||
        strcmp(e->comm, "sshd") == 0) {
        return 0;
        }

    // --- 2. İSTATİSTİK GÜNCELLEME ---

    // Find or Create Process Stats
    int key_pid = (int)e->pid;
    HASH_FIND_INT(processes, &key_pid, s);

    if (!s) {
        s = (struct process_stats *)malloc(sizeof(struct process_stats));
        s->pid = key_pid;
        __builtin_strncpy(s->comm, e->comm, TASK_COMM_LEN);
        s->comm[TASK_COMM_LEN - 1] = '\0';
        s->exec_count = 0;
        s->write_count = 0;
        HASH_ADD_INT(processes, pid, s);
    }

    // ... (Filtreleme kodları aynı kalacak) ...

    // --- OLAY TÜRÜNE GÖRE MANTIK ---
    switch (e->type) {
        case EVENT_EXEC:
            s->exec_count++;
            printf("[EXEC]   PID: %-6d | COMM: %-16s | FILE: %s\n",
                   s->pid, s->comm, e->filename);
            break;

        case EVENT_WRITE:
            s->write_count++;
            printf("[WRITE]  PID: %-6d | COMM: %-16s | Count: %lu\n",
                   s->pid, s->comm, s->write_count);
            break;

        case EVENT_OPEN:
            // openat çok sık olur, sadece görmek için logluyoruz
            printf("[OPEN]   PID: %-6d | COMM: %-16s | FILE: %s\n",
                   s->pid, s->comm, e->filename);
            break;

        case EVENT_RENAME:
            // BU ÇOK KRİTİK! Fidye yazılımı belirtisi olabilir.
            printf("[RENAME] PID: %-6d | COMM: %-16s | FILE: %s\n",
                   s->pid, s->comm, e->filename);
            break;

        default:
            break;
    }
    // ...

    return 0;
}

int main(int argc, char **argv)
{
    struct hello_kern* skel;
    struct ring_buffer *rb_manager = NULL;
    int err;

    // Kendi PID'imizi öğrenelim
    own_pid = getpid();

    libbpf_set_print(print_libbpf_log);
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    // --- 1. Open ---
    skel = hello_kern__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open eBPF skeleton\n");
        return 1;
    }

    // --- 2. Load ---
    err = hello_kern__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load eBPF skeleton: %d\n", err);
        goto cleanup;
    }

    // --- 3. Attach ---
    err = hello_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to attach eBPF skeleton: %d\n", err);
        goto cleanup;
    }

    // --- 4. Ring Buffer ---
    rb_manager = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb_manager) {
        err = -1;
        fprintf(stderr, "Error: Failed to set up ring buffer\n");
        goto cleanup;
    }

    printf("Hafizali eBPF Ajan (PID: %d) baslatildi.\n", own_pid);
    printf("Kendi PID'imden gelen olaylar yoksayilacak.\n");
    printf("-------------------------------------------------------\n");

    // --- 5. Poll Loop ---
    while (!exiting) {
        err = ring_buffer__poll(rb_manager, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error: Polling ring buffer: %d\n", err);
            break;
        }
    }

    printf("\nExiting...\n");

cleanup:
    struct process_stats *current_user, *tmp;
    HASH_ITER(hh, processes, current_user, tmp) {
        HASH_DEL(processes, current_user);
        free(current_user);
    }

    ring_buffer__free(rb_manager);
    hello_kern__destroy(skel);

    return -err;
}