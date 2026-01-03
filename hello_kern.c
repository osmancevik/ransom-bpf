/* hello_kern.c - v0.8.0 (Metadata Enrichment) */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> // [YENI] task_struct okumak icin gerekli
#include "common.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline void send_event(void *ctx, int type, const char *filename_ptr)
{
    struct event *e;
    __u64 pid_tgid;
    __u64 uid_gid;
    struct task_struct *task;
    struct task_struct *parent;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    e->type = type;

    // 1. PID ve Process Name
    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (__u32)(pid_tgid >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 2. [YENI] UID (Kullanici Kimligi)
    // bpf_get_current_uid_gid() -> Lower 32 bits: UID, Upper 32 bits: GID
    uid_gid = bpf_get_current_uid_gid();
    e->uid = (__u32)uid_gid;

    // 3. [YENI] PPID (Ana Surec Kimligi)
    // Su anki task_struct'a erisip, parent pointer'ini takip ediyoruz.
    task = (struct task_struct *)bpf_get_current_task();

    // BPF_CORE_READ macrosu ile guvenli bellek okumasi:
    // task -> real_parent -> tgid (PID)
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 4. Dosya Adi
    if (filename_ptr) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

// --- IZLEME NOKTALARI (HOOKS) ---

// 1. EXECVE
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_EXEC, (const char *)ctx->args[0]);
    return 0;
}

// 2. WRITE
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write_enter(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_WRITE, NULL);
    return 0;
}

// 3. OPENAT
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_OPEN, (const char *)ctx->args[1]);
    return 0;
}

// 4. RENAMEAT (Eski)
SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat_enter(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_RENAME, (const char *)ctx->args[1]);
    return 0;
}

// 5. RENAMEAT2 (Modern - mv komutu için)
SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2_enter(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_RENAME, (const char *)ctx->args[1]);
    return 0;
}

// 6. EXIT (Temizlik için)
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
    send_event(ctx, EVENT_EXIT, NULL);
    return 0;
}

// 7. UNLINK (Dosya Silme)
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    // Ozel durum: Unlink icin send_event helper'ini burada kullanamiyoruz
    // cunku args indeksleri farkli olabilir veya manuel islem gerekebilir.
    // Ancak send_event genel yapida oldugu icin onu cagirabiliriz:
    send_event(ctx, EVENT_UNLINK, (const char *)ctx->args[1]);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";