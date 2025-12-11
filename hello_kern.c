/* hello_kern.c - Çekirdek Alanı */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
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

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    e->type = type;
    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (__u32)(pid_tgid >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (filename_ptr) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

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
int handle_exit(void *ctx)   // <--- DÜZELTME BURADA (struct ... yerine void *ctx)
{
    send_event(ctx, EVENT_EXIT, NULL);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";