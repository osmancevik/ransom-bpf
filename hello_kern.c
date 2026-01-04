/* hello_kern.c - v0.9.9 (Universal Syscall Coverage) */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
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

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    e->type = type;

    // 1. PID ve Process Name
    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (__u32)(pid_tgid >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 2. UID
    uid_gid = bpf_get_current_uid_gid();
    e->uid = (__u32)uid_gid;

    // 3. PPID
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 4. Dosya Adi
    if (filename_ptr) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    } else {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

// --- DOSYA YAZMA (WRITE FAMILY) ---

// 1. Standart Write
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_WRITE, NULL);
    return 0;
}

// 2. Pwrite64 (Python/Java siklikla kullanir)
SEC("tracepoint/syscalls/sys_enter_pwrite64")
int handle_pwrite64(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_WRITE, NULL);
    return 0;
}

// 3. Writev (Vektorlu Yazma)
SEC("tracepoint/syscalls/sys_enter_writev")
int handle_writev(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_WRITE, NULL);
    return 0;
}

// --- ISIM DEGISTIRME (RENAME FAMILY) ---

// 1. Rename (Standart - args[1] = newname)
SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_RENAME, (const char *)ctx->args[1]);
    return 0;
}

// 2. Renameat (Klasor bazli - args[3] = newname)
SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter* ctx)
{
    // renameat(olddfd, oldname, newdfd, newname)
    send_event(ctx, EVENT_RENAME, (const char *)ctx->args[3]);
    return 0;
}

// 3. Renameat2 (Modern ve Flag destekli - args[3] = newname)
SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter* ctx)
{
    // renameat2(olddfd, oldname, newdfd, newname, flags)
    send_event(ctx, EVENT_RENAME, (const char *)ctx->args[3]);
    return 0;
}

// --- DIGERLERI ---

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_OPEN, (const char *)ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_EXEC, (const char *)ctx->args[0]);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
    send_event(ctx, EVENT_EXIT, NULL);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    send_event(ctx, EVENT_UNLINK, (const char *)ctx->args[1]);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";