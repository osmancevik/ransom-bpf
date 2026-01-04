/**
 * @file hello_kern.c
 * @brief eBPF Kernel Space Program for Ransomware Detection.
 * @version 0.9.0
 *
 * This module hooks into various kernel tracepoints to capture file system
 * and process activities. It collects metadata (PID, UID, PPID, Comm)
 * and sends structured events to user space via a Ring Buffer.
 *
 * It provides "Universal Coverage" by monitoring standard syscalls (write, rename)
 * as well as variants used by high-level languages like Python and Java (pwrite64).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/**
 * @brief Ring Buffer definition for high-performance data transfer.
 *
 * Used to push `struct event` data from kernel space to user space.
 * Size is set to 256KB to accommodate bursty traffic.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief Helper function to package and submit an event to the Ring Buffer.
 *
 * Populates the `struct event` with process metadata (PID, UID, PPID)
 * and the associated filename, then submits it to user space.
 *
 * @param ctx Tracepoint context (opaque pointer).
 * @param type Event type identifier (e.g., EVENT_WRITE, EVENT_RENAME).
 * @param filename_ptr Pointer to the filename string in user memory (can be NULL).
 */
static __always_inline void send_event(void *ctx, int type, const char *filename_ptr)
{
    struct event *e;
    __u64 pid_tgid;
    __u64 uid_gid;
    struct task_struct *task;

    // Reserve space in the Ring Buffer
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    e->type = type;

    // 1. Capture PID and Process Name
    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (__u32)(pid_tgid >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 2. Capture User ID (Real UID)
    uid_gid = bpf_get_current_uid_gid();
    e->uid = (__u32)uid_gid;

    // 3. Capture Parent Process ID (PPID) using CO-RE
    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 4. Capture Filename (if applicable)
    if (filename_ptr) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    } else {
        e->filename[0] = '\0';
    }

    // Submit the event
    bpf_ringbuf_submit(e, 0);
}

// --- FILE WRITE OPERATIONS (WRITE FAMILY) ---

/**
 * @brief Hooks the standard `write` syscall.
 *
 * Captures file modification attempts. Commonly used by C/C++ applications
 * and shell scripts (e.g., `echo "data" > file`).
 */
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_WRITE, NULL);
    return 0;
}

/**
 * @brief Hooks the `pwrite64` syscall.
 *
 * Critical for detecting ransomware written in high-level languages
 * like Python and Java, which prefer positional writes.
 */
SEC("tracepoint/syscalls/sys_enter_pwrite64")
int handle_pwrite64(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_WRITE, NULL);
    return 0;
}

/**
 * @brief Hooks the `writev` syscall (Vectorized Write).
 *
 * Monitors scatter-gather I/O operations, often used by high-performance
 * runtimes like NodeJS and Go.
 */
SEC("tracepoint/syscalls/sys_enter_writev")
int handle_writev(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_WRITE, NULL);
    return 0;
}

// --- FILE RENAME OPERATIONS (RENAME FAMILY) ---

/**
 * @brief Hooks the legacy `rename` syscall.
 *
 * Captures basic file renaming. `args[1]` contains the `newname`.
 */
SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_RENAME, (const char *)ctx->args[1]);
    return 0;
}

/**
 * @brief Hooks the `renameat` syscall.
 *
 * Directory-relative renaming. `args[3]` contains the `newname`.
 */
SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter* ctx)
{
    // signature: renameat(olddfd, oldname, newdfd, newname)
    send_event(ctx, EVENT_RENAME, (const char *)ctx->args[3]);
    return 0;
}

/**
 * @brief Hooks the modern `renameat2` syscall.
 *
 * Used by modern Linux utilities (mv) and atomic exchange operations.
 * `args[3]` contains the `newname`.
 */
SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter* ctx)
{
    // signature: renameat2(olddfd, oldname, newdfd, newname, flags)
    send_event(ctx, EVENT_RENAME, (const char *)ctx->args[3]);
    return 0;
}

// --- OTHER CRITICAL OPERATIONS ---

/**
 * @brief Hooks the `openat` syscall.
 *
 * Captures file opening attempts, used for detecting traversal patterns
 * or honeypot access. `args[1]` contains the filename.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_OPEN, (const char *)ctx->args[1]);
    return 0;
}

/**
 * @brief Hooks the `execve` syscall.
 *
 * Captures new process execution. Essential for building the process tree
 * and detecting chain execution (e.g., bash spawning python).
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter* ctx)
{
    send_event(ctx, EVENT_EXEC, (const char *)ctx->args[0]);
    return 0;
}

/**
 * @brief Hooks the process exit tracepoint.
 *
 * Used to signal the user space agent to clean up memory resources
 * associated with the terminated process ID.
 */
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
    send_event(ctx, EVENT_EXIT, NULL);
    return 0;
}

/**
 * @brief Hooks the `unlinkat` syscall.
 *
 * Captures file deletion attempts. High risk if targeted at backups.
 * `args[1]` contains the filename.
 */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    send_event(ctx, EVENT_UNLINK, (const char *)ctx->args[1]);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";