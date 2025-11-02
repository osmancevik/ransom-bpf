// SPDX-License-Identifier: GPL-2.0
/*
 * hello_user.c: User-space agent to load and attach the eBPF program.
 *
 * This agent uses libbpf and the auto-generated skeleton
 * to open, load, and attach the eBPF kernel program.
 * It then waits for a signal (Ctrl+C) to gracefully exit.
 */

#include <stdio.h>
#include <unistd.h>     // for sleep()
#include <signal.h>     // for signal handling
#include <bpf/libbpf.h> // for libbpf functions

/*
 * hello_kern.skel.h: The auto-generated skeleton header.
 *
 * This file is created by 'bpftool gen skeleton' during the
 * CMake build process (in the cmake-build-debug... directory).
 * It contains the open, load, attach, and destroy functions
 * for our eBPF object.
 */
#include "hello_kern.skel.h"

// Flag to control the main loop, set by the signal handler
static volatile bool exiting = false;

// Signal handler to catch Ctrl+C (SIGINT) and SIGTERM
static void handle_exit(int sig)
{
    exiting = true;
}

// Optional: libbpf log printer callback
// This prints detailed logs from libbpf if errors occur.
int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
    // You can filter by log level if you want
    // İf (level > LIBBPF_WARN) {
    //     return 0;
    // }
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct hello_kern* skel;
    int err;

    // Set up the libbpf log printer
    libbpf_set_print(print_libbpf_log);

    // Set up signal handlers for graceful exit
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    // --- 1. Open ---
    // Opens the eBPF object file, but does not load it yet.
    skel = hello_kern__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open eBPF skeleton\n");
        return 1;
    }

    // --- 2. Load ---
    // Loads the eBPF program and maps into the kernel.
    err = hello_kern__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load eBPF skeleton: %d\n", err);
        goto cleanup;
    }

    // --- 3. Attach ---
    // Attaches the loaded tracepoint program to the kernel event.
    err = hello_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to attach eBPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("eBPF program loaded successfully.\n");
    printf("Waiting for execve() syscalls... (Press Ctrl+C to exit)\n");
    printf("--- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
    printf("Log output will appear in the kernel trace pipe.\n");
    printf("Run this in *another* terminal to see the output:\n");
    printf("sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("--- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");

    // --- 4. Wait for exit ---
    // Loop until the user presses Ctrl+C
    while (!exiting) {
        // Sleep for 1 second to reduce CPU usage
        sleep(1);
    }

    printf("\nExiting...\n");

cleanup:
    // --- 5. Cleanup ---
    // Detach and unload the program from the kernel
    hello_kern__destroy(skel);
    return -err;
}