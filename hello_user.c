// SPDX-License-Identifier: GPL-2.0
/*
 * hello_user.c: User-space agent to load eBPF program
 * and read events from a Ring Buffer.
 *
 * This agent uses libbpf and the auto-generated skeleton
 * to open, load, and attach the eBPF kernel program.
 *
 * It then sets up a Ring Buffer manager to poll for
 * data (struct event) sent from the kernel, printing
 * the event details (PID, comm, filename) to stdout.
 */

#include <stdio.h>
#include <unistd.h>     // for sleep()
#include <signal.h>     // for signal handling
#include <bpf/libbpf.h> // for libbpf functions
#include <errno.h>

/*
 * hello_kern.skel.h: The auto-generated skeleton header.
 *
 * This file is created by 'bpftool gen skeleton' during the
 * CMake build process (in the cmake-build-debug... directory).
 * It contains the open, load, attach, and destroy functions
 * for our eBPF object.
 */
#include "hello_kern.skel.h"

/*
 * common.h: The shared data structure (struct event)
 * between the kernel and user-space.
 */
#include "common.h"

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
    // if (level > LIBBPF_WARN) {
    //     return 0;
    // }
    return vfprintf(stderr, format, args);
}

/*
 * handle_event: The Ring Buffer callback function.
 *
 * This function is called by 'ring_buffer__poll()' every time
 * a new event (sample) is read from the ring buffer.
 *
 * It implements the "Parser & Logger" role by casting
 * the raw data to our 'struct event' and printing it.
 */
int handle_event(void *ctx, void *data, size_t size)
{
    // Cast the raw data pointer to our 'struct event'
    const struct event *event = data;

    // Check if the data size matches our struct size
    if (size < sizeof(*event)) {
        fprintf(stderr, "Error: Malformed event received\n");
        return 1;
    }

    // Print the event data (the "Logger" part)
    printf("Event received: PID=%-6u COMM=%.16s FILENAME=%s\n",
           event->pid,
           event->comm,
           event->filename);

    return 0;
}

int main(int argc, char **argv)
{
    struct hello_kern* skel;
    struct ring_buffer *rb_manager = NULL; // Ring Buffer Manager
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

    // --- 4. Set up Ring Buffer ---
    // This is the "Event Listener" setup
    printf("Setting up Ring Buffer...\n");

    // 'ring_buffer__new()' creates a manager that links the map's
    // file descriptor (skel->maps.rb) to our 'handle_event' callback.
    rb_manager = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb_manager) {
        err = -1;
        fprintf(stderr, "Error: Failed to set up ring buffer\n");
        goto cleanup;
    }

    printf("eBPF program loaded successfully.\n");
    printf("Waiting for execve() syscalls... (Press Ctrl+C to exit)\n");
    printf("--- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");

    // --- 5. Poll for events ---
    // Loop until the user presses Ctrl+C
    while (!exiting) {
        // 'ring_buffer__poll()' will check for new data and
        // call 'handle_event' if any is found.
        // We set a 100ms timeout.
        err = ring_buffer__poll(rb_manager, 100 /* timeout, ms */);
        if (err == -EINTR) {
            // Interrupted by Ctrl+C
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
    // --- 6. Cleanup ---

    // Free the ring buffer manager
    ring_buffer__free(rb_manager);

    // Detach and unload the program from the kernel
    hello_kern__destroy(skel);

    return -err;
}