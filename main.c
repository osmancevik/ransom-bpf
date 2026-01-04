/**
 * @file main.c
 * @brief RansomBPF Application Entry Point and Orchestrator.
 * @version 0.9.0
 *
 * This module is responsible for bootstrapping the application, loading the
 * eBPF kernel program, managing the Ring Buffer event loop, and coordinating
 * data flow between the kernel and the user-space analysis engine.
 *
 * It handles the application lifecycle, including graceful shutdown on signals
 * and crash recovery logging.
 *
 * Update Note (v0.9.0): Addressed unused parameter warnings in signal and
 * event callbacks to ensure a clean compilation.
 */

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

// External declaration for cleanup
extern void cleanup_whitelist();

/** @brief Process ID of the agent itself, used for self-filtering. */
static int own_pid = 0;

/** @brief Global flag to control the main event loop. */
static volatile bool exiting = false;

/** @brief Stores the source of the loaded configuration for logging. */
static char config_source[256] = "Default (Embedded)";

/**
 * @brief Signal handler for graceful shutdown (SIGINT, SIGTERM).
 * @param sig Signal number.
 */
static void handle_exit(int sig) {
    (void)sig; // Silence unused parameter warning
    exiting = true;
}

/**
 * @brief Signal handler for critical crashes (SIGSEGV, SIGABRT).
 *
 * Ensures logs are flushed to disk before the process terminates abnormally.
 * @param sig Signal number.
 */
static void handle_crash(int sig) {
    fprintf(stderr, "CRITICAL ERROR: Program crashed! Signal: %d\n", sig);
    finalize_logger();
    exit(1);
}

/**
 * @brief Ring Buffer event callback.
 *
 * This function is invoked by libbpf whenever a new event is received from
 * the kernel. It acts as the pipeline dispatcher:
 * 1. Filters out the agent's own activities (Self-Monitoring).
 * 2. Handles process exit events for memory cleanup.
 * 3. Checks the whitelist to reduce noise.
 * 4. Forwards valid events to the Analysis Engine.
 *
 * @param ctx Context (unused).
 * @param data Pointer to the `struct event` data.
 * @param size Size of the data (unused).
 * @return 0 on success.
 */
int handle_event(void *ctx, void *data, size_t size) {
    (void)ctx;  // Silence unused parameter warning
    (void)size; // Silence unused parameter warning

    if (!data) return 0;
    const struct event *e = data;

    // [CRITICAL] Self-filtering to prevent Feedback Loops.
    // Prevents the agent from analyzing its own log write operations,
    // which would otherwise cause an infinite loop and 100% CPU usage.
    if ((int)e->pid == own_pid) return 0;

    // Handle Process Exit Event
    // Necessary for preventing memory leaks in the state manager.
    if (e->type == EVENT_EXIT) {
        remove_process(e->pid);
        return 0;
    }

    // State Management: Retrieve or create process statistics
    struct process_stats *s = get_process_stats(e->pid, e->comm);
    if (!s) return 0;

    // Dynamic Whitelist Check (O(1) Hash Table lookup)
    // If the process is trusted, skip expensive analysis.
    if (is_whitelisted(s->comm)) return 0;

    // Forward to Analysis Engine
    analyze_event(s, e);

    return 0;
}

/**
 * @brief Main application entry point.
 *
 * 1. Initializes configuration and logger.
 * 2. Parses CLI arguments.
 * 3. Loads and verifies the eBPF program.
 * 4. Enters the main polling loop.
 * 5. Performs cleanup on exit.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, error code otherwise.
 */
int main(int argc, char **argv) {
    struct hello_kern* skel;
    struct ring_buffer *rb = NULL;
    int err;

    own_pid = getpid(); // Capture agent's own PID

    // --- 1. PREPARATION ---
    init_config_defaults();

    // --- 2. CLI ARGUMENT PARSING ---
    // Handle --help, --version, or config overrides.
    // Returns 1 if the program should exit immediately (e.g., after help).
    if (parse_arguments(argc, argv) == 1) {
        return 0;
    }

    // --- 3. CONFIGURATION LOADING ---
    // Priority: CLI Path (-c) > Local File > System File
    if (strlen(config.config_path) > 0) {
        if (access(config.config_path, F_OK) == 0) {
            load_config_file(config.config_path);
            snprintf(config_source, sizeof(config_source), "%s", config.config_path);
        } else {
            fprintf(stderr, "ERROR: Specified config file not found: %s\n", config.config_path);
            return 1;
        }
    }
    else {
        // Fallback to default locations
        if (access("ransom.conf", F_OK) == 0) {
            load_config_file("ransom.conf");
            snprintf(config_source, sizeof(config_source), "./ransom.conf");
        }
        else if (access("/etc/ransom-bpf/ransom.conf", F_OK) == 0) {
            load_config_file("/etc/ransom-bpf/ransom.conf");
            snprintf(config_source, sizeof(config_source), "/etc/ransom-bpf/ransom.conf");
        }
    }

    // --- 4. SYSTEM INITIALIZATION ---
    // Initialize Logger and Whitelist using loaded config
    init_logger();
    init_whitelist(config.whitelist_str);

    // [NEW] Silent Startup: Filter libbpf noise using custom callback
    libbpf_set_print(logger_libbpf_print);

    // Log startup info
    LOG_INFO("Starting up... (Config Source: %s)", config_source);

    // Display configuration summary to stdout
    print_startup_summary();

    // Register signal handlers
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);
    signal(SIGSEGV, handle_crash);
    signal(SIGABRT, handle_crash);

    // --- 5. eBPF LOADING ---
    skel = hello_kern__open();
    if (!skel) {
        LOG_ERR("Failed to open eBPF skeleton.");
        return 1;
    }

    err = hello_kern__load(skel);
    if (err) {
        LOG_ERR("Failed to load eBPF program.");
        goto cleanup;
    }

    err = hello_kern__attach(skel);
    if (err) {
        LOG_ERR("Failed to attach eBPF program.");
        goto cleanup;
    }

    // Initialize Ring Buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        LOG_ERR("Failed to create ring buffer.");
        goto cleanup;
    }

    LOG_INFO("System monitoring active... (Press Ctrl+C to exit)");

    // Main Event Loop
    while (!exiting) {
        err = ring_buffer__poll(rb, 100); // Poll every 100ms
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

    // --- 6. CLEANUP ---
    cleanup:
    LOG_INFO("Shutting down...");
    cleanup_whitelist();
    cleanup_all_processes();
    ring_buffer__free(rb);
    hello_kern__destroy(skel);
    finalize_logger();

    return -err;
}