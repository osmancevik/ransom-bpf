/**
 * @file test_runner.c
 * @brief Unit Test Suite for RansomBPF Heuristic Engine.
 * @version 0.9.0
 *
 * This module validates the core logic of the detection engine in isolation.
 * It mocks the logging and eBPF subsystems to test the risk scoring algorithms
 * (Write Burst, Rename, Honeypot, etc.) without requiring a running kernel.
 *
 * Usage:
 * gcc tests/test_runner.c detector.c config.c state_manager.c whitelist.c -o run_tests
 * ./run_tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdarg.h>

#include "../detector.h"
#include "../config.h"
#include "../logger.h"
#include "../common.h"
#include "../state_manager.h"

// Explicit declaration for testing if header is not included
extern int is_honeypot_access(const char *filename);

#ifndef EVENT_UNLINK
#define EVENT_UNLINK 6
#endif

// --- MOCK INFRASTRUCTURE ---
// Replaces real I/O and System calls for deterministic testing.

LogLevel last_log_level = -1;
char last_log_msg[256];
int alarm_triggered = 0;

/**
 * @brief Mock implementation of log_message.
 *
 * Intercepts log calls to check if an ALARM was triggered.
 */
void log_message(LogLevel level, const char *file, int line, const char *format, ...) {
    last_log_level = level;

    if (level == LOG_LEVEL_ALARM) {
        alarm_triggered = 1;
    }

    va_list args;
    va_start(args, format);
    vsnprintf(last_log_msg, sizeof(last_log_msg), format, args);
    va_end(args);
}

/**
 * @brief Mock implementation of Audit Logging.
 */
void log_audit_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename)
{
    // No-op for unit tests
}

/**
 * @brief Mock implementation of Alert Logging.
 *
 * Matches the signature in logger.h v0.9.0.
 */
void log_alert_json(const char *event_type,
                    int pid, int ppid, int uid,
                    const char *comm,
                    const char *filename,
                    const char *risk_reason,
                    int score)
{
    // No-op. Alarm state is captured via log_message mock.
}

/**
 * @brief Mock implementation for libbpf print callback.
 */
int logger_libbpf_print(enum libbpf_print_level level, const char *format, va_list args) {
    return 0;
}


// --- HELPER FUNCTIONS ---

/**
 * @brief Resets the global state before each test case.
 */
void setup() {
    alarm_triggered = 0;
    last_log_level = -1;
    memset(last_log_msg, 0, sizeof(last_log_msg));

    // Reset Config
    memset(&config, 0, sizeof(struct app_config));

    // Set Test Configuration (Phase 2 Scoring)
    config.window_sec = 5;
    config.risk_threshold = 100;

    config.score_write = 10;
    config.score_rename = 20;
    config.score_unlink = 50;
    config.score_honeypot = 1000;
    config.score_ext_penalty = 50;

    // Legacy params (kept for backward compatibility checks)
    config.write_threshold = 10;
    config.rename_threshold = 5;

    config.verbose_mode = 0;
    config.active_blocking = 0; // Disable kill() for unit tests

    // Clear string buffers
    strcpy(config.service_log, "");
    strcpy(config.alert_log, "");
    strcpy(config.audit_log, "");

    strcpy(config.honeypot_file, "secret_passwords.txt");
}

#define PASS() printf("\033[0;32m[PASS]\033[0m\n")
#define FAIL() printf("\033[0;31m[FAIL]\033[0m\n")

// --- TEST CASES ---

void test_write_burst_detection() {
    printf("Test 1: Write Burst Detection (Risk Score Based)... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 1001;
    strcpy(p.comm, "ransom.exe");
    p.window_start_time = time(NULL);

    struct event e;
    e.type = EVENT_WRITE;
    e.pid = 1001;
    e.uid = 1000; e.ppid = 900;

    // Simulate 11 writes (11 * 10 = 110 points > 100)
    for (int i = 0; i < 11; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 1) PASS();
    else {
        FAIL();
        printf("   -> Expected: Alarm should trigger. (Final Score: %d)\n", p.current_score);
        exit(1);
    }
}

void test_normal_user_behavior() {
    printf("Test 2: Normal User Behavior (False Positive Verification)... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 2002;
    p.window_start_time = time(NULL);

    struct event e;
    e.type = EVENT_WRITE;
    e.uid = 1000;

    // Simulate 5 writes (5 * 10 = 50 points < 100)
    for (int i = 0; i < 5; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 0) PASS();
    else {
        FAIL();
        printf("   -> Error: False Positive! Alarm triggered. (Score: %d)\n", p.current_score);
        exit(1);
    }
}

void test_window_reset_logic() {
    printf("Test 3: Time Window Reset Logic... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 3003;
    p.current_score = 90;
    // Set window start to 10 seconds ago (config.window_sec is 5)
    // Note: detector.c uses decay logic now, but strong window reset might still apply
    // depending on specific implementation version. Assuming decay reduces score.
    p.last_decay_time = time(NULL) - 10;

    struct event e;
    e.type = EVENT_WRITE;
    e.uid = 1000;

    analyze_event(&p, &e);

    // Score should decay significantly or reset.
    // If logic is purely window-based reset in older versions, it goes to 0 or low.
    // If logic is decay-based: 10s * 10% = 100% reduction.
    if (alarm_triggered == 0 && p.current_score < 90) PASS();
    else {
        FAIL();
        printf("   -> Error: Score did not decay/reset. (Score: %d)\n", p.current_score);
        exit(1);
    }
}

void test_rename_burst_detection() {
    printf("Test 4: Rename Burst Detection... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 4004;
    p.window_start_time = time(NULL);

    struct event e;
    e.type = EVENT_RENAME;
    e.uid = 1000;
    strcpy(e.filename, "data.txt.locked"); // Suspicious extension adds penalty

    // 2 Renames should trigger alarm:
    // 20 (Base) + 50 (Ext Penalty) = 70 per event.
    // 2 * 70 = 140 > 100.
    for (int i = 0; i < 2; i++) {
        analyze_event(&p, &e);
    }

    if (alarm_triggered == 1) PASS();
    else {
        FAIL();
        printf("   -> Error: Rename burst failed to trigger alarm. (Score: %d)\n", p.current_score);
        exit(1);
    }
}

void test_honeypot_access() {
    printf("Test 5: Honeypot Access Detection... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 5005;
    strcpy(p.comm, "hacker");

    struct event e;
    e.type = EVENT_OPEN;
    e.uid = 1000;
    // Must match setup() honeypot file
    strcpy(e.filename, "/var/www/secret_passwords.txt");

    analyze_event(&p, &e);

    if (alarm_triggered == 1) PASS();
    else {
        FAIL();
        printf("   -> Error: Honeypot access was missed!\n");
        exit(1);
    }
}

void test_deletion_event() {
    printf("Test 6: File Deletion Risk Analysis... ");
    setup();

    struct process_stats p;
    memset(&p, 0, sizeof(p));
    p.pid = 6006;

    struct event e;
    e.type = EVENT_UNLINK;
    e.uid = 1000;
    strcpy(e.filename, "important.pdf");

    // 1st Deletion: 50 points
    analyze_event(&p, &e);
    assert(alarm_triggered == 0);

    // 2nd Deletion: +50 points = 100 (Threshold reached)
    analyze_event(&p, &e);

    if (alarm_triggered == 1) PASS();
    else {
        FAIL();
        printf("   -> Error: Alarm not triggered on 2nd deletion.\n");
        exit(1);
    }
}

int main() {
    printf("==========================================\n");
    printf("   RANSOM-BPF: UNIT TESTS (v0.9.0)        \n");
    printf("==========================================\n");

    test_write_burst_detection();
    test_normal_user_behavior();
    test_window_reset_logic();
    test_rename_burst_detection();
    test_honeypot_access();
    test_deletion_event();

    printf("==========================================\n");
    printf("   ALL TESTS PASSED SUCCESSFULLY.         \n");
    printf("==========================================\n");
    
    return 0;
}