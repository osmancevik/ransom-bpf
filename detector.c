/**
 * @file detector.c
 * @brief Heuristic Analysis Engine implementation.
 * @version 0.9.8
 *
 * This module implements the core logic for detecting ransomware behavior based on
 * risk scoring, context awareness, and statistical anomalies. It also handles
 * the "Active Intervention" (IPS) mechanism with safety filters.
 *
 * Update Note (v0.9.8): Resolved logic errors in filename checks and utilized
 * unused parameters in the kill switch logging routine.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h> // For kill() and SIGKILL
#include <errno.h>
#include "detector.h"
#include "logger.h"
#include "config.h"
#include "whitelist.h"

// --- HELPER FUNCTIONS ---

/**
 * @brief Applies a time-based decay to the process risk score.
 *
 * Reduces the risk score over time to prevent false positives from
 * long-running processes (handling "Low and Slow" attacks).
 * Currently reduces score by 10% for every second of inactivity.
 *
 * @param s Pointer to the process statistics structure.
 */
static void apply_decay(struct process_stats *s) {
    time_t now = time(NULL);
    double diff = difftime(now, s->last_decay_time);

    // Apply decay if at least 1 second has passed
    if (diff >= 1.0) {
        int decay_amount = (int)(s->current_score * 0.10 * diff);

        // Ensure at least 1 point is removed if score is positive
        if (s->current_score > 0 && decay_amount == 0) decay_amount = 1;

        s->current_score -= decay_amount;

        // Clamp score to 0
        if (s->current_score < 0) s->current_score = 0;

        // Reset burst counters if score reaches 0
        if (s->current_score == 0) {
            s->write_burst = 0;
            s->rename_burst = 0;
        }

        s->last_decay_time = now;
    }
}

/**
 * @brief Checks if a filename ends with a known ransomware extension.
 *
 * Scans against a hardcoded list of suspicious extensions (e.g., .locked, .enc).
 *
 * @param filename The filename to check.
 * @return 1 if suspicious, 0 otherwise.
 */
static int has_suspicious_extension(const char *filename) {
    if (!filename) return 0;

    const char *suspicious_exts[] = {
        ".locked", ".enc", ".cry", ".crypto",
        ".crypted", ".wanna", ".dark", NULL
    };

    size_t len = strlen(filename);

    for (int i = 0; suspicious_exts[i] != NULL; i++) {
        const char *ext = suspicious_exts[i];
        size_t ext_len = strlen(ext);

        if (len > ext_len) {
            // Check suffix match
            if (strcmp(filename + len - ext_len, ext) == 0) return 1;
        }
    }
    return 0;
}

/**
 * @brief Checks if the accessed file is the designated honeypot.
 *
 * Performs a substring check against the configured honeypot file path.
 *
 * @param filename The accessed file path.
 * @return 1 if it matches the honeypot, 0 otherwise.
 */
int is_honeypot_access(const char *filename) {
    if (!filename || strlen(config.honeypot_file) == 0) return 0;

    if (strstr(filename, config.honeypot_file) != NULL) return 1;

    return 0;
}

/**
 * @brief Terminates a malicious process (Active Intervention).
 *
 * Sends a SIGKILL signal to the target process. Includes critical safety
 * checks to prevent system instability (e.g., protecting PID 1).
 *
 * @param s Process statistics (Target).
 * @param e Event details (Context).
 * @param original_reason The primary reason for triggering the kill switch.
 */
static void kill_process(struct process_stats *s, const struct event *e, const char *original_reason) {

    // --- SAFETY FILTERS (Critical) ---

    // 1. Critical System Process Protection (PID 0, 1)
    // Killing PID 1 (init/systemd) causes a kernel panic.
    if (s->pid <= 1) {
        LOG_ERR("⚠️ CRITICAL SAFETY: Attempted to kill PID %d (init/systemd)! Blocked.", s->pid);
        log_alert_json(
            "KILL_PREVENTED",
            s->pid, e->ppid, e->uid, s->comm, e->filename,
            "Critical System Process Protection",
            s->current_score
        );
        return;
    }

    // 2. Whitelist Protection (Last Resort Check)
    // Double-check whitelist status to prevent collateral damage due to race conditions.
    if (is_whitelisted(s->comm)) {
        LOG_WARN("⚠️ SAFETY: Attempted to kill whitelisted process (%s)! Blocked.", s->comm);
        log_alert_json(
            "KILL_PREVENTED",
            s->pid, e->ppid, e->uid, s->comm, e->filename,
            "Whitelisted Process Protection",
            s->current_score
        );
        return;
    }

    // --- ACTION (The Kill Switch) ---

    // 9 = SIGKILL (Immediate termination, cannot be caught or ignored)
    int ret = kill(s->pid, SIGKILL);

    if (ret == 0) {
        // SUCCESS: Log to console
        LOG_ALARM("⛔ ACTIVE INTERVENTION: Process Killed! PID: %d (%s)", s->pid, s->comm);

        // SUCCESS: Log to Alerts JSON
        // FIX: Using 'original_reason' instead of hardcoded string to fix unused parameter warning
        log_alert_json(
            "PROCESS_KILLED",
            s->pid, e->ppid, e->uid, s->comm, e->filename,
            original_reason,
            s->current_score
        );
    } else {
        // FAILURE: Permission denied, process already dead, or zombie
        LOG_ERR("❌ INTERVENTION FAILED: Could not kill process (PID: %d). Error: %s",
                s->pid, strerror(errno));

        log_alert_json(
            "KILL_FAILED",
            s->pid, e->ppid, e->uid, s->comm, e->filename,
            strerror(errno), s->current_score
        );
    }
}

// --- MAIN ANALYSIS ROUTINE ---

/**
 * @brief Evaluates an event against the detection heuristics.
 *
 * This is the entry point for the detection logic. It updates the risk score based on:
 * 1. Event Type weights (Write, Rename, etc.)
 * 2. Context Multipliers (Directory sensitivity)
 * 3. Semantic Analysis (File extensions)
 * 4. Honeypot Access
 *
 * Triggers alarms and active blocking if the risk threshold is exceeded.
 *
 * @param s Process statistics structure.
 * @param e Event data from kernel space.
 */
void analyze_event(struct process_stats *s, const struct event *e) {

    // 1. Whitelist Filter (Early exit to reduce noise)
    if (is_whitelisted(s->comm)) return;

    // 2. Audit Logging (Log RAW events that passed the whitelist)
    const char *event_name = "UNKNOWN";
    switch(e->type) {
        case EVENT_WRITE: event_name = "WRITE"; break;
        case EVENT_RENAME: event_name = "RENAME"; break;
        case EVENT_OPEN: event_name = "OPEN"; break;
        case EVENT_UNLINK: event_name = "UNLINK"; break;
    }

    log_audit_json(event_name, s->pid, e->ppid, e->uid, s->comm, e->filename);

    // 3. Analysis and Scoring
    apply_decay(s);

    int score_gained = 0;
    int is_alarm = 0;
    char risk_reason[64] = {0};

    switch (e->type) {
        case EVENT_WRITE:
            s->write_burst++;
            s->total_write_count++;
            score_gained = config.score_write;

            if (is_honeypot_access(e->filename)) {
                score_gained += config.score_honeypot;
                snprintf(risk_reason, sizeof(risk_reason), "HONEYPOT WRITE");
            }
            break;

        case EVENT_RENAME:
            s->rename_burst++;
            score_gained = config.score_rename;

            if (is_honeypot_access(e->filename)) {
                score_gained += config.score_honeypot;
                snprintf(risk_reason, sizeof(risk_reason), "HONEYPOT RENAME");
            }
            break;

        case EVENT_UNLINK:
            score_gained = config.score_unlink;
            break;

        case EVENT_OPEN:
            if (is_honeypot_access(e->filename)) {
                score_gained += config.score_honeypot;
                snprintf(risk_reason, sizeof(risk_reason), "HONEYPOT ACCESS");
            }
            break;
    }

    // Apply Directory Sensitivity Multipliers
    double multiplier = 1.0;

    // FIX: Check if string is not empty, because e->filename array address is never NULL.
    if (e->filename[0] != '\0') {
        if (strncmp(e->filename, "/home", 5) == 0) multiplier = 2.0;       // High value user data
        else if (strncmp(e->filename, "/etc", 4) == 0) multiplier = 5.0;   // Critical config files
        else if (strncmp(e->filename, "/var/www", 8) == 0) multiplier = 2.0; // Webroot
        else if (strncmp(e->filename, "/tmp", 4) == 0) multiplier = 0.5;   // Temp files (Noise reduction)
    }
    score_gained = (int)(score_gained * multiplier);

    // Apply Extension Penalty
    if ((e->type == EVENT_RENAME || e->type == EVENT_WRITE) && has_suspicious_extension(e->filename)) {
        score_gained += config.score_ext_penalty;
        if (strlen(risk_reason) == 0) snprintf(risk_reason, sizeof(risk_reason), "SUSPICIOUS EXTENSION");
    }

    s->current_score += score_gained;

    // Check Threshold
    if (strlen(risk_reason) == 0) {
        if (s->current_score >= config.risk_threshold) {
            is_alarm = 1;
            snprintf(risk_reason, sizeof(risk_reason), "RISK THRESHOLD EXCEEDED");
        }
    } else {
        // Immediate alarm if there's a specific high-risk reason (like Honeypot)
        if (s->current_score >= config.risk_threshold) is_alarm = 1;
    }

    // 4. Alarm and Response
    if (is_alarm) {
        // A. Detection Log
        LOG_ALARM("RANSOMWARE SUSPECTED [%s]! PID:%d UID:%d | File:%s | Score:%d",
                  risk_reason, s->pid, e->uid, e->filename, s->current_score);

        log_alert_json(
            "RANSOMWARE_DETECTED",
            s->pid, e->ppid, e->uid, s->comm, e->filename,
            risk_reason, s->current_score
        );

        // B. Active Blocking (IPS Mode)
        if (config.active_blocking) {
            kill_process(s, e, risk_reason);
        }

        // C. Reset Score after Action/Alarm
        s->current_score = 0;
        s->write_burst = 0;
        s->rename_burst = 0;
        s->last_decay_time = time(NULL);
    }
}