/* detector.h - v0.9.0 (Standardized) */
#ifndef DETECTOR_H
#define DETECTOR_H

#include "state_manager.h"
#include "common.h"

/**
 * @file detector.h
 * @brief Core Heuristic Analysis Engine.
 * * This module contains the logic for evaluating events, calculating risk scores,
 * and triggering alarms or active interventions.
 */

/**
 * @brief Analyzes a system event to detect ransomware-like behavior.
 * * This function applies the scoring logic based on the event type (WRITE, RENAME, etc.),
 * context (file path, extension), and frequency. It updates the process's risk score
 * and triggers an alarm if the threshold is exceeded.
 * * @param s Pointer to the process state structure.
 * @param e Pointer to the current event data.
 */
void analyze_event(struct process_stats *s, const struct event *e);

/**
 * @brief Checks if the accessed file matches the configured honeypot file.
 * * @param filename The file path/name being accessed.
 * @return 1 (True) if the file is a honeypot, 0 (False) otherwise.
 */
int is_honeypot_access(const char *filename);

#endif // DETECTOR_H