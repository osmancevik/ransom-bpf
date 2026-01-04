/**
 * @file state_manager.c
 * @brief State Management Implementation for Process Tracking.
 * @version 0.9.0
 *
 * This module manages the lifecycle of process statistics using a hash table.
 * It provides O(1) access to per-process behavioral data (write counts,
 * risk scores, timestamps) which is essential for the heuristic analysis engine.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "state_manager.h"
#include "logger.h"

/**
 * @brief Global hash table head for process statistics.
 *
 * This pointer serves as the entry point for the uthash-based hash table.
 * It must be initialized to NULL.
 */
struct process_stats *processes = NULL;

/**
 * @brief Retrieves or creates the statistics structure for a given process.
 *
 * Checks if the PID exists in the hash table. If found, returns the existing
 * structure. If not, allocates memory for a new structure, initializes it
 * with default values, and adds it to the hash table.
 *
 * @param pid Process ID.
 * @param comm Process command name (used for initialization if creating new).
 * @return Pointer to the process_stats structure, or NULL if memory allocation fails.
 */
struct process_stats *get_process_stats(int pid, const char *comm) {
    struct process_stats *s;

    // Search for the PID in the hash table
    HASH_FIND_INT(processes, &pid, s);

    if (s == NULL) {
        // Not found, create a new entry
        s = (struct process_stats*)malloc(sizeof(struct process_stats));
        if (!s) {
            fprintf(stderr, "[WARN] Memory allocation failed (malloc) for PID: %d\n", pid);
            return NULL;
        }

        // Initialize fields
        s->pid = pid;
        strncpy(s->comm, comm, sizeof(s->comm) - 1);
        s->comm[sizeof(s->comm) - 1] = '\0';

        s->total_write_count = 0;
        s->write_burst = 0;
        s->rename_burst = 0;
        s->current_score = 0;

        s->window_start_time = time(NULL);
        s->last_decay_time = time(NULL);

        // Add to the hash table
        HASH_ADD_INT(processes, pid, s);
    }
    return s;
}

/**
 * @brief Removes a process from the tracking table and frees memory.
 *
 * This function should be called when a process termination event (EVENT_EXIT)
 * is received to prevent memory leaks.
 *
 * @param pid Process ID to remove.
 */
void remove_process(int pid) {
    struct process_stats *s;

    HASH_FIND_INT(processes, &pid, s);

    if (s) {
        HASH_DEL(processes, s);
        free(s);
    }
}

/**
 * @brief Cleans up all tracked processes and frees all allocated memory.
 *
 * Iterates through the entire hash table and frees every element.
 * This ensures a clean exit without memory leaks.
 */
void cleanup_all_processes() {
    struct process_stats *current_process, *tmp;

    // uthash macro: Safe iteration for deletion
    HASH_ITER(hh, processes, current_process, tmp) {
        HASH_DEL(processes, current_process);
        free(current_process);
    }
}