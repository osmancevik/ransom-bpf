/* state_manager.h - v0.9.0 (Standardized) */
#ifndef STATE_MANAGER_H
#define STATE_MANAGER_H

#include "uthash.h"
#include <time.h>

/**
 * @file state_manager.h
 * @brief Manages the state and behavioral statistics of active processes.
 */

/**
 * @struct process_stats
 * @brief Holds behavioral metrics and state for a specific process.
 * * This structure is used in a hash table (uthash) to provide O(1) access
 * to process statistics based on PID.
 */
struct process_stats {
    int pid;                    /**< Key: Process ID */
    char comm[16];              /**< Process command name */

    unsigned long total_write_count; /**< Total write operations observed */
    unsigned long write_burst;       /**< Write operations in the current window */
    unsigned long rename_burst;      /**< Rename operations in the current window */

    time_t window_start_time;   /**< Timestamp when the current observation window started */
    time_t last_decay_time;     /**< Timestamp of the last score decay operation */

    int current_score;          /**< Current cumulative risk score */

    UT_hash_handle hh;          /**< Uthash handle for hash table management */
};

/**
 * @brief Retrieves or creates the statistics structure for a given process.
 * * Checks if the PID exists in the hash table. If not, allocates and
 * initializes a new structure.
 * * @param pid Process ID.
 * @param comm Process command name (for initialization).
 * @return Pointer to the process_stats structure, or NULL on failure.
 */
struct process_stats *get_process_stats(int pid, const char *comm);

/**
 * @brief Removes a process from the tracking table and frees memory.
 * * @param pid Process ID to remove.
 */
void remove_process(int pid);

/**
 * @brief Cleans up all tracked processes and frees all allocated memory.
 * * This function should be called during the graceful shutdown sequence.
 */
void cleanup_all_processes();

#endif // STATE_MANAGER_H