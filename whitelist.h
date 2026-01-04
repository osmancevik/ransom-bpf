/* whitelist.h - v0.9.0 (Standardized) */
#ifndef WHITELIST_H
#define WHITELIST_H

#include <stdbool.h>
#include "uthash.h"

/**
 * @file whitelist.h
 * @brief High-performance Process Whitelisting Mechanism.
 *
 * This module manages a list of trusted process names that should be excluded
 * from behavioral analysis to reduce noise and CPU overhead. It utilizes
 * a hash table (uthash) to ensure O(1) lookup complexity.
 */

/**
 * @struct whitelist_entry
 * @brief Represents a single trusted process in the hash table.
 */
struct whitelist_entry {
    char comm[16];      /**< Key: Process command name (e.g., "systemd") */
    UT_hash_handle hh;  /**< Uthash handle for hash table management */
};

/**
 * @brief Initializes the whitelist hash table from a comma-separated string.
 *
 * Parses the input string (loaded from config) and populates the hash table.
 * Duplicate entries are automatically handled.
 *
 * @param whitelist_string A CSV string containing trusted process names
 * (e.g., "systemd,sshd,git").
 */
void init_whitelist(const char *whitelist_string);

/**
 * @brief Checks if a given process name is in the whitelist.
 *
 * Performs a constant-time O(1) lookup in the hash table.
 *
 * @param comm The process command name to check.
 * @return true if the process is whitelisted (trusted), false otherwise.
 */
bool is_whitelisted(const char *comm);

/**
 * @brief Frees all memory allocated for the whitelist hash table.
 *
 * Should be called during the graceful shutdown sequence to prevent memory leaks.
 */
void cleanup_whitelist();

#endif // WHITELIST_H