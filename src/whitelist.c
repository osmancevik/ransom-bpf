/**
 * @file whitelist.c
 * @brief O(1) Performance Optimized Process Whitelisting Implementation.
 * @version 0.9.0
 *
 * This module implements the logic for parsing, storing, and querying the
 * process whitelist. It relies on the 'uthash' macro library to provide
 * constant-time lookups, ensuring that the filtering mechanism does not
 * introduce latency into the event processing pipeline.
 */

#include "whitelist.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "logger.h"

/**
 * @brief Head of the global whitelist hash table.
 *
 * This pointer serves as the anchor for the uthash structure.
 * Initialized to NULL as required by the library.
 */
static struct whitelist_entry *whitelist_head = NULL;

/**
 * @brief Initializes the whitelist hash table from a CSV string.
 *
 * Tokenizes the input string, allocates memory for each unique process name,
 * and adds it to the hash table. Duplicate entries in the input string
 * are silently ignored to maintain table integrity.
 *
 * @param whitelist_string Comma-separated list of trusted process names.
 */
void init_whitelist(const char *whitelist_string) {
    // Handle empty whitelist case
    if (whitelist_string == NULL || strlen(whitelist_string) == 0) {
        LOG_INFO("Whitelist is empty. Monitoring all processes.");
        return;
    }

    // Duplicate string because strtok_r modifies the input
    char *temp_str = strdup(whitelist_string);
    if (temp_str == NULL) {
        LOG_ERR("Memory allocation failed for whitelist parsing.");
        return;
    }

    char *token;
    char *saveptr;
    int count = 0;

    // Iterate through tokens using reentrant strtok_r
    for (token = strtok_r(temp_str, ",", &saveptr);
         token != NULL;
         token = strtok_r(NULL, ",", &saveptr)) {

        // Check for duplicates in the hash table
        struct whitelist_entry *s;
        HASH_FIND_STR(whitelist_head, token, s);

        if (s == NULL) {
            // Allocate new entry
            s = (struct whitelist_entry*)malloc(sizeof(struct whitelist_entry));
            if (s) {
                // Copy process name (ensure null-termination)
                strncpy(s->comm, token, sizeof(s->comm) - 1);
                s->comm[sizeof(s->comm) - 1] = '\0';

                // Add to hash table (Key: comm field)
                HASH_ADD_STR(whitelist_head, comm, s);
                count++;
            } else {
                LOG_ERR("Memory allocation failed for whitelist entry: %s", token);
            }
        }
    }

    LOG_INFO("Whitelist initialized. Loaded %d trusted processes.", count);
    free(temp_str);
}

/**
 * @brief Checks if a process is trusted.
 *
 * Performs a high-performance hash lookup to determine if the process
 * should be excluded from analysis.
 *
 * @param comm The process command name to check.
 * @return true if whitelisted, false otherwise.
 */
bool is_whitelisted(const char *comm) {
    if (whitelist_head == NULL || comm == NULL) {
        return false;
    }

    struct whitelist_entry *s;

    // O(1) Lookup - String based
    HASH_FIND_STR(whitelist_head, comm, s);

    return (s != NULL);
}

/**
 * @brief Cleans up the whitelist resources.
 *
 * Iterates through the hash table, removing each item and freeing the
 * associated memory. This is essential for a clean shutdown (valgrind-clean).
 */
void cleanup_whitelist() {
    struct whitelist_entry *current_entry, *tmp;

    // Safe iteration allowing deletion
    HASH_ITER(hh, whitelist_head, current_entry, tmp) {
        HASH_DEL(whitelist_head, current_entry);
        free(current_entry);
    }
    whitelist_head = NULL;
}