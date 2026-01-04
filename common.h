/* common.h - v0.9.0 (Standardized) */
#ifndef COMMON_H
#define COMMON_H

/**
 * @file common.h
 * @brief Shared definitions and data structures between Kernel Space (eBPF) and User Space.
 *
 * This header defines the protocol for data exchange via the Ring Buffer.
 * It must be included by both the eBPF program (hello_kern.c) and the user agent.
 */

#define APP_VERSION "0.9.0"

/**
 * @brief Enumeration of supported system event types.
 */
enum event_type {
    EVENT_EXEC = 1,     /**< Process execution (execve) */
    EVENT_WRITE = 2,    /**< File write operation (write, pwrite64, writev) */
    EVENT_OPEN = 3,     /**< File open operation (openat) */
    EVENT_RENAME = 4,   /**< File rename operation (rename, renameat, renameat2) */
    EVENT_EXIT = 5,     /**< Process termination */
    EVENT_UNLINK = 6    /**< File deletion (unlinkat) */
};

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

/**
 * @struct event
 * @brief Represents a single system event captured by the eBPF program.
 *
 * This structure is populated in kernel space and submitted to the
 * Ring Buffer for consumption by the user space agent.
 */
struct event {
    int type;                           /**< Event type (see enum event_type) */
    unsigned int pid;                   /**< Process ID */
    unsigned int ppid;                  /**< Parent Process ID */
    unsigned int uid;                   /**< User ID (Real UID) */
    char comm[TASK_COMM_LEN];           /**< Command name (e.g., "bash", "python") */
    char filename[MAX_FILENAME_LEN];    /**< Associated filename or path */
};

#endif // COMMON_H